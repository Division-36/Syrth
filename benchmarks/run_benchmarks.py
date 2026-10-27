"""
SYRTH Benchmark Harness
=======================
Measures the analyser's behaviour on a labelled corpus, and refuses to report a
number it cannot justify.

What this harness reports, and why each number matters
------------------------------------------------------
**Precision and recall, not accuracy.** The corpus is dominated by safe code, so
accuracy is close to uninformative. Precision answers "when SYRTH speaks, how
often is it right", which is the only question a reviewer has.

**Abstention is a first-class outcome.** A finding set is only useful if the
tool can decline. ``selective_precision`` and ``risk_coverage`` measure what
happens as the threshold rises, and ``abstention_rate`` is reported alongside so
a silent tool cannot look good by never speaking.

**Rename invariance is measured, not asserted.** Every record is analysed twice,
once under a consistent alpha-renaming of its identifiers. ``rename_invariance``
is the fraction of records whose verdict is unchanged. This is a number a
competitor cannot match by construction, and it is the axis this project claims.

**Patch verification is measured.** Each held-out record that carries a confirmed
flow is re-analysed with a categorically correct sanitiser inserted. ``kill_rate``
is the fraction of flows that disappear. A detector that cannot demonstrate that
its own fixes work has not closed the loop.

**Leakage is checked, not assumed.** Records are grouped by a stable identity and
the split is asserted group-disjoint. Identical feature vectors carrying different
labels are counted and reported, because they cap achievable accuracy and a
reviewer deserves to know.

What this harness deliberately does not do
------------------------------------------
It does not report a single headline accuracy figure, and it does not compare
against other tools without running them. Quoted baselines are worthless; run
them with :mod:`benchmarks.baselines`.

Usage::

    python -m benchmarks.run_benchmarks --dataset data/records.jsonl
    python -m benchmarks.run_benchmarks --dataset data/records.jsonl --json out.json
"""

from __future__ import annotations

import argparse
import builtins
import json
import random
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from syrth.features import FeatureExtractor
from syrth.parser import PythonParser
from syrth.scan import Finding, SyrthScanner

#: A categorically correct patch per sink category, used to measure kill rate.
#: Each is a sanitiser that the kill model recognises for exactly that category,
#: so a killed flow means the model genuinely understood the mitigation.
CATEGORY_PATCH: dict[str, str] = {
    "SQL": "sqlalchemy.sql.text",
    "XSS": "html.escape",
    "FILE": "os.path.basename",
    "EXEC": "shlex.quote",
    "NET": "urllib.parse.urlparse",
    "REDIRECT": "urllib.parse.urlparse",
    "DESER": "json.loads",
    "CRYPTO": "hashlib.sha256",
    "CRED": "os.getenv",
    "UPLOAD": "os.path.basename",
    "XXE": "defusedxml.fromstring",
}

#: Bootstrap resamples used for confidence intervals.
BOOTSTRAP_SAMPLES = 2000
CONFIDENCE = 0.95


@dataclass
class Record:
    """One labelled example.

    Attributes:
        source: Python source.
        label: CWE identifier, or ``""`` for a record known to be safe.
        group: Stable identity used to keep the split group-disjoint.
        tier: Corpus evidence tier (``direct-sink`` / ``module-proximity``).
            Empty for datasets that predate tiers. It never affects a verdict
            here; it only lets a report split its figures by evidence strength.
        pair_id: Identifies the vulnerable/patched pair a record belongs to.
            Needed whenever records are matched up: one advisory can fix several
            functions, so grouping by ``group`` and zipping positionally pairs
            unrelated functions together.
    """

    source: str
    label: str
    group: str
    tier: str = ""
    pair_id: str = ""


@dataclass
class Outcome:
    """What the analyser decided about one record.

    Attributes:
        record: The originating record.
        predicted: CWEs the analyser reported.
        taint_confirmed: Whether a source-to-sink flow was confirmed.
        category: Category of the highest-severity confirmed flow.
        confidence: Confidence of that finding.
        rename_stable: Whether the verdict survived alpha-renaming.
        killed_by_patch: Whether a categorically correct patch removed the flow.
    """

    record: Record
    predicted: tuple[str, ...]
    taint_confirmed: bool
    category: str
    confidence: float
    rename_stable: bool = True
    killed_by_patch: bool | None = None


@dataclass
class Metrics:
    """Metrics with bootstrap confidence intervals.

    Attributes:
        precision: True positives over everything reported.
        recall: True positives over everything present.
        f1: Harmonic mean.
        selective_precision: Precision at a 0.9 confidence floor.
        coverage: Fraction of unsafe records on which the tool spoke.
        abstention_rate: Fraction of safe records on which it stayed silent.
        false_positive_rate: Reported findings among safe records.
        rename_invariance: Fraction of verdicts unchanged by renaming.
        kill_rate: Fraction of confirmed flows removed by a correct patch.
        support: Raw counts, so every rate can be checked by hand.
        confidence_intervals: Bootstrap 95% intervals for the headline rates.
        label_ties: Records whose feature vector is shared across differing labels.
        warnings: Anything a reader must know before quoting a number.
    """

    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    selective_precision: float = 0.0
    coverage: float = 0.0
    abstention_rate: float = 0.0
    false_positive_rate: float = 0.0
    rename_invariance: float = 0.0
    kill_rate: float = 0.0
    support: dict[str, int] = field(default_factory=dict)
    confidence_intervals: dict[str, dict[str, float]] = field(default_factory=dict)
    label_ties: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable view."""
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "selective_precision_at_0.9": round(self.selective_precision, 4),
            "coverage": round(self.coverage, 4),
            "abstention_rate": round(self.abstention_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "rename_invariance": round(self.rename_invariance, 4),
            "patch_kill_rate": round(self.kill_rate, 4),
            "support": dict(sorted(self.support.items())),
            "confidence_intervals_95": self.confidence_intervals,
            "label_ties": self.label_ties,
            "warnings": list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Alpha renaming
# ---------------------------------------------------------------------------

#: Reserved words and builtins that must keep their spelling for the program to
#: remain valid Python. Renaming ``open`` or ``len`` is not an alpha-renaming: it
#: changes what the program does, so the invariance measurement would be
#: measuring the renamer rather than the analyser.
RESERVED = frozenset(
    """
    False None True and as assert async await break class continue def del elif
    else except finally for from global if import in is lambda nonlocal not or
    pass raise return try while with yield
    """.split()
) | frozenset(dir(builtins))


def _significant_tokens(source: str) -> list[tuple]:
    """Tokenise and classify every token for renameability.

    Returns:
        A list of ``(token, in_import, after_as, after_dot, kwarg)`` tuples in
        source order. An empty list when the source cannot be tokenised.

    The classification is computed once and consumed by both name collection and
    rewriting, so the two cannot disagree about what is renameable. A
    disagreement would silently produce an unsound invariance measurement -- the
    one number this project is willing to make a strong claim about.
    """
    import io
    import tokenize

    try:
        raw = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []

    layout = (
        tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT, tokenize.ENCODING,
        tokenize.NEWLINE, tokenize.NL,
    )

    # Reduce to the tokens that matter, keeping their original positions.
    significant: list[tuple] = [
        (position, token) for position, token in enumerate(raw) if token.type not in layout
    ]

    result: list[tuple] = []
    in_import = False
    import_line = -1
    bracket_depth = 0

    for index, (_stored, token) in enumerate(significant):
        previous = significant[index - 1][1] if index > 0 else None
        previous_string = previous.string if previous is not None else ""
        line = token.start[0]

        after_dot = previous is not None and previous.type == tokenize.OP \
            and previous.string == "."
        after_as = previous_string == "as"

        # An import statement spans one logical line, unless it is parenthesised.
        if in_import and bracket_depth == 0 and line != import_line:
            in_import = False

        if token.type == tokenize.NAME and token.string in ("import", "from"):
            in_import = True
            import_line = line
            bracket_depth = 0

        is_kwarg = False
        if token.type == tokenize.NAME and not in_import and not after_dot:
            following = (
                significant[index + 1][1]
                if index + 1 < len(significant) else None
            )
            # ``name=`` is a keyword argument only inside a call. A statement
            # level ``name = ...`` must not match: treating the assignment target
            # as a kwarg excluded it from renaming while its uses were still
            # renamed, which rewrote the program and silently deleted a real
            # finding. The preceding token therefore has to be ``,`` or ``(``.
            opens_call = previous is not None and previous.type == tokenize.OP \
                and previous.string in ("(", ",")
            is_kwarg = (
                opens_call
                and following is not None
                and following.type == tokenize.OP
                and following.string == "="
            )

        result.append((token, in_import, after_as, after_dot, is_kwarg))

        if token.type == tokenize.OP:
            if token.string in ("(", "[", "{"):
                bracket_depth += 1
            elif token.string in (")", "]", "}"):
                bracket_depth = max(0, bracket_depth - 1)
            elif token.string == ":" and bracket_depth == 0:
                in_import = False

    return result


def import_bound_names(source: str) -> set:
    """Names an ``import`` statement binds at module scope.

    These are excluded from renaming everywhere in the file, not just inside the
    import statement itself. Renaming ``os`` in ``import os`` is obvious; renaming
    the *use* of ``os`` three functions later is the subtle half, and without
    this the renamer would produce a program that raises
    :class:`ModuleNotFoundError` at runtime -- making the invariance measurement
    meaningless.

    Returns:
        The bound names. Empty when the source cannot be tokenised.
    """
    import io
    import tokenize

    try:
        raw = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return set()

    layout = (
        tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT, tokenize.ENCODING,
        tokenize.NEWLINE, tokenize.NL,
    )
    significant = [
        (index, token) for index, token in enumerate(raw) if token.type not in layout
    ]

    bound: set = set()
    in_import = False
    import_line = -1
    bracket_depth = 0
    after_as = False
    module_part = True

    for index, (_stored, token) in enumerate(significant):
        previous = significant[index - 1][1] if index > 0 else None
        previous_string = previous.string if previous is not None else ""
        line = token.start[0]
        after_dot = previous is not None and previous.type == tokenize.OP \
            and previous.string == "."

        if in_import and bracket_depth == 0 and line != import_line:
            in_import = False
            after_as = False
            module_part = True

        if token.type == tokenize.NAME and token.string in ("import", "from"):
            in_import = True
            import_line = line
            bracket_depth = 0
            after_as = False
            module_part = True
            continue

        if in_import and token.type == tokenize.NAME and not after_dot:
            if token.string == "as":
                # ''as'' is a keyword, never an identifier to freeze or rename.
                continue
            if previous_string == "as":
                after_as = True
                module_part = False
                # Deliberately NOT added to the frozen set. An alias is a local
                # binding, so renaming ``import subprocess as sp`` together with
                # every use of ``sp`` is sound; freezing it would leave the
                # renamer unable to exercise aliased calls at all.
            elif after_as:
                pass
            elif module_part:
                if previous_string == "import" or after_dot:
                    # ``import a.b`` binds the top-level package name ``a``.
                    bound.add(token.string)
                elif "," in previous_string or line == import_line:
                    bound.add(token.string)
            else:
                bound.add(token.string)

        if token.type == tokenize.OP:
            if token.string in ("(", "[", "{"):
                bracket_depth += 1
            elif token.string in (")", "]", "}"):
                bracket_depth = max(0, bracket_depth - 1)
            elif token.string in (",", ":") and bracket_depth == 0:
                if token.string == ",":
                    module_part = False
            elif token.string == ".":
                continue
        if token.type == tokenize.NAME and token.string != "as":
            after_as = previous_string == "as"
    return bound


def locally_bound_names(source: str) -> set[str]:
    """Names this fragment itself binds.

    A renamer that touches a *free* name is not renaming, it is rewriting the
    program: in a fragment whose imports are not visible, ``render_to_response``
    looks free, so renaming it removed the very sink under test and the
    invariance metric reported engine instability that was the harness's own
    doing. Only names bound here -- parameters, assignments, ``def``/``class``
    names, loop and ``with`` targets, comprehension targets, ``except ... as``,
    walrus targets and ``global``/``nonlocal`` declarations -- can be renamed
    without needing to know the surrounding module.
    """
    import ast

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()

    bound: set[str] = set()

    def bind_target(node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            bound.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                bind_target(element)
        elif isinstance(node, ast.Starred):
            bind_target(node.value)

    def bind_arguments(args: ast.arguments) -> None:
        for arg in (
            list(args.posonlyargs)
            + list(args.args)
            + list(args.kwonlyargs)
            + ([args.vararg] if args.vararg else [])
            + ([args.kwarg] if args.kwarg else [])
        ):
            bound.add(arg.arg)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bind_arguments(node.args)
        elif isinstance(node, ast.Lambda):
            bind_arguments(node.args)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                bind_target(target)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            bind_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind_target(node.target)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                bind_target(node.optional_vars)
        elif isinstance(node, ast.comprehension):
            bind_target(node.target)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bound.add(node.name)
        elif isinstance(node, ast.NamedExpr):
            bind_target(node.target)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # An ``as`` alias is a local binding and is renameable; the module
            # path is not, which ``import_bound_names`` handles separately.
            for alias in node.names:
                if alias.asname:
                    bound.add(alias.asname)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
    return bound


def renameable_names(source: str) -> list[str]:
    """Identifiers that may be renamed without changing program behaviour.

    Soundness matters here: the rename-invariance metric is a headline claim, so
    the renamer must produce a program that is *semantically identical*. Five
    categories are therefore excluded:

    *   **Free names.** Anything not bound inside the fragment may be a global or
        an import this module does not show. Renaming it rewrites the program.
    *   **Module paths.** Renaming ``import os`` to ``import zz1_ab12`` produces
        a different program that raises :class:`ModuleNotFoundError`. Only an
        explicit ``as`` alias is renameable, and an imported name is excluded
        everywhere it appears, not just inside the import.
    *   **Attribute names.** Renaming ``os.system`` to ``os.zz2_cd34`` is not a
        rename; it is a bug.
    *   **Keyword-argument names.** Renaming ``requests.get(url=x)`` changes which
        parameter is passed.
    *   **Python keywords and builtins**, which would stop the program parsing.

    Returns:
        The renameable identifiers, in first-appearance order. Empty when the
        source cannot be tokenised.
    """
    import tokenize

    import_bound = import_bound_names(source)
    local = locally_bound_names(source)
    names: list[str] = []
    for token, in_import, after_as, after_dot, kwarg in _significant_tokens(source):
        if token.type != tokenize.NAME:
            continue
        if token.string in RESERVED or token.string in import_bound:
            continue
        if token.string not in local:
            continue
        if after_dot or kwarg:
            continue
        if in_import and not after_as:
            continue
        names.append(token.string)
    return names


def alpha_rename(source: str, seed: int = 0) -> str:
    """Apply a consistent renaming to every renameable identifier.

    The result is the same program with different spelling for its locals and
    locally-defined names. Module paths, attribute names and keyword arguments
    are preserved, so the program remains semantically identical -- which is what
    makes the analyser's verdict the thing under test.

    Args:
        source: Python source.
        seed: Seed for the rename table, so the renaming is reproducible.

    Returns:
        Renamed source, or the original unchanged when no sound rename exists.
    """
    import io
    import tokenize

    unique = sorted(set(renameable_names(source)))
    if not unique:
        return source
    rng = random.Random(seed)
    # A bijection onto fresh names, so two identifiers never collide and the
    # mapping stays injective.
    table = {
        name: f"zz{index}_{rng.randrange(16 ** 6):06x}"
        for index, name in enumerate(unique)
    }

    import_bound = import_bound_names(source)
    classified = _significant_tokens(source)
    renamed_by_offset = {
        token.start: table[token.string]
        for token, in_import, after_as, after_dot, kwarg in classified
        if token.type == tokenize.NAME
        and token.string in table
        and token.string not in import_bound
        and not after_dot
        and not kwarg
        and (not in_import or after_as)
    }
    if not renamed_by_offset:
        return source

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return source

    pieces: list[tuple] = []
    for token in tokens:
        replacement = renamed_by_offset.get(token.start)
        text = replacement if replacement else token.string
        # Five-tuples, not two. ``untokenize`` with ``(type, string)`` pairs
        # rebuilds spacing heuristically and destroys exact layout -- it silently
        # truncated a backslash line continuation, which changed the program and
        # made the invariance metric measure the renamer's corruption instead of
        # the analyser's stability.
        pieces.append((token.type, text, token.start, token.end, token.line))
    try:
        return tokenize.untokenize(pieces)
    except (ValueError, TypeError):
        return source


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    records: Sequence[Record], threshold: float = 0.5, seed: int = 42
) -> tuple[Metrics, list[Outcome]]:
    """Run the analyser over ``records`` and compute the metrics.

    Args:
        records: Labelled examples.
        threshold: Confidence floor for a finding to count as reported.
        seed: Seed for the renaming used in the invariance check.

    Returns:
        ``(metrics, outcomes)``. Outcomes are returned so a caller can inspect
        individual decisions rather than only the aggregate.
    """
    scanner = SyrthScanner(threshold=threshold)
    outcomes: list[Outcome] = []

    for record in records:
        report = scanner.scan_source(record.source, record.group)
        predicted = tuple(sorted({f.cwe for f in report.findings}))
        primary = report.findings[0] if report.findings else None

        renamed = alpha_rename(record.source, seed)
        renamed_report = (
            scanner.scan_source(renamed, record.group) if renamed != record.source else None
        )
        stable = (
            renamed_report is None
            or tuple(sorted({f.cwe for f in renamed_report.findings})) == predicted
        )

        killed: bool | None = None
        if primary is not None and primary.category:
            killed = _kills_flow(record.source, primary, scanner)

        outcomes.append(
            Outcome(
                record=record,
                predicted=predicted,
                taint_confirmed=bool(primary is not None and primary.origins),
                category=primary.category if primary else "",
                confidence=primary.confidence if primary else 0.0,
                rename_stable=stable,
                killed_by_patch=killed,
            )
        )

    return _metrics(outcomes), outcomes


def _kills_flow(source: str, finding: Finding, scanner: SyrthScanner) -> bool:
    """True when a categorically correct sanitiser removes the reported flow.

    The patch is applied textually to the sink argument. This is a *lower bound*
    on what the kill model understands: it measures whether the model recognises
    the mitigation the category calls for, which is the claim being tested.
    """
    patch = CATEGORY_PATCH.get(finding.category)
    if patch is None:
        return None
    lines = source.splitlines()
    index = finding.lineno - 1
    if not 0 <= index < len(lines):
        return None
    line = lines[index]
    for token in (f"{finding.sink_call}(", finding.sink.split("_")[0].lower() + "("):
        position = line.find(token)
        if position >= 0:
            start = position + len(token)
            end = line.find(")", start)
            if start < end:
                lines[index] = (
                    line[:start] + f"{patch}({line[start:end]})" + line[end:]
                )
                break
    else:
        return None
    patched = "\n".join(lines) + ("\n" if source.endswith("\n") else "")
    after = scanner.scan_source(patched, finding.file)
    return not after.findings


def _metrics(outcomes: Sequence[Outcome]) -> Metrics:
    """Compute metrics and bootstrap intervals from a list of outcomes."""
    metrics = Metrics()

    unsafe = [o for o in outcomes if o.record.label]
    safe = [o for o in outcomes if not o.record.label]

    true_positive = sum(1 for o in unsafe if o.record.label in o.predicted)
    reported = sum(1 for o in outcomes if o.predicted)
    false_positive = sum(1 for o in safe if o.predicted)

    metrics.support = {
        "records": len(outcomes),
        "unsafe": len(unsafe),
        "safe": len(safe),
        "reported": reported,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "confirmed_flows": sum(1 for o in outcomes if o.taint_confirmed),
    }

    metrics.precision = true_positive / reported if reported else 0.0
    metrics.recall = true_positive / len(unsafe) if unsafe else 0.0
    if metrics.precision + metrics.recall > 0:
        metrics.f1 = 2 * metrics.precision * metrics.recall / (
            metrics.precision + metrics.recall
        )

    confident = [o for o in outcomes if o.confidence >= 0.9]
    metrics.selective_precision = (
        sum(1 for o in confident if o.record.label in o.predicted) / len(confident)
        if confident else 0.0
    )
    metrics.coverage = (
        sum(1 for o in unsafe if o.predicted) / len(unsafe) if unsafe else 0.0
    )
    metrics.abstention_rate = (
        sum(1 for o in safe if not o.predicted) / len(safe) if safe else 0.0
    )
    metrics.false_positive_rate = (
        false_positive / len(safe) if safe else 0.0
    )
    metrics.rename_invariance = (
        sum(1 for o in outcomes if o.rename_stable) / len(outcomes) if outcomes else 0.0
    )

    kills = [o.killed_by_patch for o in outcomes if o.killed_by_patch is not None]
    metrics.kill_rate = sum(1 for k in kills if k) / len(kills) if kills else 0.0
    metrics.support["patch_attempts"] = len(kills)

    metrics.confidence_intervals = _bootstrap(outcomes)

    if false_positive:
        metrics.warnings.append(
            f"{false_positive} finding(s) on safe code; precision is the headline "
            "number to quote, not accuracy"
        )
    if metrics.rename_invariance < 1.0:
        unstable = [o for o in outcomes if not o.rename_stable][:5]
        metrics.warnings.append(
            f"{1 - metrics.rename_invariance:.1%} of verdicts changed under "
            "consistent renaming, which breaks the invariance guarantee; first "
            f"cases: {[o.record.group for o in unstable]}"
        )
    if kills and metrics.kill_rate < 1.0:
        metrics.warnings.append(
            f"{1 - metrics.kill_rate:.1%} of confirmed flows survived a correct "
            "sanitiser; the kill model does not yet understand those categories"
        )
    if not unsafe or not safe:
        metrics.warnings.append(
            "the corpus needs both unsafe and safe records for precision and "
            "abstention to be meaningful"
        )
    return metrics


def _bootstrap(
    outcomes: Sequence[Outcome], samples: int = BOOTSTRAP_SAMPLES, seed: int = 7
) -> dict[str, dict[str, float]]:
    """Bootstrap 95% intervals for precision, recall and rename invariance.

    Resampling is over records, which is the unit of independence. Confidence
    intervals are reported because a point estimate on a few hundred records is
    not a result; the previous harness printed point estimates and called the
    difference from a baseline "statistically significant" without a single test.
    """
    if not outcomes:
        return {}
    rng = random.Random(seed)
    n = len(outcomes)

    def statistic(sample: Sequence[Outcome]) -> float:
        reported = [o for o in sample if o.predicted]
        correct = sum(1 for o in reported if o.record.label in o.predicted)
        return correct / len(reported) if reported else 0.0

    def recall_statistic(sample: Sequence[Outcome]) -> float:
        unsafe = [o for o in sample if o.record.label]
        if not unsafe:
            return 0.0
        return sum(1 for o in unsafe if o.record.label in o.predicted) / len(unsafe)

    def invariance_statistic(sample: Sequence[Outcome]) -> float:
        return sum(1 for o in sample if o.rename_stable) / len(sample)

    observed = {
        "precision": statistic(outcomes),
        "recall": recall_statistic(outcomes),
        "rename_invariance": invariance_statistic(outcomes),
    }
    draws: dict[str, list[float]] = {k: [] for k in observed}
    for _ in range(samples):
        sample = [outcomes[rng.randrange(n)] for _ in range(n)]
        draws["precision"].append(statistic(sample))
        draws["recall"].append(recall_statistic(sample))
        draws["rename_invariance"].append(invariance_statistic(sample))

    intervals: dict[str, dict[str, float]] = {}
    alpha = (1 - CONFIDENCE) / 2
    for key, observed_value in observed.items():
        ordered = sorted(draws[key])
        low = ordered[max(0, int(alpha * samples))]
        high = ordered[min(samples - 1, int((1 - alpha) * samples))]
        intervals[key] = {
            "point": round(observed_value, 4),
            "low": round(low, 4),
            "high": round(high, 4),
        }
    return intervals


def label_ties(records: Sequence[Record]) -> int:
    """Count feature vectors shared by records with different labels.

    A nonzero count caps achievable accuracy: no classifier can separate two
    identical inputs with opposite labels. It is reported rather than hidden.
    """
    extractor = FeatureExtractor()
    parser = PythonParser()
    by_vector: dict[tuple[float, ...], set] = {}
    for record in records:
        trace = parser.parse(record.source, record.group)
        if not trace.functions:
            continue
        vector = tuple(
            extractor.extract_function(trace.functions[0], trace)
        )
        by_vector.setdefault(vector, set()).add(record.label)
    return sum(1 for labels in by_vector.values() if len({x for x in labels if x}) > 1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_records(path: str) -> list[Record]:
    """Load records from JSON Lines or a JSON array.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a record is missing a required field.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"dataset not found: {path}")
    text = target.read_text(encoding="utf-8")
    objects: list[Mapping[str, Any]]
    if text.lstrip().startswith("["):
        loaded = json.loads(text)
        if not isinstance(loaded, list):
            raise ValueError(f"{path}: expected a JSON array")
        objects = loaded
    else:
        objects = [json.loads(line) for line in text.splitlines() if line.strip()]

    records: list[Record] = []
    for index, obj in enumerate(objects, start=1):
        source = obj.get("source") or obj.get("code")
        if source is None:
            raise ValueError(f"{path} record {index}: missing 'source'")
        records.append(
            Record(
                source=str(source),
                label=str(obj.get("label") or obj.get("cwe") or ""),
                group=str(obj.get("group") or obj.get("advisory") or f"record-{index}"),
                tier=str(obj.get("evidence") or obj.get("tier") or ""),
                pair_id=str(obj.get("pair_id") or ""),
            )
        )
    return records


def split(
    records: Sequence[Record], test_fraction: float = 0.25, seed: int = 42
) -> tuple[list[Record], list[Record], int]:
    """Group-disjoint split.

    Returns:
        ``(train, test, leaked_group_count)``. The leak count must be zero; it is
        returned so the caller can assert rather than trust.
    """
    rng = random.Random(seed)
    groups: dict[str, list[Record]] = {}
    for record in records:
        groups.setdefault(record.group, []).append(record)
    ordered = sorted(groups)
    rng.shuffle(ordered)
    target = int(round(len(records) * test_fraction))
    test: list[Record] = []
    running = 0
    for group in ordered:
        if running >= target:
            break
        test.extend(groups[group])
        running += len(groups[group])
    chosen = {r.group for r in test}
    train = [r for r in records if r.group not in chosen]
    leaked = len({r.group for r in train} & chosen)
    return train, test, leaked


def render(metrics: Metrics) -> str:
    """Human-readable report."""
    lines = ["=" * 72, "SYRTH benchmark", "=" * 72]
    support = metrics.support
    lines.append(
        "records {records} (unsafe {unsafe}, safe {safe}) -> reported {reported}".format(
            **support
        )
    )
    lines.append("")
    rows = [
        ("precision", metrics.precision),
        ("recall", metrics.recall),
        ("f1", metrics.f1),
        ("selective precision @0.9", metrics.selective_precision),
        ("coverage on unsafe records", metrics.coverage),
        ("abstention rate on safe records", metrics.abstention_rate),
        ("false positive rate on safe records", metrics.false_positive_rate),
        ("rename invariance", metrics.rename_invariance),
        ("patch kill rate", metrics.kill_rate),
    ]
    for name, value in rows:
        interval = metrics.confidence_intervals.get(name.split(" @")[0].split(" on ")[0])
        suffix = ""
        if interval:
            suffix = f"   95% CI [{interval['low']:.3f}, {interval['high']:.3f}]"
        lines.append(f"  {name:<38} {value:6.2%}{suffix}")
    if metrics.label_ties:
        lines.append("")
        lines.append(
            f"  {metrics.label_ties} feature vector(s) shared across differing "
            "labels; achievable accuracy is capped accordingly"
        )
    if metrics.warnings:
        lines.append("")
        lines.append("WARNINGS")
        for warning in metrics.warnings:
            lines.append(f"  - {warning}")
    lines.append("")
    lines.append(
        "Quote precision, selectivity and the invariance and kill-rate figures. "
        "Do not quote accuracy on a corpus that is mostly safe code."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="benchmarks.run_benchmarks",
        description="Evaluate SYRTH on a labelled corpus",
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--test-fraction", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", default=None, help="Write metrics JSON here")
    args = parser.parse_args(argv)

    try:
        records = load_records(args.dataset)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    if not records:
        print("[error] dataset is empty", file=sys.stderr)
        return 2

    train, test, leaked = split(records, args.test_fraction, args.seed)
    if leaked:
        print(f"[error] {leaked} group(s) straddle the split", file=sys.stderr)
        return 2

    metrics, _outcomes = evaluate(test, threshold=args.threshold, seed=args.seed)
    metrics.label_ties = label_ties(test)

    print(render(metrics))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(
            json.dumps(metrics.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "CATEGORY_PATCH",
    "Metrics",
    "Outcome",
    "Record",
    "alpha_rename",
    "evaluate",
    "label_ties",
    "load_records",
    "render",
    "split",
]
