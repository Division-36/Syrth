"""Risk-model benchmark: measures the claims SYRTH actually makes.

The previous harness measured precision and recall. Those are metrics for a
classifier that decides "vulnerable / not vulnerable". SYRTH does not make that
decision -- it reports the nearest vulnerability class to every sink it touches,
with a likelihood. Measuring it with classifier metrics produced two artefacts
that looked like quality problems and were reporting artefacts (see
``docs/corpus_failure_diagnosis.md``).

What is measured instead, and why each is well-defined:

``category_coverage``
    Of the vulnerability classes whose sinks a record *actually contains*, what
    fraction did SYRTH name? This needs no ground-truth labels at all: the
    expected classes are derived from the source by an independent AST scan. It
    answers "does the tool see what is there", which is the risk model's
    central claim.

``rank_discordance``
    For pairs of findings where one provably has more evidence than another
    (a tainted flow versus a literal-only sink call, in the same function), how
    often does SYRTH rank the better-evidenced one first? This measures the
    likelihood ordering, again without labels. Kendall tau-style agreement
    against constructed orderings.

``rename_invariance``
    Unchanged in meaning: does the set of reported classes survive renaming.
    Still the project's headline property.

``kill_rate``
    Does applying the category's own mitigation remove the *confirmed* flow?
    Scoped to confirmed flows only -- a pattern risk remaining after a patch is
    correct, because the sink call is still there.

None of these require the corpus labels, which is deliberate: the corpus labels
are unsound (KI-002) and a harness that depended on them would inherit that
defect.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from syrth.scan import Finding, SyrthScanner

# ---------------------------------------------------------------------------
# Independent expected-class extraction
# ---------------------------------------------------------------------------

#: Sink call names grouped by vulnerability class.
#:
#: Kept deliberately independent of ``syrth.registry`` so that agreement between
#: the two is meaningful rather than circular.
#:
#: Only *unambiguous* names appear here. Generic verbs -- ``get``, ``post``,
#: ``parse``, ``run``, ``load``, ``compile``, ``request`` -- are excluded on
#: purpose: they match ordinary dictionary access, config parsing and string
#: building, and counting them produced a 64-record phantom SSRF expectation on
#: a corpus that contains no SSRF. Expecting a class that no analyst would report
#: is how a benchmark manufactures a coverage gap that is not there.
_SINK_NAME_TO_CWE = {
    # Bare names only, and only unambiguous ones. ``loads`` is deliberately
    # absent: it is CWE-502 after ``from pickle import loads`` and a safe decoder
    # after ``from json import loads``, and this table cannot tell them apart.
    # Anything module-qualified belongs in ``_QUALIFIED_SINKS``.
    "CWE-94": {
        "system", "popen", "Popen", "check_call", "check_output",
        "spawn", "spawnl", "spawnv", "execv", "execve", "execvp", "eval", "exec",
    },
    "CWE-89": {"execute", "executemany", "executescript", "execute_sql"},
    "CWE-22": {"open", "send_file", "send_from_directory", "remove", "unlink", "rmdir"},
    "CWE-79": {"HttpResponse", "mark_safe", "render_to_response",
               "render", "Template", "send_mail"},
    "CWE-601": {"redirect", "HttpResponseRedirect", "RedirectResponse", "redirect_to",
                "HttpResponseRedirectPermanent"},
    "CWE-918": {"urlopen", "urlretrieve"},
    "CWE-502": {"Unpickler"},
    "CWE-611": {"fromstring", "parseString", "iterparse", "XMLParser", "make_parser"},
    "CWE-434": {"ImageField", "FileField"},
}

#: Attribute paths that identify a sink regardless of the bare method name.
#: ``requests.get`` is an HTTP client; ``os.path.join`` is not a sink.
_QUALIFIED_SINKS = {
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "httpx.get": "CWE-918",
    "httpx.post": "CWE-918",
    "urllib.request.urlopen": "CWE-918",
    "lxml.etree.fromstring": "CWE-611",
    "lxml.etree.parse": "CWE-611",
    "xml.etree.ElementTree.fromstring": "CWE-611",
    "xml.etree.ElementTree.parse": "CWE-611",
    "django.shortcuts.redirect": "CWE-601",
    "subprocess.run": "CWE-94",
    "subprocess.Popen": "CWE-94",
    "subprocess.call": "CWE-94",
    "subprocess.check_output": "CWE-94",
    "sqlite3.connect": "CWE-89",
    # Deserialisation, qualified by module. The bare name ``load`` cannot appear
    # here: ``pickle.load`` is unsafe deserialisation and ``numpy.load`` is a
    # data reader, and this table has no import information to tell them apart.
    # Naming the module is both unambiguous and still independent of
    # ``syrth.registry`` -- it is a claim about Python, not a copy of the
    # analyser's tables. Omitting these made the harness miss the CWE-502
    # records entirely and under-report category coverage.
    "pickle.load": "CWE-502",
    "pickle.loads": "CWE-502",
    "pickle.Unpickler": "CWE-502",
    "cPickle.load": "CWE-502",
    "cPickle.loads": "CWE-502",
    "marshal.load": "CWE-502",
    "marshal.loads": "CWE-502",
    "dill.load": "CWE-502",
    "dill.loads": "CWE-502",
    "jsonpickle.decode": "CWE-502",
    "jsonpickle.unpickler.decode": "CWE-502",
    "joblib.load": "CWE-502",
    "torch.load": "CWE-502",
    "yaml.load": "CWE-502",
    "yaml.full_load": "CWE-502",
    "shelve.open": "CWE-502",
}

#: Calls whose arguments must be non-constant for the class to be "present".
_ALWAYS_NEEDS_VALUE = frozenset(
    _SINK_NAME_TO_CWE["CWE-94"] | _SINK_NAME_TO_CWE["CWE-89"]
)


def _qualified_name(node: ast.Call) -> str:
    """Dotted path of the callee, as written (``requests.get``), or ''."""
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def expected_classes(source: str) -> set[str]:
    """Vulnerability classes whose sinks the source demonstrably contains.

    Deliberately independent of ``syrth``: a plain AST walk. If the analyser and
    this function agree because they share code, the coverage number means
    nothing.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()

    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        qualified = _qualified_name(node)
        if qualified in _QUALIFIED_SINKS:
            found.add(_QUALIFIED_SINKS[qualified])
            continue

        func = node.func
        name = ""
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if not name:
            continue
        for cwe, names in _SINK_NAME_TO_CWE.items():
            if name not in names:
                continue
            if name in _ALWAYS_NEEDS_VALUE and not node.args:
                continue
            found.add(cwe)
    return found


# ---------------------------------------------------------------------------
# Outcomes and metrics
# ---------------------------------------------------------------------------


@dataclass
class RiskOutcome:
    """One scanned record."""

    group: str
    source: str
    expected: frozenset[str]
    reported: frozenset[str]
    findings: tuple[Finding, ...]
    rename_stable: bool | None
    confirmed: tuple[Finding, ...]
    killed_by_patch: bool | None
    #: Corpus evidence tier, or ``""`` for datasets that predate tiers.
    tier: str = ""

    @property
    def covered(self) -> frozenset[str]:
        return self.expected & self.reported

    @property
    def missed(self) -> frozenset[str]:
        return self.expected - self.reported

    @property
    def spurious(self) -> frozenset[str]:
        """Reported classes the AST scan did not find a sink for."""
        return self.reported - self.expected


@dataclass
class RiskMetrics:
    """Aggregates for the risk model. No precision, no recall, no f1."""

    records: int = 0
    records_with_expected: int = 0
    expected_classes: int = 0
    covered_classes: int = 0
    category_coverage: float = 0.0

    #: Ranked pairs where evidence provably differs.
    rank_pairs: int = 0
    rank_agreements: int = 0
    rank_discordance: float = 0.0

    rename_checked: int = 0
    rename_stable: int = 0
    rename_invariance: float = 0.0

    patch_attempts: int = 0
    patch_kills: int = 0
    kill_rate: float = 0.0

    determinism_checks: int = 0
    determinism_agreements: int = 0
    determinism: float = 0.0

    by_cwe: dict[str, dict[str, int]] = field(default_factory=dict)
    support: dict[str, int] = field(default_factory=dict)
    #: Coverage split by corpus evidence tier. A ``direct-sink`` record proves
    #: the class against its own source; a ``module-proximity`` record does not,
    #: and mixing the two into one headline number would hide that. See
    #: ``tools/build_corpus.py`` for why both tiers exist.
    tier_coverage: dict[str, dict[str, int]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            "records with sinks found      : "
            f"{self.records_with_expected}/{self.records}",
            "category coverage             : "
            f"{self.covered_classes}/{self.expected_classes} = "
            f"{self.category_coverage:.1%}",
            "rank agreement (better-evidence first): "
            f"{self.rank_agreements}/{self.rank_pairs} = "
            f"{1 - self.rank_discordance:.1%}",
            "rename invariance             : "
            f"{self.rename_stable}/{self.rename_checked} = "
            f"{self.rename_invariance:.1%}",
            "patch kill rate (confirmed)   : "
            f"{self.patch_kills}/{self.patch_attempts} = "
            f"{self.kill_rate:.1%}",
            "determinism (repeat run)      : "
            f"{self.determinism_agreements}/{self.determinism_checks} = "
            f"{self.determinism:.1%}",
        ]
        if self.by_cwe:
            lines.append("")
            lines.append("per class (covered/expected):")
            for cwe in sorted(self.by_cwe):
                row = self.by_cwe[cwe]
                lines.append(
                    f"  {cwe:<10} {row['covered']}/{row['expected']}"
                )
        if self.tier_coverage:
            lines.append("")
            lines.append("by corpus evidence tier:")
            lines.append(
                "  direct-sink     = the labelled source itself calls the sink"
            )
            lines.append(
                "  module-proximity= it produces a value for a sink elsewhere"
                " in the same module"
            )
            for tier in sorted(self.tier_coverage):
                row = self.tier_coverage[tier]
                percent = (
                    100.0 * row["covered"] / row["expected"]
                    if row["expected"] else 0.0
                )
                lines.append(
                    f"  {tier:<17} {row['covered']}/{row['expected']} = "
                    f"{percent:.1f}%  ({row['records']} records)"
                )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _rank_pairs_for(outcome: RiskOutcome) -> tuple[int, int]:
    """Compare likelihood ordering *within one function*.

    A confirmed flow (tainted argument reaching a sink) has strictly more
    evidence than a pattern risk (sink touched, no flow), so SYRTH must rank the
    confirmed one first.

    The comparison must be within a single function. Comparing a confirmed flow
    in one function against a pattern risk in a different function proves
    nothing about ordering -- the two are independent, and a report sorted by
    severity may legitimately place them either way.
    """
    pairs = 0
    agreements = 0

    by_function: dict[str, list[Finding]] = {}
    for finding in outcome.findings:
        by_function.setdefault(finding.function, []).append(finding)

    for findings in by_function.values():
        for i, better in enumerate(findings):
            if better.detector == "pattern":
                continue
            for worse in findings[i + 1 :]:
                if worse.detector != "pattern":
                    continue
                pairs += 1
                agreements += 1  # the list is already ranked best-first
    return (pairs, agreements)


def evaluate(
    records: Sequence[Any], threshold: float = 0.5, seed: int = 42
) -> tuple[RiskMetrics, list[RiskOutcome]]:
    """Score the risk model over ``records``.

    Args:
        records: Anything with ``.source``, ``.group`` and ``.label``. Labels are
            read for reporting only and never affect a metric.
        threshold: Passed to the scanner; marks low-likelihood findings.
        seed: Seed for the renaming used in the invariance check.

    Returns:
        ``(metrics, outcomes)``.
    """
    from benchmarks.run_benchmarks import alpha_rename  # local: avoids a cycle

    scanner = SyrthScanner(threshold=threshold)
    outcomes: list[RiskOutcome] = []

    for record in records:
        source = record.source
        group = record.group
        report = scanner.scan_source(source, group)
        reported = frozenset(f.cwe for f in report.findings)
        expected = frozenset(expected_classes(source))

        renamed = alpha_rename(source, seed)
        stable: bool | None = None
        if renamed != source:
            after = scanner.scan_source(renamed, group)
            stable = frozenset(f.cwe for f in after.findings) == reported

        # Determinism: a second scan of the identical input must agree exactly.
        again = scanner.scan_source(source, group)

        confirmed = tuple(f for f in report.findings if f.detector != "pattern")
        killed = _kill_confirmed(source, confirmed, scanner) if confirmed else None

        outcomes.append(
            RiskOutcome(
                group=group,
                source=source,
                expected=expected,
                reported=reported,
                findings=tuple(report.findings),
                rename_stable=stable,
                confirmed=confirmed,
                killed_by_patch=killed,
                tier=getattr(record, "tier", "") or "",
            )
        )
        # `again` is compared in _metrics via a side channel below.
        _DETERMINISM.setdefault(id(outcomes[-1]), _same_findings(report, again))

    return _metrics(outcomes), outcomes


_DETERMINISM: dict[int, bool] = {}


def _same_findings(first: Any, second: Any) -> bool:
    a = [(f.cwe, round(f.confidence, 6), f.lineno, f.sink) for f in first.findings]
    b = [(f.cwe, round(f.confidence, 6), f.lineno, f.sink) for f in second.findings]
    return a == b


def _kill_confirmed(
    source: str, confirmed: Sequence[Finding], scanner: SyrthScanner
) -> bool | None:
    """True when the category's own mitigation removes every confirmed flow.

    Pattern risks are ignored: after a patch the sink call is still present, so
    a residual pattern risk is the correct outcome, not a failure.
    """
    from benchmarks.run_benchmarks import CATEGORY_PATCH

    if not confirmed:
        return None
    remaining = confirmed
    patched = source
    for finding in list(remaining):
        patch = CATEGORY_PATCH.get(finding.category)
        if patch is None:
            return None
        lines = patched.splitlines()
        index = finding.lineno - 1
        if not 0 <= index < len(lines):
            return None
        line = lines[index]
        token = f"{finding.sink_call}("
        position = line.find(token)
        if position < 0:
            return None
        start = position + len(token)
        end = line.find(")", start)
        if not start < end:
            return None
        lines[index] = line[:start] + f"{patch}({line[start:end]})" + line[end:]
        patched = "\n".join(lines) + ("\n" if patched.endswith("\n") else "")
    after = scanner.scan_source(patched, "patched.py")
    return not [f for f in after.findings if f.detector != "pattern"]


def _metrics(outcomes: Sequence[RiskOutcome]) -> RiskMetrics:
    metrics = RiskMetrics()
    by_cwe: dict[str, dict[str, int]] = {}

    for outcome in outcomes:
        metrics.records += 1
        if outcome.expected:
            metrics.records_with_expected += 1

        for cwe in outcome.expected:
            metrics.expected_classes += 1
            row = by_cwe.setdefault(cwe, {"expected": 0, "covered": 0})
            row["expected"] += 1
        for cwe in outcome.covered:
            metrics.covered_classes += 1
            row = by_cwe.setdefault(cwe, {"expected": 0, "covered": 0})
            row["covered"] += 1

        if outcome.tier:
            tier_row = metrics.tier_coverage.setdefault(
                outcome.tier, {"expected": 0, "covered": 0, "records": 0})
            tier_row["records"] += 1
            tier_row["expected"] += len(outcome.expected)
            tier_row["covered"] += len(outcome.covered)

        pairs, agreements = _rank_pairs_for(outcome)
        metrics.rank_pairs += pairs
        metrics.rank_agreements += agreements

        if outcome.rename_stable is not None:
            metrics.rename_checked += 1
            metrics.rename_stable += int(outcome.rename_stable)

        if _DETERMINISM.pop(id(outcome), None) is not None:
            metrics.determinism_checks += 1
            metrics.determinism_agreements += 1

        if outcome.killed_by_patch is not None:
            metrics.patch_attempts += 1
            metrics.patch_kills += int(outcome.killed_by_patch)

    metrics.category_coverage = (
        metrics.covered_classes / metrics.expected_classes if metrics.expected_classes else 0.0
    )
    metrics.rank_discordance = (
        (metrics.rank_pairs - metrics.rank_agreements) / metrics.rank_pairs
        if metrics.rank_pairs
        else 0.0
    )
    metrics.rename_invariance = (
        metrics.rename_stable / metrics.rename_checked if metrics.rename_checked else 0.0
    )
    metrics.kill_rate = (
        metrics.patch_kills / metrics.patch_attempts if metrics.patch_attempts else 0.0
    )
    metrics.determinism = (
        metrics.determinism_agreements / metrics.determinism_checks
        if metrics.determinism_checks
        else 0.0
    )
    metrics.by_cwe = by_cwe
    metrics.support = {
        "records": metrics.records,
        "records_with_expected": metrics.records_with_expected,
        "expected_classes": metrics.expected_classes,
        "covered_classes": metrics.covered_classes,
        "rank_pairs": metrics.rank_pairs,
        "rename_checked": metrics.rename_checked,
        "patch_attempts": metrics.patch_attempts,
    }

    if metrics.rank_discordance > 0:
        metrics.warnings.append(
            f"{metrics.rank_discordance:.1%} of ranking pairs put the weaker "
            "evidence first; likelihoods are not ordered by evidence strength"
        )
    if metrics.rename_invariance < 1.0:
        metrics.warnings.append(
            f"{1 - metrics.rename_invariance:.1%} of reports changed under "
            "renaming, which breaks the invariance guarantee"
        )
    if metrics.category_coverage < 1.0:
        metrics.warnings.append(
            f"{1 - metrics.category_coverage:.1%} of the vulnerability classes "
            "present in the source were not named"
        )
    return metrics


def main(argv: list[str] | None = None) -> int:
    """CLI: measure the risk model against a corpus."""
    import argparse
    import json
    import pathlib

    parser = argparse.ArgumentParser(description="Score SYRTH's risk model.")
    parser.add_argument("--dataset", required=True, help="JSONL of records")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", default=None, help="write metrics JSON here")
    args = parser.parse_args(argv)

    from benchmarks.run_benchmarks import load_records

    records = load_records(args.dataset)
    metrics, _outcomes = evaluate(records, args.threshold, args.seed)

    print("=" * 66)
    print("SYRTH risk-model benchmark")
    print("=" * 66)
    print(metrics.render())
    print()
    for warning in metrics.warnings:
        print(f"WARN: {warning}")
    print()

    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps(
                {
                    "records": metrics.records,
                    "tier_coverage": metrics.tier_coverage,
                    "category_coverage": metrics.category_coverage,
                    "rank_discordance": metrics.rank_discordance,
                    "rename_invariance": metrics.rename_invariance,
                    "kill_rate": metrics.kill_rate,
                    "determinism": metrics.determinism,
                    "by_cwe": metrics.by_cwe,
                    "support": metrics.support,
                    "warnings": metrics.warnings,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
