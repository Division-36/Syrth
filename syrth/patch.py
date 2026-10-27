"""
SYRTH Patch Synthesis and Verification
======================================
Proposes fixes for confirmed flows and *mechanically proves* whether they work.

The loop this closes
--------------------
Detection is only half the job. Every static analyser in production leaves a
manual step: a developer fixes the flagged line, and nobody checks whether the
fix actually removed the flow. This module makes that step mechanical:

1.  A :class:`PatchBackend` proposes a source rewrite for one trace.
2.  The rewrite is applied to a copy of the file.
3.  :func:`verify` re-analyses the patched file and requires **three** properties
    before a patch is accepted:
        * the targeted flow is **gone**;
        * **no new** flow appeared anywhere in the file;
        * the file still **parses**.
4.  The verdict is recorded per patch, and a rejected patch is reported with the
    reason rather than silently dropped.

Only property 1 makes this "fix verification". Properties 2 and 3 are what make
it safe to automate: a patch that silences one finding by introducing another, or
by breaking the file, is a regression.

Backends
--------
:class:`SanitiserBackend`
    Deterministic and offline. Applies the category-typed sanitiser that the kill
    model already understands, for the categories where that is a semantically
    correct fix. It **refuses** the categories where no mechanical rewrite is
    sound -- SQL in particular requires real parameterisation, and emitting a
    plausible-looking but wrong query would be worse than emitting nothing.

:class:`CommandBackend`
    Delegates to an external command, which is how an LLM or a human is plugged
    in. SYRTH does not pretend to contain a model: if you want a model in this
    loop, you bring one, and it is judged by the same mechanical criteria.

Verification is backend-independent: any backend's output passes or fails the
same three checks.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .diff import DiffReport, diff_reports
from .registry import Category
from .scan import Finding, SyrthScanner
from .trace import Trace

#: The import each sanitiser requires, keyed by canonical sanitiser name.
SANITISER_IMPORT: dict[str, tuple[str, str]] = {
    "shlex.quote": ("import shlex\n", "shlex"),
    "os.path.basename": ("import os.path\n", "os"),
    "html.escape": ("import html\n", "html"),
    "urllib.parse.quote": ("import urllib.parse\n", "urllib"),
}

#: Which sanitiser the deterministic backend uses per category, and whether that
#: sanitiser is a *sound* complete fix for the category. Where it is not, the
#: backend refuses rather than emitting a rewrite it cannot justify.
CATEGORY_FIX: dict[str, str | None] = {
    Category.EXEC: "shlex.quote",
    Category.FILE: "os.path.basename",
    Category.XSS: "html.escape",
    Category.REDIRECT: "urllib.parse.quote",
    Category.NET: None,
    Category.SQL: None,
    Category.DESER: None,
    Category.CRYPTO: None,
    Category.CRED: None,
    Category.UPLOAD: None,
    Category.XXE: "defusedxml.fromstring",
}

#: Why the backend declines, per category. Recorded so a refusal is actionable.
REFUSAL_REASON: dict[str, str] = {
    Category.SQL: (
        "requires converting the statement to a parameterised query; the "
        "literal and its placeholders must be derived from the original, which "
        "no mechanical rewrite can do soundly"
    ),
    Category.DESER: (
        "requires choosing a data-only format, which changes the wire protocol "
        "and cannot be inferred from the call site"
    ),
    Category.NET: (
        "requires validating the destination host against an allow-list; the "
        "allow-list is a policy decision, not a mechanical transformation"
    ),
    Category.CRYPTO: "requires choosing an algorithm and a migration path",
    Category.CRED: "requires moving the secret into a secret store",
    Category.UPLOAD: "requires defining the validation and storage policy",
}


@dataclass
class PatchProposal:
    """A proposed source rewrite.

    Attributes:
        trace_id: Identity of the flow this patch targets.
        function: Enclosing function name.
        category: Sink category.
        backend: Which backend produced it.
        rationale: One line explaining the change.
        patched_source: The full rewritten file.
        line_delta: Lines added minus lines removed, for review.
        refused: True when the backend declined, with :attr:`rationale` saying why.
    """

    trace_id: str
    function: str
    category: str
    backend: str
    rationale: str
    patched_source: str | None = None
    line_delta: int = 0
    refused: bool = False

    @property
    def applicable(self) -> bool:
        """True when a rewrite was produced."""
        return not self.refused and self.patched_source is not None

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable view."""
        return {
            "trace_id": self.trace_id,
            "function": self.function,
            "category": self.category,
            "backend": self.backend,
            "rationale": self.rationale,
            "line_delta": self.line_delta,
            "refused": self.refused,
        }


@dataclass
class PatchResult:
    """The verdict on one proposal.

    Attributes:
        proposal: The proposal that was judged.
        flow_killed: True when the targeted flow is gone from the patched file.
        new_flows: Flows that appeared in the patched file.
        parses: True when the patched file is syntactically valid Python.
        accepted: True only when all three checks pass.
        reasons: Why the patch was rejected, or a note when it was accepted.
    """

    proposal: PatchProposal
    flow_killed: bool = False
    new_flows: tuple[str, ...] = ()
    parses: bool = True
    accepted: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable view."""
        return {
            **self.proposal.to_dict(),
            "flow_killed": self.flow_killed,
            "new_flows": list(self.new_flows),
            "parses": self.parses,
            "accepted": self.accepted,
            "reasons": list(self.reasons),
        }


class PatchBackend(Protocol):
    """Protocol every patch backend implements."""

    name: str

    def propose(self, source: str, finding: Finding, trace: Trace) -> PatchProposal:
        """Propose a rewrite for one finding."""
        ...


# ---------------------------------------------------------------------------
# Deterministic backend
# ---------------------------------------------------------------------------


class SanitiserBackend:
    """Offline, deterministic backend.

    Wraps the sink argument in the category-typed sanitiser that the kill model
    recognises, and adds the import it needs. Applies to the categories where
    that rewrite is a complete fix; declines the others with a recorded reason.
    """

    name = "sanitiser"

    def propose(self, source: str, finding: Finding, trace: Trace) -> PatchProposal:
        """Propose a sanitiser insertion, or decline with a reason."""
        category = finding.category
        sanitiser = CATEGORY_FIX.get(category)
        if sanitiser is None:
            return PatchProposal(
                trace_id=trace.trace_id,
                function=finding.function,
                category=category,
                backend=self.name,
                rationale="declined: " + REFUSAL_REASON.get(
                    category, "no mechanical fix is known for this category"
                ),
                refused=True,
            )

        span = _sink_argument_span(source, finding)
        if span is None:
            return PatchProposal(
                trace_id=trace.trace_id,
                function=finding.function,
                category=category,
                backend=self.name,
                rationale="declined: the sink argument could not be located "
                          "unambiguously in the source",
                refused=True,
            )

        start, end = span
        patched = source[:start] + f"{sanitiser}({source[start:end]})" + source[end:]
        patched = _ensure_import(patched, sanitiser)
        delta = len(patched.splitlines()) - len(source.splitlines())
        return PatchProposal(
            trace_id=trace.trace_id,
            function=finding.function,
            category=category,
            backend=self.name,
            rationale=(
                f"wrap the {category} sink argument in {sanitiser}, which the "
                f"kill model recognises as a complete mitigation for {category}"
            ),
            patched_source=patched,
            line_delta=delta,
        )


def _sink_argument_span(source: str, finding: Finding) -> tuple[int, int] | None:
    """Locate the sink argument text in the source.

    Works on the single line the sink call starts on and returns character
    offsets into the whole file.

    Returns:
        ``(start, end)`` of the argument expression, or ``None`` when it cannot be
        located unambiguously. Refusing to guess is deliberate: a rewrite applied
        to the wrong span is worse than no rewrite.
    """
    lines = source.splitlines(keepends=True)
    index = finding.lineno - 1
    if not 0 <= index < len(lines):
        return None
    line = lines[index]
    # Offsets returned must be absolute in ``source``, so record where this line
    # begins. Splicing line-relative offsets into the whole file is the kind of
    # off-by-N that produces a file that no longer parses -- which is exactly
    # what the verification step exists to catch.
    line_start = sum(len(text) for text in lines[:index])

    call_position = line.find(f"{finding.sink_call}(")
    if call_position < 0:
        short = finding.sink_call.rpartition(".")[2]
        call_position = line.find(f"{short}(")
        if call_position < 0:
            return None
    open_paren = call_position + len(finding.sink_call) - 1
    if open_paren >= len(line) or line[open_paren] != "(":
        short = finding.sink_call.rpartition(".")[2]
        call_position = line.find(f"{short}(")
        if call_position < 0:
            return None
        open_paren = call_position + len(short)
    close_paren = line.rfind(")")
    if close_paren <= open_paren:
        return None

    body = line[open_paren + 1 : close_paren]
    offset = open_paren + 1

    if finding.sink_arg.startswith("kw:"):
        keyword = finding.sink_arg[3:] + "="
        position = body.find(keyword)
        if position < 0:
            return None
        inner_start = position + len(keyword)
        inner_end = _end_of_expression(body, inner_start)
        if inner_end is None:
            return None
        return (line_start + offset + inner_start, line_start + offset + inner_end)

    if finding.sink_arg.startswith("pos:"):
        try:
            wanted = int(finding.sink_arg[4:])
        except ValueError:
            return None
        position, end = _nth_argument(body, wanted)
        if position is None or end is None:
            return None
        return (line_start + offset + position, line_start + offset + end)

    # A splatted argument has no single span.
    return None


def _nth_argument(body: str, wanted: int) -> tuple[int | None, int | None]:
    """Offsets of the ``wanted``-th top-level argument inside ``body``."""
    depth = 0
    quote: str | None = None
    index = 0
    start = 0
    seen = 0
    while index < len(body):
        char = body[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                if seen == wanted:
                    return (start, index)
                break
            depth -= 1
        elif char == "," and depth == 0:
            if seen == wanted:
                return (start, index)
            seen += 1
            start = index + 1
        index += 1
    if seen == wanted:
        return (start, len(body))
    return (None, None)


def _end_of_expression(body: str, start: int) -> int | None:
    """Offset just past the expression beginning at ``start``.

    Handles nested brackets and string literals, and stops at the first
    top-level comma or the end of ``body``. A keyword argument's value is
    frequently *not* parenthesised (``execute(sql="..." , params=x)``), so
    matching a bracket pair would fail to locate it at all.

    Returns:
        The end offset, or ``None`` when the expression cannot be delimited --
        which happens on an unbalanced body, where refusing is correct.
    """
    depth = 0
    quote: str | None = None
    index = start
    while index < len(body):
        char = body[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif char == "," and depth == 0:
            return index
        index += 1
    if quote is not None:
        return None
    return len(body)


def _ensure_import(source: str, sanitiser: str) -> str:
    """Add the import a sanitiser needs, unless it is already present."""
    module, _root = SANITISER_IMPORT.get(sanitiser, ("", ""))
    if not module:
        return source
    root = module.split()[1].split(".")[0]
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ") and root in stripped:
            return source
        if stripped.startswith("from ") and root in stripped:
            return source
    lines = source.splitlines(keepends=True)
    insert_at = 0
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("import ", "from ")):
            insert_at = index + 1
        elif line.strip() and not line.lstrip().startswith("#"):
            break
    lines.insert(insert_at, module)
    return "".join(lines)


# ---------------------------------------------------------------------------
# Command backend
# ---------------------------------------------------------------------------


class CommandBackend:
    """Delegates to an external command, one invocation per finding.

    This is the seam for an LLM or a human. SYRTH does not ship a model and does
    not pretend to: the point of the seam is that whatever produces the rewrite is
    judged by the same three mechanical checks, so a model cannot talk its way
    into an accepted bad patch.

    The command is called as::

        <argv...> <path-to-source-file>

    and must write the patched source to stdout.

    Attributes:
        name: Backend label recorded on each proposal.
        argv: The command to run.
        timeout: Seconds before the command is abandoned.
    """

    def __init__(
        self,
        argv: Sequence[str],
        name: str = "command",
        timeout: float = 60.0,
    ):
        if not argv:
            raise ValueError("CommandBackend needs a command to run")
        if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
            raise FileNotFoundError(f"command not found: {argv[0]}")
        self.name = name
        self.argv = list(argv)
        self.timeout = float(timeout)

    def propose(self, source: str, finding: Finding, trace: Trace) -> PatchProposal:
        """Ask the external command for a rewrite.

        A command that fails, times out or returns something that does not parse
        yields a refused proposal carrying the reason, so a broken backend is
        visible rather than silent.
        """
        workspace = Path(".syrth-patch").resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        target = workspace / "input.py"
        target.write_text(source, encoding="utf-8")
        try:
            completed = subprocess.run(
                [*self.argv, str(target)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return PatchProposal(
                trace_id=trace.trace_id, function=finding.function,
                category=finding.category, backend=self.name,
                rationale=f"declined: the command timed out after {self.timeout}s",
                refused=True,
            )
        except OSError as exc:
            return PatchProposal(
                trace_id=trace.trace_id, function=finding.function,
                category=finding.category, backend=self.name,
                rationale=f"declined: the command could not be run ({exc})",
                refused=True,
            )
        finally:
            target.unlink(missing_ok=True)

        if completed.returncode != 0:
            return PatchProposal(
                trace_id=trace.trace_id, function=finding.function,
                category=finding.category, backend=self.name,
                rationale=(
                    "declined: the command exited "
                    f"{completed.returncode}: {(completed.stderr or '').strip()[:200]}"
                ),
                refused=True,
            )
        patched = completed.stdout
        if not patched.strip():
            return PatchProposal(
                trace_id=trace.trace_id, function=finding.function,
                category=finding.category, backend=self.name,
                rationale="declined: the command produced no output",
                refused=True,
            )
        return PatchProposal(
            trace_id=trace.trace_id,
            function=finding.function,
            category=finding.category,
            backend=self.name,
            rationale="external rewrite supplied by " + " ".join(self.argv),
            patched_source=patched,
            line_delta=len(patched.splitlines()) - len(source.splitlines()),
        )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify(
    proposal: PatchProposal,
    source: str,
    finding: Finding,
    trace: Trace,
    scanner: SyrthScanner | None = None,
) -> PatchResult:
    """Judge a proposal against the three acceptance criteria.

    Args:
        proposal: The proposal to judge.
        source: The original source the proposal rewrites.
        finding: The finding the patch targets.
        trace: The trace the patch targets.
        scanner: Scanner to reuse. A fresh one is built when omitted.

    Returns:
        A :class:`PatchResult`. ``accepted`` is true only when the targeted flow
        is gone, no new flow appeared, and the file still parses.
    """
    result = PatchResult(proposal=proposal)

    if not proposal.applicable:
        result.reasons.append(proposal.rationale)
        return result

    patched = proposal.patched_source or ""
    result.parses = _parses(patched)
    if not result.parses:
        result.reasons.append("the patched file is not valid Python")
        return result

    engine = scanner or SyrthScanner()
    before = engine.scan_source(source, finding.file)
    after = engine.scan_source(patched, finding.file)

    comparison: DiffReport = diff_reports(before, after, "original", "patched")

    killed = {entry.trace.trace_id for entry in comparison.killed}
    changed = {entry.trace.trace_id for entry in comparison.changed}
    residual = {entry.trace.trace_id for entry in comparison.residual}
    introduced = comparison.introduced
    target = trace.trace_id

    # The flow must be *gone*, not merely reshaped. A rewrite that swaps one
    # execution sink for another keeps the same trace identity (same function,
    # same canonical sink, same argument, same origins) and the diff reports it
    # as `changed`; treating that as a fix would let a patch trade one injection
    # for another and still be accepted.
    if target in killed:
        result.flow_killed = True
    elif target in changed:
        result.flow_killed = False
        entry = next(e for e in comparison.changed if e.trace.trace_id == target)
        result.reasons.append(
            f"the flow was rewritten rather than removed: it still reaches "
            f"{entry.trace.sink} at {entry.location}"
        )
    elif target in residual:
        result.flow_killed = False
        result.reasons.append("the targeted flow is still present after patching")
    else:
        # The identity vanished entirely -- for example the sink call was
        # deleted. That is a genuine removal.
        result.flow_killed = True

    if introduced:
        result.new_flows = tuple(sorted({e.trace.trace_id for e in introduced}))
        result.reasons.append(
            f"the patch introduced {len(introduced)} new flow(s): "
            + ", ".join(e.location for e in introduced[:3])
        )
    result.accepted = result.flow_killed and not introduced and result.parses
    if result.accepted:
        result.reasons.append(
            "verified: the targeted flow is gone, no new flow appeared, and the "
            "file still parses"
        )
    return result


def _parses(source: str) -> bool:
    """True when ``source`` is syntactically valid Python."""
    try:
        ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    return True


def propose_and_verify(
    source: str,
    report,
    backend: PatchBackend | None = None,
    scanner: SyrthScanner | None = None,
    apply: bool = False,
) -> tuple[list[PatchResult], str]:
    """Propose and judge a patch for every finding in a report.

    Patches are applied cumulatively in severity order, and the work list is
    **re-derived from a fresh scan after each accepted patch**. This matters:
    inserting an ``import`` shifts every line below it, so findings carried over
    from the original report would carry stale line numbers, and the second patch
    would be spliced into the wrong line. Trace identities are line-independent,
    so they are the stable key for "already handled".

    Args:
        source: Original source.
        report: A :class:`~syrth.scan.ScanReport` for ``source``.
        backend: Backend to use. Defaults to :class:`SanitiserBackend`.
        scanner: Scanner to reuse.
        apply: When true, accepted patches are folded into the returned source.

    Returns:
        ``(results, final_source)``. ``final_source`` equals ``source`` when
        ``apply`` is false.
    """
    engine = scanner or SyrthScanner()
    chosen = backend or SanitiserBackend()
    path = report.file or "<source>"

    results: list[PatchResult] = []
    handled: set = set()
    current = source
    live = report
    rewrote = False

    while True:
        candidate = next(
            (
                finding
                for finding in live.findings
                if finding.trace_id not in handled
            ),
            None,
        )
        if candidate is None:
            break

        trace = next((t for t in live.traces if t.trace_id == candidate.trace_id), None)
        if trace is None:
            handled.add(candidate.trace_id)
            continue

        proposal = chosen.propose(current, candidate, trace)
        result = verify(proposal, current, candidate, trace, engine)
        results.append(result)
        handled.add(candidate.trace_id)

        if apply and result.accepted and proposal.patched_source:
            current = proposal.patched_source
            rewrote = True
            live = engine.scan_source(current, path)

    if apply and not rewrote:
        return results, source
    return results, current


def render(results: Sequence[PatchResult]) -> str:
    """Human-readable rendering of patch results."""
    lines = ["=" * 72, "SYRTH patch verification", "=" * 72]
    if not results:
        lines.append("nothing to patch")
        lines.append("")
        return "\n".join(lines)

    accepted = [r for r in results if r.accepted]
    refused = [r for r in results if not r.proposal.applicable]
    rejected = [r for r in results if r.proposal.applicable and not r.accepted]

    lines.append(
        f"proposed {len(results)}  accepted {len(accepted)}  "
        f"rejected {len(rejected)}  declined {len(refused)}"
    )
    for group, heading in ((accepted, "ACCEPTED"), (rejected, "REJECTED"),
                           (refused, "DECLINED")):
        if not group:
            continue
        lines.append("")
        lines.append(f"{heading} ({len(group)})")
        for result in group:
            proposal = result.proposal
            lines.append(
                f"  {proposal.trace_id}  {proposal.category:<9} "
                f"{proposal.function}()  [{proposal.backend}]"
            )
            for reason in result.reasons:
                lines.append(f"      {reason}")
    lines.append("")
    lines.append(
        "An accepted patch has been proven to remove the flow without "
        "introducing another. A rejected or declined patch has not been applied."
    )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "CATEGORY_FIX",
    "CommandBackend",
    "PatchBackend",
    "PatchProposal",
    "PatchResult",
    "REFUSAL_REASON",
    "SANITISER_IMPORT",
    "SanitiserBackend",
    "propose_and_verify",
    "render",
    "verify",
]
