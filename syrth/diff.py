"""
SYRTH Revision Diff
===================
Compares two scan reports and answers the question a security reviewer actually
has after a patch: *did this change remove the flow, add one, or leave it
dangling?*

Why this is not just "diff the findings"
---------------------------------------
Finding lists are positional, so a one-line insertion above a sink shifts every
line number and makes every finding look new. A :class:`~syrth.trace.Trace`
carries a :attr:`~syrth.trace.Trace.trace_id` computed from its *structure* --
function name, canonical sink, sink argument, origin set and the sequence of
propagation edges -- with line numbers deliberately excluded. Two revisions
therefore match the same flow even when the code moved.

Matching strategy
-----------------
Traces are matched on :attr:`~syrth.trace.Trace.trace_id`, which is derived from
the flow's structure -- function, canonical sink, sink argument, origin set and
the full sequence of propagation edges -- with line numbers excluded. Two
revisions therefore match the same flow even when the code moved.

There is deliberately **no** looser fallback that matches on function, sink and
origin while ignoring the propagation edges. Such a fallback silently pairs two
*different* flows: rewriting ``os.system("ls " + x)`` into ``eval(x)`` produces two
distinct traces that share function, sink, argument and origins, and a loose
matcher would report that substitution as "the same flow, slightly moved" -- so a
patch that trades one code-execution injection for another would be recorded as a
fix. Reporting the truth instead -- one flow killed, another introduced -- is both
more honest and what makes :func:`syrth.patch.verify` able to reject the patch.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .scan import ScanReport
from .trace import Trace, sort_traces

#: Diff outcome vocabulary.
INTRODUCED = "introduced"
KILLED = "killed"
RESIDUAL = "residual"
CHANGED = "changed"


@dataclass
class DiffEntry:
    """One trace's fate across a revision pair.

    Attributes:
        outcome: One of ``introduced``, ``killed``, ``residual`` or ``changed``.
        trace: The trace on the side where it is present. For ``killed`` this is
            the trace from the *before* revision.
        counterpart: The matching trace on the other side, when there is one.
        line_delta: For ``changed``, how far the sink moved. Positive means it
            moved down the file.
    """

    outcome: str
    trace: Trace
    counterpart: Trace | None = None
    line_delta: int = 0

    @property
    def cwe(self) -> str:
        """CWE of the primary trace."""
        return self.trace.cwe

    @property
    def location(self) -> str:
        """``path:line`` of the primary trace."""
        return f"{self.trace.file}:{self.trace.sink_line}"

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable view."""
        return {
            "outcome": self.outcome,
            "cwe": self.cwe,
            "category": self.trace.category,
            "sink": self.trace.sink,
            "location": self.location,
            "trace_id": self.trace.trace_id,
            "counterpart_id": self.counterpart.trace_id if self.counterpart else None,
            "line_delta": self.line_delta,
            "detail": self.trace.summary(),
        }


@dataclass
class DiffReport:
    """Result of comparing two revisions.

    Attributes:
        before: Label for the baseline revision.
        after: Label for the compared revision.
        entries: Every classified trace, worst outcomes first.
        errors: Errors from either side, so a scan failure is never mistaken for
            "the patch fixed everything".
    """

    before: str = "before"
    after: str = "after"
    entries: list[DiffEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def of(self, outcome: str) -> list[DiffEntry]:
        """Entries with a given outcome."""
        return [entry for entry in self.entries if entry.outcome == outcome]

    @property
    def introduced(self) -> list[DiffEntry]:
        """Flows present only after the change."""
        return self.of(INTRODUCED)

    @property
    def killed(self) -> list[DiffEntry]:
        """Flows present only before the change."""
        return self.of(KILLED)

    @property
    def residual(self) -> list[DiffEntry]:
        """Flows present in both revisions."""
        return self.of(RESIDUAL)

    @property
    def changed(self) -> list[DiffEntry]:
        """Flows present in both revisions whose shape changed."""
        return self.of(CHANGED)

    @property
    def net_new(self) -> int:
        """Number of newly introduced flows."""
        return len(self.introduced)

    @property
    def fixed(self) -> int:
        """Number of removed flows."""
        return len(self.killed)

    def verdict(self) -> str:
        """One-word assessment of the change.

        ``regression`` when new flows appeared, ``improved`` when flows were
        removed and none added, ``mixed`` when both happened, and ``neutral``
        when neither did.
        """
        if self.introduced:
            return "regression" if not self.killed else "mixed"
        return "improved" if self.killed else "neutral"

    def summary(self) -> dict[str, object]:
        """Counts by outcome plus the verdict."""
        return {
            "before": self.before,
            "after": self.after,
            "introduced": len(self.introduced),
            "killed": len(self.killed),
            "residual": len(self.residual),
            "changed": len(self.changed),
            "verdict": self.verdict(),
            "errors": list(self.errors),
        }

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable view."""
        return {**self.summary(), "entries": [e.to_dict() for e in self.entries]}

    def render(self) -> str:
        """Human-readable rendering."""
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append(f"SYRTH revision diff: {self.before} -> {self.after}")
        lines.append("=" * 72)
        counts = self.summary()
        lines.append(
            "introduced {introduced}  killed {killed}  residual {residual}  "
            "changed {changed}".format(
                introduced=counts["introduced"], killed=counts["killed"],
                residual=counts["residual"], changed=counts["changed"],
            )
        )
        lines.append(f"verdict: {counts['verdict']}")
        for outcome in (INTRODUCED, CHANGED, RESIDUAL, KILLED):
            group = self.of(outcome)
            if not group:
                continue
            lines.append("")
            lines.append(f"{outcome.upper()} ({len(group)})")
            for entry in group:
                lines.append(f"  {entry.location}  {entry.cwe}  {entry.trace.sink}")
                lines.append(f"      {entry.trace.summary()}")
                if entry.outcome == CHANGED:
                    lines.append(f"      sink moved {entry.line_delta:+d} line(s)")
        if self.errors:
            lines.append("")
            lines.append("ERRORS (a failed scan is not evidence of a fix)")
            for message in self.errors:
                lines.append(f"  {message}")
        lines.append("")
        return "\n".join(lines)


def diff_traces(
    before: Sequence[Trace], after: Sequence[Trace]
) -> list[DiffEntry]:
    """Classify every trace across two revisions.

    Args:
        before: Traces from the baseline revision.
        after: Traces from the compared revision.

    Returns:
        Entries ordered by outcome severity, then location.
    """
    before_list = sort_traces(before)
    after_list = sort_traces(after)

    entries: list[DiffEntry] = []
    remaining_before = list(before_list)
    remaining_after = list(after_list)

    # Pass 1: identity. A flow is the same flow exactly when its identity,
    # which encodes the whole propagation path, matches. A location change alone
    # makes the entry `changed` so the reader can see the code moved.
    after_by_id: dict[str, Trace] = {}
    for trace in remaining_after:
        after_by_id.setdefault(trace.trace_id, trace)

    matched_after: set = set()
    for trace in list(remaining_before):
        counterpart = after_by_id.get(trace.trace_id)
        if counterpart is None:
            continue
        delta = counterpart.sink_line - trace.sink_line
        entries.append(
            DiffEntry(
                outcome=CHANGED if delta != 0 else RESIDUAL,
                trace=counterpart,
                counterpart=trace,
                line_delta=delta,
            )
        )
        matched_after.add(counterpart.trace_id)
        remaining_before.remove(trace)

    remaining_after = [t for t in remaining_after if t.trace_id not in matched_after]

    # Anything left is unmatched on exactly one side, so it is genuinely
    # introduced or killed.
    for trace in remaining_before:
        entries.append(DiffEntry(outcome=KILLED, trace=trace))
    for trace in remaining_after:
        entries.append(DiffEntry(outcome=INTRODUCED, trace=trace))

    order = {INTRODUCED: 0, CHANGED: 1, RESIDUAL: 2, KILLED: 3}
    entries.sort(
        key=lambda e: (order[e.outcome], e.trace.file, e.trace.sink_line, e.trace.trace_id)
    )
    return entries


def diff_reports(
    before: ScanReport, after: ScanReport, before_label: str = "before",
    after_label: str = "after",
) -> DiffReport:
    """Compare two scan reports.

    Scan errors from either side are carried into the result. A baseline scan
    that failed must never be reported as "the patch removed every finding".
    """
    result = DiffReport(before=before_label, after=after_label)
    result.entries = diff_traces(before.traces, after.traces)
    result.errors.extend(f"{path}: {message}" for path, message in before.errors)
    result.errors.extend(f"{path}: {message}" for path, message in after.errors)
    return result


def diff_sources(
    scanner,
    before: str,
    after: str,
    filename: str = "<source>",
    before_label: str = "before",
    after_label: str = "after",
) -> DiffReport:
    """Scan two revisions of one source string and diff them.

    Args:
        scanner: A configured :class:`~syrth.scan.SyrthScanner`.
        before: Baseline source text.
        after: Compared source text.
        filename: Path recorded on both sides' traces.
        before_label: Label for the baseline revision.
        after_label: Label for the compared revision.
    """
    return diff_reports(
        scanner.scan_source(before, filename),
        scanner.scan_source(after, filename),
        before_label,
        after_label,
    )


def diff_trees(
    scanner,
    before_root: str,
    after_root: str,
    before_label: str = "before",
    after_label: str = "after",
) -> DiffReport:
    """Scan two directory trees and diff them.

    Both trees are analysed with a shared call graph per tree, so cross-function
    flows participate in the comparison.
    """
    return diff_reports(
        scanner.scan_paths([before_root]),
        scanner.scan_paths([after_root]),
        before_label,
        after_label,
    )


def patch_status(
    diff: DiffReport, expected_kills: Iterable[str] = ()
) -> tuple[bool, list[str]]:
    """Decide whether a patch achieved what it claimed.

    A patch is accepted only when it introduced no new flows and killed at least
    one. When ``expected_kills`` names CWE identifiers, every one of them must
    have been killed.

    Args:
        diff: The comparison result.
        expected_kills: CWE identifiers the patch claimed to fix.

    Returns:
        ``(accepted, reasons)``. ``reasons`` is empty when accepted.
    """
    reasons: list[str] = []
    if diff.errors:
        reasons.append("scan errors present; the comparison is not conclusive")
    if diff.introduced:
        locations = ", ".join(entry.location for entry in diff.introduced[:5])
        reasons.append(f"{len(diff.introduced)} new flow(s) introduced: {locations}")
    expected = {cwe.strip() for cwe in expected_kills if cwe.strip()}
    if expected:
        killed_cwes = {entry.cwe for entry in diff.killed}
        missing = sorted(expected - killed_cwes)
        if missing:
            reasons.append(f"claimed fixes not removed: {', '.join(missing)}")
    if not reasons and not diff.killed and not expected:
        reasons.append("no flow was removed and none was claimed")
    return (not reasons), reasons


__all__ = [
    "CHANGED",
    "DiffEntry",
    "DiffReport",
    "INTRODUCED",
    "KILLED",
    "RESIDUAL",
    "diff_reports",
    "diff_sources",
    "diff_traces",
    "diff_trees",
    "patch_status",
]
