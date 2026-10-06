"""
SYRTH Scanner
=============
End-to-end pipeline: parse -> taint analysis -> interprocedural resolution ->
classification -> traces -> report.

Pipeline
--------
::

    source ──► PythonParser ──► FileTrace (functions + module scope)
                                    │
                                    ├─► FeatureExtractor ──► 84-dim vector
                                    │
                                    └─► Trace set (confirmed source-to-sink paths)
                                          │
                                          ├─► rule classifier (always)
                                          └─► XGBoost classifier (optional, additive)
                                                    │
                                          SyrthScanner ──► ScanReport

Design decisions
----------------
*   **The trace is the answer.** Classification refines a *category*; it never
    decides *whether* a flow exists. A confirmed trace is always reported, and a
    model can at most attach a probability and a rank to it.
*   **Per-record isolation.** Whether the ML path is available is decided once in
    the constructor. A prediction failure is recorded on the record that failed
    and does not disable the model for the rest of the file. The previous
    version mutated shared state inside the per-function loop, so one failure
    silently changed every subsequent answer in the same file.
*   **Out-of-distribution is not "low confidence".** ``ood`` records that the
    classifier could not place the record in its training distribution;
    ``below_threshold`` records that the report policy suppressed it. They are
    separate fields and never conflated.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classifier.rule import (
    CONFIDENCE_UNIQUE_CATEGORY,
    classify,
    classify_sink_categories,
)
from .features import FeatureExtractor
from .interproc import CallGraph, CrossFunctionTrace
from .parser import PythonParser
from .parser.base import FileTrace, FunctionTrace
from .registry import CATEGORY_CWE, SINK_SPECS, Bindings, Category, canonical_sink
from .trace import SCHEMA_VERSION, Trace

#: Likelihood a confirmed flow keeps once a containment check dominates its sink.
#:
#: ``docs/risk-model.md`` gives the shape this models: a confirmed ``subprocess.run``
#: flow drops to ``0.12`` and LOW when an allowlist guard constrains the value. A
#: containment check that exits is the same kind of structural fact, so it lands in
#: the same place rather than at some invented middle value.
CONTAINMENT_GUARD_CONFIDENCE = 0.12

__version__ = "3.0.0"

#: Ceiling on a pattern-only risk. Reaching a sink is not evidence of a
#: vulnerability, so no amount of sink contact may claim a high likelihood.
CONFIDENCE_PATTERN_RISK = CONFIDENCE_UNIQUE_CATEGORY

#: Default confidence below which a finding is reported as review-only rather
#: than as a finding. Confirmed flows score 0.9, amplifiers 0.6, category-only
#: 0.4, so this policy separates "report it" from "mention it".
DEFAULT_THRESHOLD = 0.5

#: File extensions the scanner accepts.
SUPPORTED_EXTENSIONS: dict[str, Any] = {".py": PythonParser}

#: Directories never walked during a repository scan.
PRUNED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", "node_modules", ".tox", ".venv", "venv", "env",
        "build", "dist", ".eggs", "site-packages",
    }
)


class ScanError(RuntimeError):
    """Raised for unrecoverable scanning errors."""


@dataclass
class Finding:
    """One reported vulnerability, backed by at least one trace.

    Attributes:
        function: Enclosing function name, or ``<module>``.
        lineno: 1-indexed line of the sink call.
        cwe: CWE identifier.
        category: Sink category.
        confidence: Confidence in ``[0, 1]``.
        detector: Which detector produced the finding.
        severity: ``critical``/``high``/``medium``/``low``/``info``.
        origins: Taint origins that reached the sink.
        sink: Canonical sink name.
        sink_call: Sink call as written.
        sink_arg: How the data entered the sink.
        steps: The source-to-sink path.
        kills: Sanitisers observed on the path.
        file: Source path.
        trace_id: Identity of the primary trace.
        model: ``"rule"``, ``"ml"`` or ``"hybrid"``.
        reasons: Human-readable evidence lines.
        below_threshold: True when the report policy suppressed the finding.
        ood: True when the classifier could not place the record.
    """

    function: str
    lineno: int
    cwe: str
    category: str
    confidence: float
    detector: str
    severity: str
    origins: tuple[str, ...]
    sink: str
    sink_call: str
    sink_arg: str
    steps: tuple = ()
    kills: tuple[str, ...] = ()
    file: str = ""
    reasons: tuple[str, ...] = ()
    trace_id: str = ""
    model: str = "rule"
    below_threshold: bool = False
    ood: bool = False

    def summary_text(self) -> str:
        """One-line human-readable summary of the finding."""
        origin = "/".join(self.origins) or "no external origin"
        return (
            f"{self.cwe} ({self.category}): untrusted data from {origin} reaches "
            f"{self.sink} in {self.function}() at line {self.lineno} "
            f"via {self.sink_arg}; confidence {self.confidence:.2f}"
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable view."""
        return {
            "function": self.function,
            "lineno": self.lineno,
            "cwe": self.cwe,
            "category": self.category,
            "confidence": round(float(self.confidence), 4),
            "detector": self.detector,
            "severity": self.severity,
            "origins": list(self.origins),
            "sink": self.sink,
            "sink_call": self.sink_call,
            "sink_arg": self.sink_arg,
            "steps": [s.to_dict() for s in self.steps],
            "kills": list(self.kills),
            "file": self.file,
            "trace_id": self.trace_id,
            "model": self.model,
            "reasons": list(self.reasons),
            "below_threshold": self.below_threshold,
            "ood": self.ood,
        }


@dataclass
class ScanReport:
    """Everything produced by one scan run.

    Attributes:
        file: File scanned, or ``""`` for a repository scan.
        mode: ``dev`` when the ML classifier was available, else ``rule``.
        findings: Reportable findings, most severe first.
        suppressed: Findings the report policy withheld.
        traces: Every trace produced, including suppressed ones.
        cross_function: Traces resolved across function boundaries.
        files_scanned: Number of files analysed.
        functions_scanned: Number of functions analysed.
        parse_errors: Paths whose parse was not clean.
        errors: ``(path, message)`` pairs for files that could not be scanned.
        model: ``ml``, ``hybrid`` or ``rule``.
    """

    file: str = ""
    mode: str = "dev"
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    traces: list[Trace] = field(default_factory=list)
    cross_function: list[CrossFunctionTrace] = field(default_factory=list)
    files_scanned: int = 0
    functions_scanned: int = 0
    parse_errors: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    model: str = "rule"

    def summary(self) -> dict[str, Any]:
        """Aggregate counts by CWE and severity."""
        by_cwe: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in self.findings:
            by_cwe[finding.cwe] = by_cwe.get(finding.cwe, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        return {
            "files_scanned": self.files_scanned,
            "functions_scanned": self.functions_scanned,
            "traces": len(self.traces),
            "findings": len(self.findings),
            "suppressed": len(self.suppressed),
            "cross_function_traces": len(self.cross_function),
            "by_cwe": dict(sorted(by_cwe.items())),
            "by_severity": dict(sorted(by_severity.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable view of the whole report."""
        return {
            "schema": SCHEMA_VERSION,
            "file": self.file,
            "mode": self.mode,
            "model": self.model,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.to_dict() for f in self.suppressed],
            "traces": [t.to_dict() for t in self.traces],
            "cross_function": [_cross_to_dict(t) for t in self.cross_function],
            "parse_errors": list(self.parse_errors),
            "errors": [{"file": f, "message": m} for f, m in self.errors],
        }


def _sinks_for_category(
    function: Any, category: str, bindings: Bindings | None
) -> tuple[list[str], list[str]]:
    """The sinks of one category, and the calls as written that reach them.

    A pattern finding previously reported ``",".join(function.sinks)`` for *every*
    category, so a CWE-79 finding in a function that also had a file sink reported
    ``FILE_OPEN`` as its sink. The sink a finding names has to be a sink of the
    class the finding claims, or the finding is not evidence for that class.

    ``sink_call`` is separately a contract violation when it carries canonical
    names such as ``FILE_OPEN``: the field is documented as the sink call as
    written, and a consumer resolving it as a call site cannot. Calls are
    therefore recovered from the function's recorded call names and matched
    through the same resolver that produced the canonical sink.

    Both lists can be empty. A category can be present with no attributed call --
    ``SQL_EXECUTE`` is inferred for a function that merely builds a SQL string --
    and an empty ``sink_call`` is the honest report there, not a missing value.
    """
    canonical = [
        sink for sink in function.sinks
        if (spec := SINK_SPECS.get(sink)) is not None and spec.category == category
    ]
    if not canonical:
        return [], []
    wanted = set(canonical)
    # ``calls`` is in source order and may repeat a name; keep first occurrences
    # only. Without this a call appearing twice produced
    # ``sink_call="os.path.join,os.path.join"``, which is not a call site.
    calls = list(
        dict.fromkeys(
            name for name in function.calls
            if canonical_sink(name, bindings) in wanted
        )
    )
    return canonical, calls


def _containment_evidence(
    file_trace: FileTrace,
) -> dict[tuple[str, int], str]:
    """FILE findings whose sink is dominated by a containment guard.

    A guard is recognised syntactically in :mod:`syrth.containment` and attached
    to the function by the parser, which is the only layer that still has the
    source. This turns that per-function record into the scan decision.

    A sink counts as guarded only when the guard **precedes** it and **shares
    state** with it: an identifier read by the sink's own argument must also be
    read by the guard's test. Without the sharing check a function that validates
    one path and then opens a different one would suppress, which is a false
    negative a reviewer would spot immediately.
    """
    guarded: dict[tuple[str, int], str] = {}
    # Callees whose every return is guard-dominated. A sink fed by one of these is
    # guarded even though the guard sits in another function.
    guarded_callees = {f.name for f in file_trace.functions if f.guarded_returns}
    for function in file_trace.functions:
        if not function.guards and guarded_callees:
            # This function's sinks may be guarded by a caller's predecessor.
            callee = _guarding_callee(function, guarded_callees)
            if callee:
                for trace in function.traces:
                    if trace.category != Category.FILE:
                        continue
                    read = function.sink_argument_names.get(trace.sink_line, frozenset())
                    if callee & read:
                        guarded[(function.name, trace.sink_line)] = (
                            f"{sorted(callee)[0]} returns only guard-dominated values, "
                            "so the path it hands back cannot escape its root"
                        )
            if not function.guards:
                continue
        sink_names = function.sink_argument_names
        for trace in function.traces:
            if trace.category != Category.FILE:
                continue
            read = sink_names.get(trace.sink_line, frozenset())
            for line, names, scope in function.guards:
                if line >= trace.sink_line:
                    continue
                if scope is not None and not (scope[0] <= trace.sink_line <= scope[1]):
                    # A ``continue``/``break`` guard only reaches sinks inside the
                    # loop it leaves. Outside it, the sink is still reachable.
                    continue
                if not read or (names & read):
                    guarded[(function.name, trace.sink_line)] = (
                        f"a containment check at line {line} exits before this "
                        f"sink, so the path cannot escape its root"
                    )
                    break
    return guarded



def _guarding_callee(
    function: FunctionTrace, guarded_callees: set[str]
) -> frozenset[str]:
    """Which guard-dominated callees this function calls."""
    if not guarded_callees:
        return frozenset()
    called = frozenset(function.calls)
    return called & guarded_callees



def _cross_to_dict(trace: CrossFunctionTrace) -> dict[str, Any]:
    """JSON-serialisable view of a cross-function trace."""
    return {
        "trace_id": trace.trace_id,
        "cwe": trace.cwe,
        "category": trace.category,
        "sink": trace.sink,
        "sink_call": trace.sink_call,
        "sink_file": trace.sink_file,
        "sink_line": trace.sink_line,
        "chain": list(trace.chain),
        "entry_file": trace.entry_file,
        "entry_line": trace.entry_line,
        "origins": list(trace.origins),
        "param_indices": list(trace.param_indices),
        "steps": [s.to_dict() for s in trace.steps],
        "kills": list(trace.kills),
        "confidence": round(float(trace.confidence), 4),
    }


class SyrthScanner:
    """Library entry point for scanning files, sources and repositories."""

    def __init__(
        self,
        model_path: str | None = None,
        threshold: float = DEFAULT_THRESHOLD,
        interprocedural: bool = True,
    ):
        """
        Args:
            model_path: Optional path to an XGBoost model bundle. When absent or
                unloadable the scanner runs rules-only, which is a fully
                supported mode: the trace set is produced either way.
            threshold: Confidence below which a finding is moved to
                ``suppressed`` instead of ``findings``.
            interprocedural: Whether to build a call graph. For a single file
                this resolves helpers called only with clean data; it costs one
                extra parse pass over the same file.
        """
        self.threshold = float(threshold)
        self.interprocedural = bool(interprocedural)
        self.extractor = FeatureExtractor()
        self.classifier = None
        self.model_error: str | None = None
        if model_path:
            self._load_model(model_path)

    # ------------------------------------------------------------- model
    def _load_model(self, model_path: str) -> None:
        """Load the optional ML classifier.

        Failure is non-fatal and recorded in :attr:`model_error`. The scanner
        must keep working rules-only rather than refusing to start, because the
        trace set -- the primary output -- does not depend on the model.
        """
        try:
            from .classifier import XGBoostClassifier

            classifier = XGBoostClassifier(model_path=model_path)
        except Exception as exc:  # noqa: BLE001 - degrade, never crash
            self.model_error = f"{type(exc).__name__}: {exc}"
            self.classifier = None
            return
        self.classifier = classifier

    @property
    def has_ml(self) -> bool:
        """True when a fitted ML model is available.

        Defensive by design: a classifier object that does not expose
        ``is_fitted`` is treated as unavailable rather than raising, because the
        scanner must keep producing its trace set regardless of the model.
        """
        classifier = self.classifier
        if classifier is None:
            return False
        probe = getattr(classifier, "is_fitted", None)
        if probe is None:
            return False
        try:
            return bool(probe())
        except Exception:  # noqa: BLE001 - a broken model is not a scan failure
            return False

    @property
    def model_label(self) -> str:
        """``ml``, ``hybrid`` or ``rule``, for the report header."""
        return "ml" if self.has_ml else "rule"

    # ------------------------------------------------------------ scanning
    def parse(self, source: str, filename: str = "<source>") -> FileTrace:
        """Parse ``source`` with the front end matching its extension."""
        suffix = Path(filename).suffix or ".py"
        parser_cls = SUPPORTED_EXTENSIONS.get(suffix)
        if parser_cls is None:
            parser_cls = PythonParser
        return parser_cls().parse(source, filename)

    def scan_source(self, source: str, filename: str = "<source>") -> ScanReport:
        """Scan one source string and return a full report."""
        file_trace = self.parse(source, filename)
        return self._report_from_traces([file_trace])

    def scan_file(self, path: str) -> ScanReport:
        """Scan one file on disk.

        A read failure is recorded on the report rather than raised, so a
        repository scan is not aborted by one unreadable file.
        """
        target = Path(path)
        try:
            source = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report = ScanReport(file=str(target))
            report.errors.append((str(target), f"{type(exc).__name__}: {exc}"))
            return report
        return self.scan_source(source, str(target))

    def scan_paths(self, paths: Iterable[str], interprocedural: bool | None = None) -> ScanReport:
        """Scan several files or directories as one unit.

        When ``interprocedural`` is enabled the whole set is analysed with a
        shared call graph, so a flow that crosses file boundaries is resolved.
        """
        files: list[Path] = []
        for raw in paths:
            candidate = Path(raw)
            if candidate.is_dir():
                files.extend(_walk(candidate))
            elif candidate.is_file():
                files.append(candidate)
        files = sorted(set(files), key=lambda p: str(p))
        return self.scan_files(files, interprocedural=interprocedural)

    def scan_files(self, files: Sequence[Path], interprocedural: bool | None = None) -> ScanReport:
        """Scan a specific list of files with one shared call graph."""
        use_interproc = self.interprocedural if interprocedural is None else interprocedural
        file_traces: list[FileTrace] = []
        report = ScanReport(model=self.model_label)

        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                report.errors.append((str(path), f"{type(exc).__name__}: {exc}"))
                continue
            file_traces.append(self.parse(source, str(path)))
            if file_traces[-1].parse_errors:
                report.parse_errors.append(str(path))

        merged = self._report_from_traces(file_traces, use_interproc=use_interproc)
        merged.errors.extend(report.errors)
        merged.parse_errors = sorted(set(merged.parse_errors))
        return merged

    def scan_source_pair(
        self, before: str, after: str, filename: str = "<source>"
    ) -> Any:
        """Convenience wrapper: scan two revisions and diff them."""
        from .diff import diff_reports

        return diff_reports(self.scan_source(before, filename), self.scan_source(after, filename))

    # ------------------------------------------------------------ internals
    def _report_from_traces(
        self, file_traces: Sequence[FileTrace], use_interproc: bool | None = None
    ) -> ScanReport:
        """Build a report from one or more analysed files.

        Report policy is applied here, once:

        *   A trace whose confidence clears :attr:`threshold` becomes a finding.
        *   A trace below the threshold becomes a suppressed entry, so the
            information is not lost and the reader can see what was withheld.
        *   A function that reaches a sink with no confirmed flow becomes a
            suppressed review item, never a finding.
        """
        run_interproc = self.interprocedural if use_interproc is None else use_interproc
        report = ScanReport(
            file=file_traces[0].path if len(file_traces) == 1 else "",
            mode="dev" if self.has_ml else "rule",
            model=self.model_label,
        )

        for file_trace in file_traces:
            report.files_scanned += 1
            report.functions_scanned += len(file_trace.functions)
            all_traces = file_trace.all_traces()
            report.traces.extend(all_traces)
            if file_trace.parse_errors:
                report.parse_errors.append(file_trace.path)

            guarded = _containment_evidence(file_trace)

            for trace in all_traces:
                finding = self._finding_from_trace(trace, file_trace)
                reason = guarded.get((trace.function, trace.sink_line))
                if reason is not None:
                    # A containment check that dominates the sink is evidence, and
                    # this project's contract is that evidence never deletes. See
                    # docs/risk-model.md: "A suppressed 0.12 risk is an answer.
                    # Silence is not." and "the only things that suppress output
                    # are an explicit suppression file and an inline ignore
                    # comment -- decisions you make, not decisions the analyser
                    # makes on your behalf."
                    #
                    # The earlier version of this code did the opposite: it moved
                    # the finding into ``report.suppressed``, which is the user's
                    # decision channel. That is the exact reporting artefact the
                    # risk model documents as the previous version's failure --
                    # a correct observation of a sink contact made invisible, and
                    # then counted as a false alarm. So the finding stays, with its
                    # likelihood lowered and the reason stated.
                    finding.confidence = min(
                        finding.confidence, CONTAINMENT_GUARD_CONFIDENCE
                    )
                    finding.reasons = (reason,) + tuple(finding.reasons)
                report.findings.append(finding)

            report.findings.extend(self._weak_findings(file_trace))

        if run_interproc and file_traces:
            graph = CallGraph.build(file_traces)
            report.cross_function = graph.resolve_traces()

        report.findings = self._dedupe_and_rank(report.findings)
        return report

    def _weak_findings(self, file_trace: FileTrace) -> list[Finding]:
        """Pattern-level risks for functions that reach a sink without a confirmed flow.

        Under the risk model these are not suppressed. Reaching a sink is not
        proof of a vulnerability, but it *is* the nearest vulnerability class to
        this code, and the reader is better served by seeing "CWE-89 here, low
        likelihood" than by silence. ``detector="pattern"`` and the low
        confidence distinguish them from confirmed flows.
        """
        weak: list[Finding] = []
        for function in file_trace.functions:
            categories = function.sink_categories()
            if not categories:
                continue
            # Which classes already have a confirmed flow? Those are reported at
            # full likelihood by the normal path. Every *other* touched class is
            # still a nearest vulnerability class and is reported as a pattern
            # risk. The previous code skipped the whole function if it had any
            # trace at all, which silently dropped every other class it touched:
            # a function with a confirmed CWE-22 flow and an ``HttpResponseRedirect``
            # reported CWE-22 and nothing for the redirect.
            confirmed_categories = {t.category for t in function.traces}
            # One finding per uncovered category. A single ``classify`` call
            # cannot represent two classes, which is why this is a loop.
            for category in sorted(set(categories) - confirmed_categories):
                result = classify([], [category])
                if not result.predicted:
                    result = classify_sink_categories([category])
                canonical, calls_as_written = _sinks_for_category(
                    function, category, file_trace.bindings)
                weak.append(
                    Finding(
                        function=function.name,
                        lineno=function.lineno,
                        cwe=CATEGORY_CWE.get(category, result.cwe),
                        category=category,
                        confidence=min(result.confidence, CONFIDENCE_PATTERN_RISK),
                        detector="pattern",
                        severity=severity_for(category, result.confidence),
                        origins=(),
                        sink=",".join(canonical),
                        sink_call=",".join(calls_as_written),
                        sink_arg="none",
                        file=file_trace.path,
                        model=self.model_label,
                        reasons=(
                            f"reaches a {category} sink but no external origin "
                            f"was confirmed",
                        ),
                        below_threshold=False,
                        ood=False,
                    )
                )
        return weak

    def _finding_from_trace(self, trace: Trace, file_trace: FileTrace) -> Finding:
        """Build one :class:`Finding` from one trace."""
        ml_confidence: float | None = None
        ood = False
        model = self.model_label
        reasons: tuple[str, ...] = ()

        if self.has_ml:
            ml_confidence, ood, model, reasons = self._apply_ml(trace, file_trace)

        confidence = trace.confidence
        if ml_confidence is not None:
            # The model refines the probability of a flow that the analysis has
            # already confirmed; it can never create or delete one.
            confidence = round(0.5 * trace.confidence + 0.5 * ml_confidence, 4)
            model = "hybrid"

        finding = Finding(
            function=trace.function,
            lineno=trace.sink_line or trace.lineno,
            cwe=trace.cwe,
            category=trace.category,
            confidence=confidence,
            detector=trace.detector,
            severity=severity_for(trace.category, confidence),
            origins=trace.origins,
            sink=trace.sink,
            sink_call=trace.sink_call,
            sink_arg=trace.sink_arg,
            steps=trace.steps,
            kills=trace.kills,
            file=trace.file or file_trace.path,
            trace_id=trace.trace_id,
            model=model,
            reasons=reasons,
            ood=ood,
        )
        if confidence < self.threshold:
            finding.below_threshold = True
        return finding

    def _apply_ml(
        self, trace: Trace, file_trace: FileTrace
    ) -> tuple[float | None, bool, str, tuple[str, ...]]:
        """Score one trace with the ML classifier, if a model is loaded.

        Returns:
            ``(confidence, out_of_distribution, model_label, reasons)``. On any
            failure the ML path is skipped for this trace only: the trace set is
            produced by the analysis and does not depend on the model, so a
            model error must not change what is reported.
        """
        function = file_trace.get_function(trace.function)
        if function is None:
            return None, False, self.model_label, ()
        try:
            vector = self.extractor.extract_function(function, file_trace)
            prediction = self.classifier.predict_single(vector)
        except Exception as exc:  # noqa: BLE001 - a model error is not a scan error
            return None, False, "rule", (
                f"ML scoring unavailable for this function ({type(exc).__name__})",
            )
        cwe = prediction.get("predicted_cwe", "")
        confidence = float(prediction.get("confidence", 0.0))
        reasons: list[str] = [f"ML ranks {cwe} first for this function"]
        if cwe and cwe != trace.cwe:
            # Reported, never silently applied: a disagreement between the model
            # and the confirmed trace is information for the reader.
            reasons.append(
                f"ML suggested {cwe}; the confirmed flow is {trace.cwe}, which wins"
            )
        return confidence, bool(prediction.get("ood", False)), "hybrid", tuple(reasons)

    @staticmethod
    def _dedupe_and_rank(findings: Sequence[Finding]) -> list[Finding]:
        """Drop duplicates and order by severity then confidence.

        Ordering is a total function of the finding's own fields, so report
        output does not depend on discovery order.
        """
        seen: dict[tuple[str, str, str, str, int], Finding] = {}
        for finding in findings:
            # The CWE is part of the identity. Without it a function that calls
            # both os.system and cur.execute on one line collapsed into a single
            # finding, hiding one of the two nearest vulnerability classes.
            key = (
                finding.file,
                finding.function,
                finding.cwe,
                finding.sink,
                finding.lineno,
            )
            existing = seen.get(key)
            if existing is None or finding.confidence > existing.confidence:
                seen[key] = finding
        return sorted(
            seen.values(),
            key=lambda f: (
                -SEVERITY_RANK.get(f.severity, 0),
                -f.confidence,
                f.file,
                f.lineno,
                f.sink,
            ),
        )

    # ---------------------------------------------------------- suppression
    @staticmethod
    def suppress(report: ScanReport, rules: SuppressionSet) -> ScanReport:
        """Apply a suppression set to a report, returning a new report."""
        kept: list[Finding] = []
        suppressed: list[Finding] = list(report.suppressed)
        for finding in report.findings:
            if rules.matches(finding, report.traces):
                suppressed.append(finding)
            else:
                kept.append(finding)
        report.findings = kept
        report.suppressed = suppressed
        return report


SEVERITY_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def severity_for(category: str, confidence: float) -> str:
    """Map a category and confidence onto a severity band.

    The mapping is deterministic and documented so that reports are comparable
    across runs.
    """
    high_risk = {"EXEC", "DESER", "CRED"}
    medium_risk = {"SQL", "XXE", "FILE", "NET"}
    if category in high_risk:
        base = "critical" if confidence >= 0.8 else "high"
    elif category in medium_risk:
        base = "high" if confidence >= 0.8 else "medium"
    else:
        base = "medium" if confidence >= 0.7 else "low"
    if confidence < 0.4:
        return "low"
    return base


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


class SuppressionSet:
    """Suppression rules, loaded from a simple text file.

    Format, one rule per line::

        # comment
        CWE-89                       suppress a class everywhere
        cwe:CWE-22:function:upload   suppress one CWE in one function
        file:legacy/*.py             suppress a whole file
        sink:EXEC_COMMAND            suppress one canonical sink
        trace:9f2c1a0b4d5e6f70       suppress one trace identity
        function:upload:>=90         suppress a function at/above a confidence

    Matching is exact unless a wildcard is present, in which case
    ``fnmatch`` semantics apply. A suppression that matches nothing is reported
    by the CLI so stale rules are visible rather than silently dead.
    """

    def __init__(self, rules: Iterable[tuple[str, dict[str, str]]] | None = None):
        self.rules: list[tuple[str, dict[str, str]]] = list(rules or [])

    @classmethod
    def load(cls, path: str) -> SuppressionSet:
        """Load rules from ``path``.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If a non-comment, non-empty line has no ``:`` separator.
        """
        text = Path(path).read_text(encoding="utf-8")
        rules: list[tuple[str, dict[str, str]]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" not in stripped:
                raise ValueError(f"{path}:{number}: expected 'kind:pattern', got {stripped!r}")
            kind, _, pattern = stripped.partition(":")
            rules.append((kind.strip(), {"pattern": pattern.strip()}))
        return cls(rules)

    def add(self, kind: str, pattern: str) -> None:
        """Append a rule programmatically."""
        self.rules.append((kind, {"pattern": pattern}))

    def matches(self, finding: Finding, traces: Sequence[Trace] = ()) -> bool:
        """True when any rule suppresses ``finding``."""
        from fnmatch import fnmatch

        for kind, options in self.rules:
            pattern = options.get("pattern", "")
            if kind == "cwe" and fnmatch(finding.cwe, pattern):
                return True
            if kind == "sink" and fnmatch(finding.sink, pattern):
                return True
            if kind == "file" and fnmatch(finding.file, pattern):
                return True
            if kind == "trace" and fnmatch(finding.trace_id, pattern):
                return True
            if kind == "function":
                parts = pattern.split(":")
                if parts and fnmatch(finding.function, parts[0]):
                    if len(parts) > 1 and parts[1].startswith(">="):
                        try:
                            threshold = float(parts[1][2:])
                        except ValueError:
                            continue
                        if finding.confidence >= threshold:
                            return True
                    else:
                        return True
            if kind == "category" and fnmatch(finding.category, pattern):
                return True
        return False

    def __len__(self) -> int:
        return len(self.rules)


# ---------------------------------------------------------------------------
# Repository walking
# ---------------------------------------------------------------------------


def _walk(root: Path) -> Iterator[Path]:
    """Yield scannable files under ``root``, pruning noise directories.

    Deterministic: entries are sorted at every level, so two runs produce the
    same file list and therefore the same report ordering.
    """
    for entry in sorted(root.iterdir(), key=lambda p: str(p).lower()):
        if entry.is_dir():
            if entry.name in PRUNED_DIRECTORIES or entry.name.startswith("."):
                continue
            yield from _walk(entry)
        elif entry.is_file() and entry.suffix in SUPPORTED_EXTENSIONS:
            yield entry


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_cli_parser() -> argparse.ArgumentParser:
    """Build the ``syrth`` command-line parser."""
    parser = argparse.ArgumentParser(
        prog="syrth",
        description="SYRTH: alpha-renaming-invariant, fix-verifying static analysis",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--file", help="Scan a single file")
    target.add_argument("--path", action="append", default=[],
                        help="Scan a file or directory (repeatable)")
    target.add_argument("--stdin", action="store_true", help="Read source from stdin")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0")
    parser.add_argument("--traces", action="store_true",
                        help="Emit the raw trace certificates")
    parser.add_argument("--model", default=None, help="Path to an XGBoost model bundle")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help="Confidence below which findings are withheld")
    parser.add_argument("--no-interprocedural", action="store_true",
                        help="Disable cross-function resolution")
    parser.add_argument("--suppress", default=None, help="Path to a suppression file")
    parser.add_argument("--fix", action="store_true",
                        help="Propose a patch for each finding and verify it "
                             "mechanically")
    parser.add_argument("--fix-apply", action="store_true",
                        help="With --fix, print the patched source instead of "
                             "the report")
    parser.add_argument("--patch-command", default=None,
                        help="External command that produces patches; receives "
                             "the source path and writes the rewrite to stdout")
    parser.add_argument("--fail-on", choices=["never", "high", "any"], default="never",
                        help="Exit non-zero when a finding at or above this level exists")
    parser.add_argument("--version", action="version", version=f"syrth {__version__}")
    return parser


def _should_fail(report: ScanReport, level: str) -> bool:
    """Whether the report should produce a non-zero exit status."""
    if level == "never":
        return False
    if level == "any":
        return bool(report.findings)
    return any(SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK["high"]
               for f in report.findings)


def _render_text(report: ScanReport, show_suppressed: bool = True) -> str:
    """Render a human-readable report.

    The output is pure ASCII apart from explicit markers, because the previous
    report used box-drawing characters and could not be printed on a default
    Windows console -- which is exactly why the end-to-end test harness had to
    capture stdout instead of reading it.
    """
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("SYRTH - Scan Your Risk Trace History")
    lines.append(f"target : {report.file or '(repository)'}")
    lines.append(f"model  : {report.model}")
    summary = report.summary()
    lines.append(
        "scanned: {files} file(s), {funcs} function(s), {traces} trace(s)".format(
            files=summary["files_scanned"],
            funcs=summary["functions_scanned"],
            traces=summary["traces"],
        )
    )
    if report.cross_function:
        lines.append(
            f"cross-function flows resolved: {len(report.cross_function)}"
        )
    lines.append("=" * 72)

    if not report.findings:
        lines.append("")
        lines.append("No sink reached anywhere in the target; no risks to report.")
        for path, message in report.errors:
            lines.append(f"[error] {path}: {message}")
        lines.append("")
        return "\n".join(lines)

    for finding in report.findings:
        lines.extend(_render_finding(finding))
        lines.append("-" * 72)

    if report.errors:
        lines.append("")
        lines.append("Errors:")
        for path, message in report.errors:
            lines.append(f"  {path}: {message}")
    lines.append("")
    return "\n".join(lines)


def _render_finding(finding: Finding) -> list[str]:
    """Render one finding as text lines."""
    lines = [
        f"[{finding.severity.upper()}] {finding.cwe} ({finding.category}) "
        f"confidence {finding.confidence:.2f}",
        f"  {finding.file}:{finding.lineno} in {finding.function}()",
        f"  sink: {finding.sink_call} -> {finding.sink} via {finding.sink_arg}",
        f"  origin: {'/'.join(finding.origins) or 'none (sanitiser assertion)'}",
    ]
    for step in finding.steps:
        marker = {"source": ">>", "sink": "<<", "sanitize": "//"}.get(step.kind, "  ")
        detail = f"  {step.detail}" if step.detail else ""
        lines.append(f"  {marker} L{step.line:<5} {step.edge:<16}{detail}")
    if finding.kills:
        lines.append(f"  sanitiser(s) on path: {', '.join(finding.kills)}")
    for reason in finding.reasons:
        lines.append(f"  {reason}")
    return lines


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_cli_parser().parse_args(argv)

    scanner = SyrthScanner(
        model_path=args.model,
        threshold=args.threshold,
        interprocedural=not args.no_interprocedural,
    )
    if scanner.model_error:
        print(f"[warn] ML model unavailable, running rules-only: {scanner.model_error}",
              file=sys.stderr)

    try:
        if args.stdin:
            report = scanner.scan_source(sys.stdin.read(), "<stdin>")
        elif args.file:
            report = scanner.scan_file(args.file)
        else:
            report = scanner.scan_paths(args.path or ["."])
    except ScanError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("[error] interrupted", file=sys.stderr)
        return 130

    if args.suppress:
        try:
            suppressions = SuppressionSet.load(args.suppress)
        except (OSError, ValueError) as exc:
            print(f"[error] cannot load suppressions: {exc}", file=sys.stderr)
            return 2
        SyrthScanner.suppress(report, suppressions)

    if args.fix:
        from .patch import SanitiserBackend, propose_and_verify, render

        try:
            source_text = (
                sys.stdin.read() if args.stdin
                else Path(args.file).read_text(encoding="utf-8", errors="replace")
            )
        except OSError as exc:
            print(f"[error] cannot read the source to patch: {exc}", file=sys.stderr)
            return 2

        backend: Any = SanitiserBackend()
        if args.patch_command:
            try:
                import shlex as shlex_parser

                from .patch import CommandBackend

                backend = CommandBackend(shlex_parser.split(args.patch_command),
                                         name="command")
            except (ValueError, FileNotFoundError) as exc:
                print(f"[error] unusable --patch-command: {exc}", file=sys.stderr)
                return 2

        results, patched = propose_and_verify(
            source_text, report, backend, scanner, apply=True
        )
        if args.fix_apply:
            print(patched)
            return 0
        payload = [result.to_dict() for result in results]
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(render(results))
        return 0

    if args.traces:
        from .trace import traces_to_json

        print(traces_to_json(report.traces))
        return 1 if _should_fail(report, args.fail_on) else 0
    if args.sarif:
        from .sarif import to_sarif

        print(to_sarif(report))
        return 1 if _should_fail(report, args.fail_on) else 0
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(_render_text(report))
    return 1 if _should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
