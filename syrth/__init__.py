"""
SYRTH: alpha-renaming-invariant, fix-verifying static analysis.
=============================================================

SYRTH parses Python source, proves that untrusted data reaches a dangerous
operation, and emits that proof as a :class:`~syrth.trace.Trace` certificate.
Traces -- not scores -- are the primary output: they are comparable across
revisions, so a patch can be shown to have killed a flow, introduced one, or
left it dangling.

Pipeline::

    source ──► PythonParser ──► FileTrace
                                    │
                                    ├─► FeatureExtractor ──► vector ──► XGBoost (optional)
                                    │
                                    └─► Trace set ──► CallGraph ──► ScanReport ──► SARIF/JSON

Guarantees this package makes
-----------------------------
*   **Rename invariance.** Two programs that differ only by a consistent
    renaming of identifiers produce identical verdicts. Parameter *position* and
    dataflow shape decide, never spelling.
*   **Determinism.** Canonical sink resolution never iterates a hash-ordered
    collection, so results do not depend on ``PYTHONHASHSEED``.
*   **Graceful degradation.** The ML classifier refines the probability of a
    flow the analysis has already confirmed; it can neither create nor delete a
    finding, and a model failure never changes what is reported.

Quick start::

    from syrth import SyrthScanner

    scanner = SyrthScanner()
    report = scanner.scan_source(open("app.py", encoding="utf-8").read(), "app.py")
    for finding in report.findings:
        print(finding.summary_text())
"""

__version__ = "1.0.0"
__author__ = "SYRTH Project"

from .features import FeatureExtractor
from .parser import BaseParser, FileTrace, FunctionTrace, PythonParser, Token
from .scan import (
    DEFAULT_THRESHOLD,
    Finding,
    ScanError,
    ScanReport,
    SuppressionSet,
    SyrthScanner,
)
from .trace import SCHEMA_VERSION, Trace, TraceStep, sort_traces, traces_from_json, traces_to_json

__all__ = [
    "DEFAULT_THRESHOLD",
    "BaseParser",
    "FeatureExtractor",
    "FileTrace",
    "Finding",
    "FunctionTrace",
    "PythonParser",
    "SCHEMA_VERSION",
    "ScanError",
    "ScanReport",
    "SuppressionSet",
    "SyrthScanner",
    "Token",
    "Trace",
    "TraceStep",
    "sort_traces",
    "traces_from_json",
    "traces_to_json",
    "__version__",
]

#: Names exported lazily so that ``import syrth`` does not pay the import cost of
#: xgboost, numpy or shap. Rules-only scanning and the CLI stay fast.
_LAZY_EXPORTS = {
    "XGBoostClassifier",
    "CWE_CLASSES",
    "CallGraph",
    "CrossFunctionTrace",
    "classify",
    "RuleResult",
    "to_sarif",
    "diff_sources",
    "diff_traces",
    "DiffReport",
    "patch_status",
}


def __getattr__(name: str):
    """Resolve a lazily exported public name on first access."""
    if name in _LAZY_EXPORTS:
        if name in ("XGBoostClassifier", "CWE_CLASSES"):
            from .classifier import CWE_CLASSES, XGBoostClassifier

            return {"XGBoostClassifier": XGBoostClassifier, "CWE_CLASSES": CWE_CLASSES}[name]
        if name in ("CallGraph", "CrossFunctionTrace"):
            from .interproc import CallGraph, CrossFunctionTrace

            return {
                "CallGraph": CallGraph,
                "CrossFunctionTrace": CrossFunctionTrace,
            }[name]
        if name in ("classify", "RuleResult"):
            from .classifier.rule import RuleResult, classify

            return {"classify": classify, "RuleResult": RuleResult}[name]
        if name == "to_sarif":
            from .sarif import to_sarif

            return to_sarif
        if name in ("diff_sources", "diff_traces", "DiffReport", "patch_status"):
            from . import diff as _diff

            return {
                "diff_sources": _diff.diff_sources,
                "diff_traces": _diff.diff_traces,
                "DiffReport": _diff.DiffReport,
                "patch_status": _diff.patch_status,
            }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(__all__) | _LAZY_EXPORTS)
