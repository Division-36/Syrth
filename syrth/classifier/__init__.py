"""
SYRTH Classifier
================
Optional XGBoost classifier plus the deterministic rule path that runs when no
model is available.

The rule path is not a weaker copy of the model: it reads the *confirmed traces*
produced by the analysis and classifies the category of a flow that has already
been proven. The model, when present, only refines the probability of that flow.
Both emit CWE identifiers from the same table
(:data:`syrth.registry.CATEGORY_CWE`), so a single report never mixes label
spaces.

``XGBoostClassifier`` and ``CWE_CLASSES`` load lazily so that rules-only usage
and the CLI do not pay the ~2 s import cost of xgboost.
"""

from .rule import (
    CONFIDENCE_AMBIGUOUS,
    CONFIDENCE_AMPLIFIER,
    CONFIDENCE_FLOW,
    DEFAULT_OOD_THRESHOLD,
    RuleResult,
    all_categories,
    classify,
    classify_sink_categories,
    classify_traces,
    is_out_of_distribution,
    rank_key,
)

__all__ = [
    "CWE_CLASSES",
    "CWE_TO_INDEX",
    "CONFIDENCE_AMBIGUOUS",
    "CONFIDENCE_AMPLIFIER",
    "CONFIDENCE_FLOW",
    "DEFAULT_OOD_THRESHOLD",
    "MODEL_CONFIG",
    "RuleResult",
    "XGBoostClassifier",
    "all_categories",
    "classify",
    "classify_sink_categories",
    "classify_traces",
    "is_out_of_distribution",
    "rank_key",
]

_LAZY = ("XGBoostClassifier", "CWE_CLASSES", "CWE_TO_INDEX", "MODEL_CONFIG")


def __getattr__(name: str):
    """Resolve the xgboost-backed names on first access."""
    if name in _LAZY:
        from . import xgboost as _xgb

        return {
            "XGBoostClassifier": _xgb.XGBoostClassifier,
            "CWE_CLASSES": _xgb.CWE_CLASSES,
            "CWE_TO_INDEX": _xgb.CWE_TO_INDEX,
            "MODEL_CONFIG": _xgb.MODEL_CONFIG,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
