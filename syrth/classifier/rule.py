"""
SYRTH Rule Classifier
=====================
Deterministic, zero-dependency classifier over the analysis output.

Design constraints
------------------
1.  **Shared label space.** Predictions are emitted as CWE identifiers derived
    from :data:`syrth.registry.CATEGORY_CWE`, the same table the ML classifier
    uses. The previous release had a five-class rule path and a fifteen-class ML
    path, so a single report could contain labels from two disjoint label spaces.
2.  **Calibrated confidence.** A rule classifier has no probability model, so
    rather than returning a vote share -- which reached ``1.0`` on a single weak
    signal and made any reporting threshold meaningless -- it returns a
    confidence derived from the *kind* of evidence, and declines to produce one
    at all when the evidence is not a confirmed flow.
3.  **Never overrides confirmed evidence.** The taint traces are ground truth
    within this tool: if a source-to-sink flow was confirmed, the rule path
    reports that flow's category. The rule path only has an opinion when no flow
    was confirmed.

Evidence ladder
---------------
=================  =========================================  ==========
Evidence            Meaning                                     Confidence
=================  =========================================  ==========
confirmed flow      A source-to-sink trace was produced          0.90
amplifier           A sanitiser assertion creates a sink         0.60
unique category     Exactly one sink category reached           0.40
ambiguous           Several sink categories reached              0.25
none               No security-relevant signal                  0.00
=================  =========================================  ==========
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ..registry import CATEGORIES, CATEGORY_CWE
from ..trace import DETECTOR_AMPLIFIER, Trace

#: Confidence assigned to each rung of the evidence ladder.
CONFIDENCE_FLOW = 0.90
CONFIDENCE_AMPLIFIER = 0.60
CONFIDENCE_UNIQUE_CATEGORY = 0.40
CONFIDENCE_AMBIGUOUS = 0.25
CONFIDENCE_NONE = 0.0

#: Confidence below which a prediction is considered unreliable and the caller
#: should abstain rather than report. Calibrated against the evidence ladder
#: above: only a confirmed flow or an amplifier clears it.
DEFAULT_OOD_THRESHOLD = 0.35

#: Severity ordering used when ranking findings, highest first.
SEVERITY_ORDER: tuple[str, ...] = (
    "EXEC", "DESER", "CRED", "SQL", "XXE", "FILE", "NET", "UPLOAD", "CRYPTO",
    "XSS", "REDIRECT",
)


@dataclass
class RuleResult:
    """Outcome of the rule classifier.

    Attributes:
        cwe: Predicted CWE identifier, or ``""`` when nothing was predicted.
        category: Predicted sink category, or ``""``.
        confidence: Confidence derived from the evidence ladder.
        evidence: Which rung of the ladder produced the prediction.
        reasons: Human-readable evidence lines.
        trace_ids: Identities of the traces that drove the prediction.
    """

    cwe: str
    category: str
    confidence: float
    evidence: str
    reasons: list[str] = field(default_factory=list)
    trace_ids: list[str] = field(default_factory=list)

    @property
    def predicted(self) -> bool:
        """True when a label was produced."""
        return bool(self.cwe)

    def to_dict(self) -> dict[str, object]:
        """Plain-dict view for reports."""
        return {
            "cwe": self.cwe,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reasons": list(self.reasons),
            "trace_ids": list(self.trace_ids),
            "fallback": True,
        }


def rank_key(category: str) -> tuple[int, str]:
    """Sort key ordering categories by severity, then alphabetically.

    Deterministic total order, so report output does not depend on dictionary
    iteration order.
    """
    try:
        return (SEVERITY_ORDER.index(category), category)
    except ValueError:
        return (len(SEVERITY_ORDER), category)


def classify_traces(traces: Sequence[Trace]) -> RuleResult:
    """Classify from confirmed traces alone.

    Args:
        traces: Traces produced by the analysis for one function or file.

    Returns:
        A :class:`RuleResult`. When at least one confirmed flow exists the
        highest-severity confirmed category wins, because a function that both
        concatenates user input into a shell command *and* into a query is
        reported as the more severe of the two.
    """
    confirmed = [t for t in traces if t.origins and t.detector != DETECTOR_AMPLIFIER]
    amplifiers = [t for t in traces if t.detector == DETECTOR_AMPLIFIER]

    if confirmed:
        best = min(confirmed, key=lambda t: (rank_key(t.category), t.sink_line, t.trace_id))
        reasons = [
            f"confirmed {best.category} flow from {'/'.join(best.origins)} "
            f"into {best.sink} ({best.sink_arg})"
        ]
        if len(confirmed) > 1:
            others = sorted({t.category for t in confirmed} - {best.category}, key=rank_key)
            if others:
                reasons.append(f"additional categories present: {', '.join(others)}")
        return RuleResult(
            cwe=best.cwe,
            category=best.category,
            confidence=CONFIDENCE_FLOW,
            evidence="confirmed-flow",
            reasons=reasons,
            trace_ids=sorted(t.trace_id for t in confirmed),
        )

    if amplifiers:
        best = min(amplifiers, key=lambda t: (t.sink_line, t.trace_id))
        reasons = [f"sanitiser assertion {best.sink_call} creates an injection sink"]
        if best.origins:
            reasons.append(
                "untrusted data is present at the assertion: " + "/".join(best.origins)
            )
        return RuleResult(
            cwe=best.cwe,
            category=best.category,
            confidence=CONFIDENCE_AMPLIFIER,
            evidence="amplifier",
            reasons=reasons,
            trace_ids=sorted(t.trace_id for t in amplifiers),
        )

    return RuleResult(
        cwe="",
        category="",
        confidence=CONFIDENCE_NONE,
        evidence="none",
        reasons=["no source-to-sink flow and no sanitiser assertion"],
    )


def classify_sink_categories(categories: Sequence[str]) -> RuleResult:
    """Classify from sink categories alone, when no flow was confirmed.

    A function that reaches a sink but whose taint was not confirmed still
    carries some signal; it is reported at a confidence low enough that callers
    should treat it as a review item rather than a finding.
    """
    unique = sorted(set(categories), key=rank_key)
    if not unique:
        return RuleResult(
            cwe="", category="", confidence=CONFIDENCE_NONE, evidence="none",
            reasons=["no sink reached"],
        )
    best = unique[0]
    if len(unique) == 1:
        return RuleResult(
            cwe=CATEGORY_CWE[best],
            category=best,
            confidence=CONFIDENCE_UNIQUE_CATEGORY,
            evidence="unique-category",
            reasons=[f"reaches a {best} sink but no external origin was confirmed"],
        )
    return RuleResult(
        cwe="",
        category="",
        confidence=CONFIDENCE_AMBIGUOUS,
        evidence="ambiguous",
        reasons=[f"reaches several sink categories: {', '.join(unique)}"],
    )


def classify(
    traces: Sequence[Trace], sink_categories: Sequence[str] = ()
) -> RuleResult:
    """Full rule path: confirmed evidence first, sink shape second.

    Args:
        traces: Traces produced by the analysis.
        sink_categories: Categories of every sink the function reaches,
            including those with no confirmed flow.

    Returns:
        A :class:`RuleResult` whose ``evidence`` field records which rung decided
        the outcome.
    """
    result = classify_traces(traces)
    if result.predicted:
        return result
    shape = classify_sink_categories(sink_categories)
    if shape.predicted or shape.confidence > result.confidence:
        return shape
    return result


def is_out_of_distribution(result: RuleResult, threshold: float = DEFAULT_OOD_THRESHOLD) -> bool:
    """True when the result is too weak to report.

    This is a *different* question from "the classifier was unsure": the rule
    path has no probability model at all, so out-of-distribution here means the
    evidence never reached the reporting rung.
    """
    return not result.predicted or result.confidence < threshold


def all_categories() -> tuple[str, ...]:
    """The closed category set, in severity order."""
    return tuple(sorted(CATEGORIES, key=rank_key))


__all__ = [
    "CONFIDENCE_AMBIGUOUS",
    "CONFIDENCE_AMPLIFIER",
    "CONFIDENCE_FLOW",
    "CONFIDENCE_NONE",
    "CONFIDENCE_UNIQUE_CATEGORY",
    "DEFAULT_OOD_THRESHOLD",
    "RuleResult",
    "SEVERITY_ORDER",
    "all_categories",
    "classify",
    "classify_sink_categories",
    "classify_traces",
    "is_out_of_distribution",
    "rank_key",
]
