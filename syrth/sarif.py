"""
SYRTH SARIF Output
==================
Emits SARIF 2.1.0 for a :class:`~syrth.scan.ScanReport`, so findings flow into
GitHub code scanning, Azure DevOps and any other SARIF consumer without a
custom integration.

What is mapped
--------------
*   Each confirmed source-to-sink flow becomes one ``runAutomationDetails``
    result with a partial-fingerprints entry keyed on the trace identity. The
    fingerprint is what lets a consumer track a finding across revisions, which
    is the property that makes ``diff`` useful downstream.
*   Traces are attached as a ``threadFlows`` location, so a consumer can render
    the source-to-sink path rather than a single line.
*   Withheld findings are emitted at ``note`` level so they stay visible without
    failing a scan.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .scan import Finding, ScanReport
from .trace import SCHEMA_VERSION

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "SYRTH"
TOOL_URI = "https://github.com/Division-36/Syrth"

#: CWE to SARIF ``security-severity``. Scores are the CVSS-style estimates SYRTH
#: publishes for each class; they are a coarse ordering aid for consumers, not a
#: CVSS computation.
SECURITY_SEVERITY: dict[str, str] = {
    "CWE-94": "9.8",
    "CWE-502": "9.8",
    "CWE-798": "9.1",
    "CWE-89": "9.1",
    "CWE-611": "8.2",
    "CWE-22": "7.5",
    "CWE-918": "7.5",
    "CWE-434": "7.5",
    "CWE-327": "7.4",
    "CWE-79": "6.1",
    "CWE-601": "6.1",
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _region(finding: Finding) -> dict[str, int]:
    """Build a SARIF region for the sink call."""
    return {"startLine": max(1, int(finding.lineno or 1))}


def _thread_flow(finding: Finding) -> dict[str, Any]:
    """Build a SARIF thread flow from a trace's propagation steps."""
    locations: list[dict[str, Any]] = []
    for step in finding.steps:
        locations.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file or "unknown"},
                        "region": {"startLine": max(1, int(step.line or 1))},
                    },
                    "message": {"text": f"{step.edge}: {step.detail}"},
                }
            }
        )
    return {"locations": locations}


def _result(finding: Finding, level: str) -> dict[str, Any]:
    """Build one SARIF result."""
    result: dict[str, Any] = {
        "ruleId": finding.cwe,
        "level": level,
        "message": {"text": finding.summary_text()},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file or "unknown"},
                    "region": _region(finding),
                },
                "logicalLocations": [
                    {"name": finding.function, "kind": "function"}
                ],
            }
        ],
        "partialFingerprints": {"syrthTraceId/v1": finding.trace_id},
        "properties": {
            "category": finding.category,
            "confidence": round(float(finding.confidence), 4),
            "detector": finding.detector,
            "origins": list(finding.origins),
            "sink": finding.sink,
            "sinkArg": finding.sink_arg,
            "sanitisers": list(finding.kills),
            "model": finding.model,
        },
    }
    if finding.steps:
        result["codeFlows"] = [_thread_flow(finding)]
    if finding.cwe in SECURITY_SEVERITY:
        result["properties"]["security-severity"] = SECURITY_SEVERITY[finding.cwe]
    return result


def _rules(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """Build the ``rules`` array, one rule per CWE actually observed."""
    observed: dict[str, list[Finding]] = {}
    for finding in findings:
        observed.setdefault(finding.cwe, []).append(finding)
    rules: list[dict[str, Any]] = []
    for cwe in sorted(observed):
        group = observed[cwe]
        rules.append(
            {
                "id": cwe,
                "name": cwe.replace("CWE-", "Cwe"),
                "shortDescription": {"text": group[0].category},
                "fullDescription": {
                    "text": f"Untrusted data reaches a {group[0].category} sink "
                            f"({group[0].sink})."
                },
                "help": {
                    "text": _help_for(group[0].category),
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(group[0].severity, "warning")
                },
                "properties": {
                    "tags": ["security", "static-analysis", "syrth", group[0].category]
                },
            }
        )
    return rules


_HELP = {
    "SQL": "Use parameterised queries. Never concatenate untrusted input into a statement.",
    "XSS": "Encode output for its context. Do not assert that a value is markup-safe.",
    "FILE": "Constrain the path to an allow-listed root and strip directory components.",
    "EXEC": "Avoid passing untrusted input to a command. Use an argument allow-list.",
    "NET": "Validate the destination host against an allow-list before requesting it.",
    "REDIRECT": "Restrict redirect targets to relative paths or an allow-listed host set.",
    "DESER": "Deserialise only data formats that cannot construct objects.",
    "CRYPTO": "Use a modern, purpose-built primitive instead of a general hash or PRNG.",
    "CRED": "Load credentials from a secret store rather than embedding them.",
    "UPLOAD": "Validate upload content and store files outside the web root.",
    "XXE": "Use a hardened XML parser that disables external entity resolution.",
}


def _help_for(category: str) -> str:
    """Category-specific remediation text."""
    return _HELP.get(category, "Review this data flow and validate the input.")


def to_sarif(report: ScanReport) -> str:
    """Render ``report`` as a SARIF 2.1.0 JSON document.

    Args:
        report: The scan report to serialise.

    Returns:
        A JSON document string.
    """
    findings: list[Finding] = list(report.findings)
    all_findings = findings + list(report.suppressed)

    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": _version(),
                        "informationUri": TOOL_URI,
                        "rules": _rules(all_findings),
                    }
                },
                "automationDetails": {
                    "id": "syrth/analysis/" + str(SCHEMA_VERSION),
                },
                "results": [
                    _result(finding, _SARIF_LEVEL.get(finding.severity, "warning"))
                    for finding in findings
                ]
                + [
                    _result(finding, "note")
                    for finding in report.suppressed
                ],
                "invocations": [
                    {
                        "executionSuccessful": not bool(report.errors),
                        "toolExecutionNotifications": [
                            {
                                "level": "error",
                                "message": {"text": f"{path}: {message}"},
                            }
                            for path, message in report.errors
                        ],
                    }
                ],
                "properties": {"summary": report.summary()},
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def _version() -> str:
    """Package version, read lazily to avoid an import cycle."""
    from .scan import __version__

    return __version__


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "SECURITY_SEVERITY", "to_sarif"]
