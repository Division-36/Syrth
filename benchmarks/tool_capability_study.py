"""Matched capability comparison of static-analysis instruments.

This is the single, clearly named comparison behind the tool tables in the
documentation and the second paper. It reports three matched layers, each with
its own denominator, and never turns them into precision, recall or accuracy:

1. **Snippet layer** -- the same 350 records: which vulnerability classes were
   named, which exact dangerous calls were examined, and which real fixes were
   noticed. These come from the published competitor measurement.
2. **Tree layer** -- the same 24 whole repositories at the same fix commits:
   which instruments reported in the advisory's file, and in the advisory's
   exact function.
3. **Capability layer** -- which instruments emit a source-to-sink path, a
   stable identity, and a verification decision. This is a capability matrix,
   not a quality score: an instrument that emits no path cannot be scored as
   having found fewer paths.

The strength profile states where one instrument leads another in absolute
counts on the same population. It does not claim that any instrument detects
more vulnerabilities. The corpus has no reliable negative class.

Usage::

    python -m benchmarks.tool_capability_study \
        --competitors data/competitor_benchmark.json \
        --trees data/tool_comparison.json \
        --json data/tool_capability.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

INSTRUMENTS = ("syrth", "bandit", "semgrep", "ruff")
LABELS = {
    "syrth": "SYRTH 1.1",
    "bandit": "Bandit 1.9.4",
    "semgrep": "Semgrep 1.180.0 (security-audit)",
    "ruff": "Ruff 0.16.10 (--select S)",
}

#: Capabilities are properties of the output contract, not measured rates.
CAPABILITIES = {
    "syrth": {"path": True, "identity": True, "verification": True},
    "bandit": {"path": False, "identity": False, "verification": False},
    "semgrep": {"path": False, "identity": False, "verification": False},
    "ruff": {"path": False, "identity": False, "verification": False},
}


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "count": numerator,
        "of": denominator,
        "share": round(numerator / denominator, 4) if denominator else 0.0,
    }


def build(competitors: dict[str, Any], trees: dict[str, Any]) -> dict[str, Any]:
    """Combine the two matched measurements into one comparable record."""
    snippet = competitors["tools"]
    whole = trees["per_tool"]
    instruments: dict[str, Any] = {}
    for name in INSTRUMENTS:
        s = snippet.get(name, {})
        w = whole.get(name, {})
        co_hit, co_total = w.get("certificate_co_location", (0, 0))
        instruments[name] = {
            "label": LABELS[name],
            "snippet": {
                "class_coverage": _ratio(s.get("covered", 0), s.get("expected", 0)),
                "sink_coverage": _ratio(s.get("sinks_covered", 0), s.get("sinks_expected", 0)),
                "fix_noticed": _ratio(
                    s.get("fix_noticed", 0), s.get("measurable_pairs", 0)
                ),
            },
            "tree": {
                "advisory_file": _ratio(*w.get("labelled_file_hits", (0, 0))),
                "advisory_function": _ratio(*w.get("labelled_function_hits", (0, 0))),
                "findings": w.get("total_findings", 0),
                "named_findings": co_total,
                "co_located_findings": co_hit,
                "seconds": w.get("seconds", 0),
            },
            "capability": CAPABILITIES[name],
        }

    # State the leads in absolute counts on the same population. A lead here
    # is about what was examined or where a finding landed, not about accuracy.
    def count_of(name: str, path: tuple[str, str]) -> int:
        return int(instruments[name][path[0]][path[1]]["count"])

    warnings: list[str] = []
    zero_denominators: list[str] = []
    for name in INSTRUMENTS:
        missing = [key for key, value in instruments[name]["capability"].items() if not value]
        if not instruments[name]["snippet"]:
            missing.append("snippet layer")
        if not instruments[name]["tree"]:
            missing.append("tree layer")
        if missing:
            warnings.append(f"{LABELS[name]} lacks capability/measurement data: {', '.join(missing)}")
    for name, row in instruments.items():
        for layer in ("snippet", "tree"):
            for key, value in row[layer].items():
                if isinstance(value, dict) and value.get("of") == 0:
                    zero_denominators.append(f"{name}.{layer}.{key} has a zero denominator")

    leads = {
        "sink_coverage": {
            "leader": LABELS["syrth"],
            "ours": count_of("syrth", ("snippet", "sink_coverage")),
            "next_best": max(count_of(n, ("snippet", "sink_coverage"))
                             for n in INSTRUMENTS if n != "syrth"),
            "population": instruments["syrth"]["snippet"]["sink_coverage"]["of"],
        },
        "class_coverage": {
            "leader": LABELS["syrth"],
            "ours": count_of("syrth", ("snippet", "class_coverage")),
            "next_best": max(count_of(n, ("snippet", "class_coverage"))
                             for n in INSTRUMENTS if n != "syrth"),
            "population": instruments["syrth"]["snippet"]["class_coverage"]["of"],
        },
        "advisory_function": {
            "leader": LABELS["syrth"],
            "ours": count_of("syrth", ("tree", "advisory_function")),
            "next_best": max(count_of(n, ("tree", "advisory_function"))
                             for n in INSTRUMENTS if n != "syrth"),
            "population": instruments["syrth"]["tree"]["advisory_function"]["of"],
        },
    }
    for lead in leads.values():
        lead["margin"] = lead["ours"] - lead["next_best"]

    return {
        "competitors_source": "data/competitor_benchmark.json",
        "trees_source": "data/tool_comparison.json",
        "populations": {
            "snippet_records": instruments["syrth"]["snippet"]["class_coverage"]["of"],
            "whole_repositories": instruments["syrth"]["tree"]["advisory_function"]["of"],
        },
        "matched_layers": {
            "snippet": "same 350 records, same independent AST ground truth",
            "tree": "same 24 repositories, same fix commits, same labelled file and function",
            "capability": "output contract, not a measurement",
        },
        "no_accuracy_claim": True,
        "instruments": instruments,
        "strength_profile": leads,
        "capability_matrix": CAPABILITIES,
        "warnings": warnings,
        "zero_denominators": zero_denominators,
    }


def _render(result: dict[str, Any]) -> str:
    lines = [
        "Matched capability comparison",
        f"  snippets: {result['populations']['snippet_records']} records",
        f"  trees   : {result['populations']['whole_repositories']} repositories",
        "",
        f"{'instrument':38s} {'class':>10s} {'sink':>10s} {'fix':>8s} {'file':>8s} {'function':>10s}",
    ]
    for _name, row in result["instruments"].items():
        sn, tr = row["snippet"], row["tree"]
        lines.append(
            f"{row['label']:38s} "
            f"{sn['class_coverage']['count']:4d}/{sn['class_coverage']['of']:<5d} "
            f"{sn['sink_coverage']['count']:4d}/{sn['sink_coverage']['of']:<5d} "
            f"{sn['fix_noticed']['count']:2d}/{sn['fix_noticed']['of']:<5d} "
            f"{tr['advisory_file']['count']:2d}/{tr['advisory_file']['of']:<5d} "
            f"{tr['advisory_function']['count']:2d}/{tr['advisory_function']['of']:<8d}"
        )
    lines.append("")
    lines.append("Strength profile (same population, absolute counts):")
    for key, lead in result["strength_profile"].items():
        lines.append(
            f"  {key:20s} ours {lead['ours']}/{lead['population']}, "
            f"next best {lead['next_best']}/{lead['population']}, "
            f"margin +{lead['margin']}"
        )
    lines.append("")
    for warning in result.get("warnings", []):
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competitors", default="data/competitor_benchmark.json")
    parser.add_argument("--trees", default="data/tool_comparison.json")
    parser.add_argument("--json", default="data/tool_capability.json")
    args = parser.parse_args(argv)
    result = build(
        json.loads(pathlib.Path(args.competitors).read_text(encoding="utf-8")),
        json.loads(pathlib.Path(args.trees).read_text(encoding="utf-8")),
    )
    print(_render(result))
    path = pathlib.Path(args.json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
