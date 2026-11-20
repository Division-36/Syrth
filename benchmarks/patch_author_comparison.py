"""Direct comparison: model-authored patches vs the real developer patches.

The patch-verification study judged 57 model answers with a contract. This module
judges the real upstream patch of the same 57 pairs with the *same* contract,
so the two arms are directly comparable: same population, same analyser, same
conditions. It is a descriptive comparison, not a new experiment; no
hypothesis is tested and no quality claim is made.

Usage::

    python -m benchmarks.patch_author_comparison \
        --dataset data/corpus.jsonl \
        --responses data/patch_responses.jsonl \
        --json data/patch_author_comparison.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

from benchmarks.patch_verification import (
    MODEL_IDENTIFIER,
    MODEL_PROVIDER,
    _all_trace_ids,
    _metadata,
    _outcome,
    _pairs,
    _traces,
    strip_fences,
    wilson,
)
from benchmarks.run_benchmarks import load_records
from syrth.scan import SyrthScanner


def judge(
    source: str, vulnerable: Any, sink_call: str, scanner: SyrthScanner
) -> dict[str, Any]:
    """Apply the certificate contract to one candidate source."""
    before = scanner.scan_source(vulnerable.source, vulnerable.group)
    after = scanner.scan_source(source, vulnerable.group)
    before_ids = _traces(before, vulnerable.label)
    after_ids = _traces(after, vulnerable.label)
    before_all = _all_trace_ids(before)
    after_all = _all_trace_ids(after)
    new_label = after_ids - before_ids
    new_any = after_all - before_all
    flow_gone = bool(before_ids) and not after_ids
    changed = source != vulnerable.source
    sink = sink_call
    row = {
        "parsed": not after.parse_errors,
        "flow_gone": flow_gone,
        "flow_replaced": bool(new_label),
        "new_flow": bool(new_any),
        "sink_call_present": bool(sink) and sink in source,
        "changed": changed,
        "before_traces": len(before_ids),
        "after_traces": len(after_ids),
    }
    row["guard_only"] = bool(
        (not flow_gone) and row["sink_call_present"] and changed
    )
    row["outcome"] = _outcome(row)
    return row


def _metadata_source_sink(vulnerable: Any) -> str:
    """The sink call the corpus associates with this record, if any."""
    return getattr(vulnerable, "sink_call", "") or ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare model-authored patches with the real developer patches."
    )
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--responses", default="data/patch_responses.jsonl")
    parser.add_argument("--json", default="data/patch_author_comparison.json")
    args = parser.parse_args(argv)

    if not pathlib.Path(args.responses).exists():
        raise SystemExit(
            f"no recorded responses at {args.responses}: the generator must "
            "record its answers before the comparison is measured"
        )
    records = load_records(args.dataset)
    meta = _metadata(args.dataset)
    by_pair = {v.pair_id: (v, p) for v, p in _pairs(records)}
    scanner = SyrthScanner(threshold=0.5)

    answers: dict[str, str] = {}
    with open(args.responses, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            answers[row["pair_id"]] = strip_fences(row.get("response", ""))

    arms: dict[str, list[dict[str, Any]]] = {"machine": [], "developer": []}
    for pair_id in sorted(answers):
        vulnerable, patched = by_pair[pair_id]
        sink = meta.get(pair_id, {}).get("sink_call", "")
        machine = judge(answers[pair_id], vulnerable, sink, scanner)
        developer = judge(patched.source, vulnerable, sink, scanner)
        arms["machine"].append(machine)
        arms["developer"].append(developer)

    summary: dict[str, Any] = {}
    for name, rows in arms.items():
        total = len(rows)
        counts = {key: sum(1 for row in rows if row[key]) for key in
                  ("parsed", "flow_gone", "guard_only", "flow_replaced", "new_flow")}
        summary[name] = {
            "attempted": total,
            **counts,
            "rates": {
                key: {"count": counts[key], "of": total,
                      "ci95": [round(v, 4) for v in wilson(counts[key], total)]}
                for key in ("flow_gone", "guard_only", "new_flow")
            },
            "outcomes": {
                outcome: sum(1 for row in rows if row["outcome"] == outcome)
                for outcome in sorted({row["outcome"] for row in rows})
            },
        }

    result = {
        "dataset": args.dataset,
        "responses": args.responses,
        "population": len(by_pair),
        "compared": len(arms["machine"]),
        "contract": {
            "same_population": True,
            "same_analyser": True,
            "same_conditions": True,
            "descriptive_not_hypothesis_test": True,
        },
        "generator": {
            "model": MODEL_IDENTIFIER,
            "provider": MODEL_PROVIDER,
            "source": "recorded responses",
        },
        "arms": summary,
    }
    path = pathlib.Path(args.json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"pairs compared: {result['compared']}")
    for name, row in summary.items():
        print(f"--- {name}")
        print(f"  parsed                 : {row['parsed']}/{row['attempted']}")
        print(f"  flow gone              : {row['flow_gone']}/{row['attempted']}")
        print(f"  guard-only             : {row['guard_only']}/{row['attempted']}")
        print(f"  flow replaced          : {row['flow_replaced']}/{row['attempted']}")
        print(f"  new flow               : {row['new_flow']}/{row['attempted']}")
        print(f"  outcomes               : {row['outcomes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
