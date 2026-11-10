"""Real-commit patch study.

The published kill rate (89/100) is a *kill model* measurement: the category's own
sanitiser is applied mechanically to the sink argument, and the question is whether
the flow disappears. It deliberately does not measure what a developer's patch
does, and the paper says so.

The corpus contains the real patched counterpart of every accepted record -- the
same function as it appears at the fix commit -- so the patch question can be
asked at certificate level:

    scan(vulnerable source), scan(patched source), diff by trace identity, and
    report what happened *to the flow the advisory is about*.

The restriction to the labelled CWE matters: a function that carries unrelated
flows must not be scored fixed because one of them moved, so every aggregate is
over the labelled flow unless noted.

Outcomes per pair, a partition (they sum to ``flow_traced``):

*   ``pairs``: 175 records in vulnerable/patched form; both sides come from real
    fix commits.
*   ``flow_traced``: the vulnerable side produced at least one trace for the
    labelled CWE. Traces, not findings -- a below-threshold flow is still a
    certificate.
*   ``flow_persists``: at least one labelled trace survives unchanged on the
    patched side (identical ``trace_id``). The certificate still holds, so patch
    verification would refuse the fix. Two subcounters are recorded because a
    function can hold several traces of one class:
    ``flow_persists_partial`` (and at least one other labelled trace died) and
    ``flow_persists_new`` (a new labelled flow appeared as well).
*   ``flow_removed``: every labelled trace is gone and none of that class was
    born. The strongest thing the diff can say about a fix.
*   ``flow_traded``: every labelled trace is gone, but a new flow of the same
    class appeared -- the patch replaced one instance with another.
*   ``any_killed``: at least one labelled trace died (subset of ``flow_traced``);
    overlaps ``flow_persists_partial``, so it is not a partition member.
*   ``killed_pairs_all``: pairs where the diff killed *any* trace of any class,
    the unfiltered view.
*   ``regression_any``: any new trace of any class appeared after the fix.

Honest limitation stated up front: the diff sees only the extracted function.
A fix that removes the danger outside this function (in the helper it calls, or
in a caller) happens in ``module-proximity`` records and shows as persistence
here. And a fix that only adds a guard leaves the certificate in place by
design -- guards lower confidence, they never delete it -- which is exactly what
a verifier should demand rather than take the patch on faith.

Usage::

    python -m benchmarks.patch_study --dataset data/corpus.jsonl
"""

from __future__ import annotations

import argparse
import json
import pathlib
from collections import Counter
from typing import Any

from benchmarks.run_benchmarks import load_records
from syrth.diff import diff_reports
from syrth.scan import SyrthScanner


def _pairs(records: Any) -> list[tuple[Any, Any]]:
    """Group records by pair id; the vulnerable side carries the CWE label."""
    grouped: dict[str, list[Any]] = {}
    for record in records:
        grouped.setdefault(record.pair_id, []).append(record)

    pairs: list[tuple[Any, Any]] = []
    for key, sides in grouped.items():
        if len(sides) != 2:
            raise SystemExit(f"pair {key} has {len(sides)} sides, expected 2")
        vulnerable = [s for s in sides if s.label]
        patched = [s for s in sides if not s.label]
        if len(vulnerable) != 1 or len(patched) != 1:
            raise SystemExit(f"pair {key} is not a labelled vulnerable/patched pair")
        pairs.append((vulnerable[0], patched[0]))
    return pairs


def measure(dataset: str, threshold: float = 0.5) -> dict[str, Any]:
    records = load_records(dataset)
    scanner = SyrthScanner(threshold=threshold)

    stats: dict[str, Any] = {
        "pairs": 0,
        "examined": 0,
        "unparseable": 0,
        "flow_traced": 0,
        "flow_persists": 0,
        "flow_persists_partial": 0,
        "flow_persists_new": 0,
        "flow_removed": 0,
        "flow_traded": 0,
        "any_killed": 0,
        "killed_pairs_all": 0,
        "regression_any": 0,
        "introduced_by_cwe": Counter(),
        "by_cwe": {},
        "by_tier": {},
    }
    notes: list[dict[str, Any]] = []

    for vulnerable, patched in _pairs(records):
        stats["pairs"] += 1
        before = scanner.scan_source(vulnerable.source, vulnerable.group)
        after = scanner.scan_source(patched.source, patched.group)
        if before.parse_errors or after.parse_errors:
            stats["unparseable"] += 1
            continue
        stats["examined"] += 1

        diff = diff_reports(before, after, "vulnerable", "patched")
        target_ids = {t.trace_id for t in before.traces if t.cwe == vulnerable.label}
        after_ids = {t.trace_id for t in after.traces}
        same_cwe_introduced = {
            entry.trace.trace_id
            for entry in diff.introduced
            if entry.trace.cwe == vulnerable.label
        }
        killed = target_ids - after_ids
        survived = target_ids & after_ids

        cwe_key = vulnerable.label
        tier_key = vulnerable.tier
        row = stats["by_cwe"].setdefault(cwe_key, Counter())
        tier = stats["by_tier"].setdefault(tier_key, Counter())

        if target_ids:
            stats["flow_traced"] += 1
            row["traced"] += 1
            tier["traced"] += 1
            if survived:
                stats["flow_persists"] += 1
                row["persists"] += 1
                tier["persists"] += 1
                if killed:
                    stats["flow_persists_partial"] += 1
                if same_cwe_introduced:
                    stats["flow_persists_new"] += 1
            elif same_cwe_introduced:
                stats["flow_traded"] += 1
                row["traded"] += 1
                tier["traded"] += 1
            else:
                stats["flow_removed"] += 1
                row["removed"] += 1
                tier["removed"] += 1
            if killed:
                stats["any_killed"] += 1
            else:
                notes.append(
                    {
                        "pair_id": vulnerable.pair_id,
                        "cwe": cwe_key,
                        "tier": tier_key,
                        "target_traces": len(target_ids),
                        "target_alive": len(survived),
                    }
                )

        if diff.killed:
            stats["killed_pairs_all"] += 1
        if diff.introduced:
            stats["regression_any"] += 1
        for entry in diff.introduced:
            stats["introduced_by_cwe"][entry.trace.cwe] += 1

    # Rows for classes that never traced on the vulnerable side but were
    # introduced by some fix elsewhere still deserve a label of zeros.
    for cwe in stats["introduced_by_cwe"]:
        stats["by_cwe"].setdefault(cwe, Counter())

    result: dict[str, Any] = {
        "dataset": dataset,
        "threshold": threshold,
        **{key: stats[key] for key in (
            "pairs", "examined", "unparseable", "flow_traced", "flow_persists",
            "flow_persists_partial", "flow_persists_new", "flow_removed",
            "flow_traded", "any_killed", "killed_pairs_all", "regression_any",
        )},
        "introduced_by_cwe": dict(stats["introduced_by_cwe"]),
        "by_cwe": {
            cwe: dict(row)
            for cwe, row in sorted(stats["by_cwe"].items())
        },
        "by_tier": {
            tier: dict(row)
            for tier, row in sorted(stats["by_tier"].items())
        },
        "unnoticed": len(notes),
        "notes": notes,
    }
    return result


def _render(result: dict[str, Any]) -> str:
    examined = result["examined"]
    traced = result["flow_traced"]
    lines = [
        f"pairs in the corpus                         : {result['pairs']}",
        f"both sides parse                            : {examined}/{result['pairs']}",
        f"labelled flow traced on the vulnerable side : {traced}/{examined}",
        f"  labelled certificate persists             : "
        f"{result['flow_persists']}/{traced}",
        f"    of which lost part of the flow          : "
        f"{result['flow_persists_partial']}/{traced}",
        f"    of which gained a new labelled flow     : "
        f"{result['flow_persists_new']}/{traced}",
        f"  labelled flow fully removed               : "
        f"{result['flow_removed']}/{traced}",
        f"  labelled flow traded for a new one        : "
        f"{result['flow_traded']}/{traced}",
        f"pairs where a labelled trace was killed     : "
        f"{result['any_killed']}/{traced}",
        f"pairs where any trace of any class was kld  : "
        f"{result['killed_pairs_all']}/{examined}",
        f"pairs where the fix introduced any flow     : "
        f"{result['regression_any']}/{examined}",
        "",
        "introduced flows by class: "
        + ", ".join(
            f"{cwe}={count}"
            for cwe, count in sorted(result["introduced_by_cwe"].items())
        ),
        "",
        "per class (traced / persists / removed / traded):",
    ]
    for cwe, row in result["by_cwe"].items():
        lines.append(
            f"  {cwe:<10} {row.get('traced', 0):>3}  {row.get('persists', 0):>3}  "
            f"{row.get('removed', 0):>3}  {row.get('traded', 0):>3}"
        )
    lines.append("per evidence tier (traced / persists / removed / traded):")
    for tier, row in result["by_tier"].items():
        lines.append(
            f"  {tier:<18} {row.get('traced', 0):>3}  {row.get('persists', 0):>3}  "
            f"{row.get('removed', 0):>3}  {row.get('traded', 0):>3}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Real-commit patch study.")
    parser.add_argument("--dataset", required=True, help="JSONL of records")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--json", default=None, help="write the results here")
    args = parser.parse_args(argv)

    result = measure(args.dataset, args.threshold)
    print(_render(result))

    if args.json:
        path = pathlib.Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
