"""Export exactly the cases a human (or an agent) can adjudicate.

Why adjudication cannot be automated here
-----------------------------------------
A mechanical mutant cannot supply a *realistic* known-negative:

* an alpha-rename leaves the code just as vulnerable, so a correct finding still
  reproduces and a false positive still fires -- the mutant measures invariance,
  not precision;
* deleting a sink makes the code safely-trivial, so the finding disappears for a
  reason that carries no information about detection;
* inserting an unused local is safe and changes nothing.

Every mechanical operator therefore lands in one of those two degenerate cases.
Realistic negatives require an authority that understands intent, which is what
adjudication is. This is a limitation of mutation-based security evaluation, not
a shortcut.

Why only the disputed subset
----------------------------
Adjudicating all 350 records is unnecessary. Two subsets carry the information:

1. **Disputed** -- SYRTH reported a class the independent scan could not see.
   These are precisely the cases where the oracle is silent and only a judgement
   can settle whether the finding is real.
2. **Kill-survivors** -- the patch was applied and the class is still reported.
   These test the typed-kill claim directly: is the surviving finding correct
   because the guard does not actually close the path, or is it a false positive?

Everything else already agrees between the two independent detectors and needs no
human to resolve it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from benchmarks.risk_metrics import expected_classes
from benchmarks.run_benchmarks import load_records
from syrth.registry import CWE_TO_CATEGORY
from syrth.scan import SyrthScanner

IN_SCOPE = frozenset(CWE_TO_CATEGORY)


def adjudicateable(records, scanner) -> list[dict]:
    """Cases needing judgement, with everything required to judge them."""
    cases: list[dict] = []

    for index, record in enumerate(records):
        want = expected_classes(record.source) & IN_SCOPE
        report = scanner.scan_source(record.source, record.group)
        named: dict[str, set[str]] = {}
        detectors: dict[str, set[str]] = {}
        for finding in report.findings:
            named.setdefault(finding.cwe, set()).add(finding.sink_call)
            detectors.setdefault(finding.cwe, set()).add(
                "pattern" if finding.detector == "pattern" else "confirmed")

        disputed = sorted(set(named) - want)
        if disputed:
            cases.append({
                "case": f"disputed-{index:04d}",
                "reason": "reported, but the independent scan sees no such sink",
                "group": record.group,
                "label": record.label,
                "kind": getattr(record, "kind", "") or _kind_of(index),
                "tier": getattr(record, "tier", ""),
                "classes_disputed": disputed,
                "classes_scan_agrees": sorted(want),
                "claimed_sinks": {c: sorted(named[c]) for c in disputed},
                "detector": {c: sorted(detectors.get(c, ())) for c in disputed},
                "source": record.source,
            })

    return cases


def _kind_of(index: int) -> str:
    return ""


def survivors(records, scanner) -> list[dict]:
    """Pairs where the class survives the patch, matched on ``pair_id``.

    Matching must be on the pair, not on the advisory. One advisory commonly
    fixes several functions -- keras carries a path-traversal and a
    deserialisation fix on the same commit -- so grouping by advisory and zipping
    the labelled records against the unlabelled ones positionally pairs unrelated
    functions together. That produced 59 cases where 45 were real.
    """
    by_pair: dict[str, list] = {}
    for record in records:
        key = record.pair_id or f"{record.group}:{record.label}"
        by_pair.setdefault(key, []).append(record)

    cases: list[dict] = []
    for pair_id, sides in by_pair.items():
        vulnerable = [r for r in sides if r.label]
        patched = [r for r in sides if not r.label]
        if len(vulnerable) != 1 or len(patched) != 1:
            continue
        vulnerable_record, patched_record = vulnerable[0], patched[0]
        cwe = vulnerable_record.label
        patched_report = scanner.scan_source(
            patched_record.source, patched_record.group)
        still = [f for f in patched_report.findings if f.cwe == cwe]
        if not still:
            continue
        cases.append({
            "case": f"survivor-{pair_id}".replace(":", "_")[:70],
            "pair_id": pair_id,
            "reason": ("the patch is applied and the class is still "
                       "reported; judge whether the guard closes the path"),
            "group": vulnerable_record.group,
            "label": cwe,
            "kind": "patched",
            "tier": getattr(patched_record, "tier", ""),
            "detector": {cwe: sorted(
                "pattern" if f.detector == "pattern" else "confirmed"
                for f in still)},
            "claimed_sinks": {cwe: sorted(f.sink_call for f in still)},
            "source": patched_record.source,
            "vulnerable_source": vulnerable_record.source,
        })
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--out", default="data/adjudication_queue.json")
    parser.add_argument("--include", nargs="*",
                        default=["disputed", "survivor"],
                        choices=["disputed", "survivor"])
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)

    records = load_records(args.dataset)
    scanner = SyrthScanner(threshold=0.5)

    cases: list[dict] = []
    if "disputed" in args.include:
        cases += adjudicateable(records, scanner)
    if "survivor" in args.include:
        cases += survivors(records, scanner)
    if args.limit:
        cases = cases[: args.limit]

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cases, indent=2, ensure_ascii=False),
                   encoding="utf-8")

    sizes = [len(c["source"]) for c in cases]
    print(f"adjudication cases : {len(cases)}")
    print(f"  disputed         : {sum(1 for c in cases if c['case'].startswith('disputed'))}")
    print(f"  kill-survivors   : {sum(1 for c in cases if c['case'].startswith('survivor'))}")
    if sizes:
        print(f"source size: total {sum(sizes) / 1024:.0f} KB, "
              f"median {sorted(sizes)[len(sizes) // 2]} chars, "
              f"max {max(sizes)} chars")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
