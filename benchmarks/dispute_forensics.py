"""Discriminate: is the precision figure our bug, or the harness's blind spot?

Two competing explanations for the disagreements:

  E1  SYRTH over-reports -- the finding names a class with no sink behind it.
  E2  The independent scan under-covers -- SYRTH names a sink the harness's
      hand-written table simply does not contain.

These have opposite consequences: E1 means the analyser is wrong, E2 means the
instrument is wrong. The discriminator is *what sink we claim* on each disputed
record, compared against what the harness's own table knows.
"""
from __future__ import annotations

import collections
import pathlib
import sys

sys.path.insert(0, r"D:\Axioms\Syrth")

from benchmarks.risk_metrics import _QUALIFIED_SINKS, _SINK_NAME_TO_CWE, expected_classes
from benchmarks.run_benchmarks import load_records
from syrth.registry import CWE_TO_CATEGORY
from syrth.scan import SyrthScanner

IN_SCOPE = frozenset(CWE_TO_CATEGORY)
DATASET = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "data/corpus.jsonl")
FOCUS = sys.argv[2] if len(sys.argv) > 2 else "CWE-79"

records = load_records(str(DATASET))
scanner = SyrthScanner(threshold=0.5)


def harness_knows(call_name: str, cwe: str) -> bool:
    """Would the independent scan recognise this exact call as this class?"""
    if _QUALIFIED_SINKS.get(call_name) == cwe:
        return True
    base = call_name.rsplit(".", 1)[-1]
    return base in _SINK_NAME_TO_CWE.get(cwe, set())


disputed: list[tuple[str, str, str, str]] = []
agreed: list[tuple[str, str, str]] = []

for record in records:
    want = expected_classes(record.source) & IN_SCOPE
    report = scanner.scan_source(record.source, record.group)
    named: dict[str, set[str]] = {}
    for finding in report.findings:
        named.setdefault(finding.cwe, set()).add(finding.sink_call)
    for cwe, calls in named.items():
        for call in calls:
            if cwe not in want:
                disputed.append((cwe, call, record.group, record.label or '-'))
            elif cwe == FOCUS:
                agreed.append((cwe, call, record.group))

print("=" * 78)
print(f"disputed findings (reported, scan disagrees): {len(disputed)}")
print("=" * 78)
buckets: collections.Counter = collections.Counter()
examples: dict[str, list[str]] = collections.defaultdict(list)

for cwe, call, repo, qualname in disputed:
    if harness_knows(call, cwe):
        key = f"{cwe}: scan knows this sink -> SYRTH likely wrong"
    else:
        key = f"{cwe}: sink outside the scan's table -> instrument gap"
    buckets[key] += 1
    examples[key].append(f"{repo}/{qualname} claims {call}")

for line, count in buckets.most_common():
    print(f"  {count:>4}  {line}")
print()
for line, rows in examples.items():
    print(f"--- {line}")
    for row in rows[:10]:
        print(f"      {row}")
    print()

print("=" * 78)
print(f"agreed findings for {FOCUS}: {len(agreed)}")
print("=" * 78)
for _cwe, call, repo in agreed[:15]:
    print(f"  {repo:<14} {call}")
