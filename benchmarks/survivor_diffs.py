"""Print the added guard lines per kill-survivor, deduplicated by shape."""
from __future__ import annotations

import collections
import difflib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

QUEUE = pathlib.Path(r"D:\Axioms\Syrth\data\adjudication_queue.json")
cases = [c for c in json.loads(QUEUE.read_text(encoding="utf-8"))
         if c["case"].startswith("survivor")]


def body_of(source: str) -> str:
    lines = source.split("\n")
    for index, line in enumerate(lines):
        if re.match(r"^\s*(async\s+)?def\s", line):
            return "\n".join(lines[index:])
    return source


def added(case) -> list[str]:
    diff = difflib.unified_diff(
        body_of(case.get("vulnerable_source", "")).split("\n"),
        body_of(case["source"]).split("\n"),
        lineterm="", n=0,
    )
    return [line[1:].rstrip() for line in diff
            if line.startswith("+") and not line.startswith("+++")
            and line[1:].strip()]


groups: dict[str, list[dict]] = collections.defaultdict(list)
for case in cases:
    key = "\n".join(added(case))
    groups[key].append(case)

print("=" * 82)
print(f"{len(groups)} distinct guard diffs across {len(cases)} survivors")
print("=" * 82)
for lines, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    first = members[0]
    sinks = sorted({s for m in members for v in m["claimed_sinks"].values() for s in v})
    print(f"\n### {len(members)} case(s)  class={first['label']}  "
          f"tier={first['tier']}  detector={sorted({d for m in members for v in m['detector'].values() for d in v})}")
    print(f"    sinks claimed: {', '.join(sinks[:6])}")
    print(f"    cases: {[m['case'][:52] for m in members][:3]}")
    print("    --- added lines ---")
    for line in lines.split("\n")[:14]:
        print(f"      + {line.strip()[:100]}")
    if len(lines.split("\n")) > 14:
        print(f"      ... ({len(lines.split(chr(10)))} added lines total)")
