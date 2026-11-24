"""Drop pairs whose patched body is identical to the vulnerable body.

The competitor harness refuses such pairs: its mitigation column compares the
same code with itself. v1 has none, but 19 expansion pairs change only module
level code, so the v1.1 comparison runs on the 700 records of the remaining
350 pairs.

Usage::

    python tools/filter_comparable.py --dataset data/corpus-v1.1.jsonl \
        --out data/corpus-v1.1-compare.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def body(source: str) -> str:
    lines = source.split("\n")
    for index, line in enumerate(lines):
        if re.match(r"^\s*(async\s+)?def\s", line):
            return "\n".join(lines[index:])
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", default="data/corpus-v1.1.jsonl")
    parser.add_argument("--out", default="data/corpus-v1.1-compare.jsonl")
    args = parser.parse_args(argv)

    rows = [json.loads(line) for line in Path(args.dataset).read_text(
        encoding="utf-8").splitlines() if line.strip()]
    sides: dict[str, dict[str, dict]] = {}
    for row in rows:
        sides.setdefault(row["pair_id"], {})[row["kind"]] = row
    excluded = {
        pid for pid, pair in sides.items()
        if pair.get("vulnerable") and pair.get("patched")
        and body(pair["vulnerable"]["source"]) == body(pair["patched"]["source"])
    }
    kept = [row for row in rows if row["pair_id"] not in excluded]
    Path(args.out).write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in kept),
        encoding="utf-8",
    )
    print(f"excluded {len(excluded)} pairs; kept {len(kept)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
