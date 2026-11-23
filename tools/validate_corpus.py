"""Validate a corpus file before any measurement reads it.

A corpus is only usable if every pair is one vulnerable and one patched record of
the same function at the same commit, if the labels are on the correct side, and
if every ``source`` is Python that parses.  Each of those has silently broken a
run before: a merge that grouped on the patched side's empty ``cwe`` produced 720
single-sided pairs, and the v1 corpus carried three pairs that were the same
function reached through two fix commits.

The validator reports counts rather than a verdict, so a manifest can quote it.
It exits non-zero when any check fails.

Usage::

    python tools/validate_corpus.py --dataset data/corpus-v1.1.jsonl
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import warnings
from collections import Counter
from pathlib import Path

REQUIRED = (
    "advisory_id", "commit", "cwe", "evidence", "file", "function", "group",
    "kind", "label", "module_sink", "origin_source", "pair_id", "qualname",
    "repo", "sink_call", "source",
)
HEX40 = re.compile(r"[0-9a-f]{40}")


def load(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def body_fingerprint(record: dict) -> str:
    """Hash the extracted function, as the merger does for content dedup."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            tree = ast.parse(record["source"])
        except SyntaxError:
            # The caller records unparseable_source and continues. Hashing the
            # raw text keeps the fingerprint total so a broken corpus still
            # produces its validation report instead of a traceback.
            return hashlib.sha256(record["source"].encode("utf-8")).hexdigest()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == record["function"]:
            return hashlib.sha256(
                ast.dump(node, include_attributes=False).encode("utf-8")
            ).hexdigest()
    return hashlib.sha256(record["source"].encode("utf-8")).hexdigest()


def validate(dataset: Path) -> dict:
    rows = load(dataset)
    failures: list[dict] = []
    counts = Counter()

    def fail(check: str, detail: dict) -> None:
        counts[check] += 1
        if len(failures) < 50:
            failures.append({"check": check, **detail})

    sides: dict[str, dict[str, dict]] = {}
    order: list[str] = []
    content_seen: dict[tuple, str] = {}

    for index, record in enumerate(rows):
        missing = [key for key in REQUIRED if key not in record]
        if missing:
            fail("missing_field", {"line": index + 1, "fields": missing})
            continue
        if record["kind"] not in ("vulnerable", "patched"):
            fail("bad_kind", {"line": index + 1, "kind": record["kind"]})
            continue
        if not HEX40.fullmatch(record["commit"]):
            fail("bad_commit", {"line": index + 1, "commit": record["commit"]})
        if not re.fullmatch(r"CWE-\d+", record["cwe"] or ""):
            if record["kind"] == "vulnerable" or record["cwe"]:
                fail("bad_cwe", {"line": index + 1, "cwe": record["cwe"]})

        pair_id = record["pair_id"]
        if pair_id not in sides:
            sides[pair_id] = {}
            order.append(pair_id)
        if record["kind"] in sides[pair_id]:
            fail("duplicate_side", {"line": index + 1, "pair_id": pair_id,
                                    "kind": record["kind"]})
            continue
        sides[pair_id][record["kind"]] = record

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                ast.parse(record["source"])
        except SyntaxError as error:
            fail("unparseable_source", {"line": index + 1, "pair_id": pair_id,
                                        "error": str(error)})

    pairs = 0
    for pair_id in order:
        pair = sides[pair_id]
        if set(pair) != {"vulnerable", "patched"}:
            fail("incomplete_pair", {"pair_id": pair_id, "sides": sorted(pair)})
            continue
        vuln, patched = pair["vulnerable"], pair["patched"]
        pairs += 1

        joined = ":".join((vuln["advisory_id"], vuln["commit"], vuln["file"],
                           vuln["qualname"], vuln["cwe"]))
        if pair_id != joined:
            fail("pair_id_mismatch", {"pair_id": pair_id, "expected": joined})
        if (patched["repo"], patched["file"], patched["qualname"]) != (
            vuln["repo"], vuln["file"], vuln["qualname"]
        ):
            fail("side_mismatch", {"pair_id": pair_id})
        if not vuln["label"]:
            fail("vulnerable_not_positive", {"pair_id": pair_id})
        if patched["label"]:
            fail("patched_is_positive", {"pair_id": pair_id})
        if patched["cwe"]:
            fail("patched_has_cwe", {"pair_id": pair_id, "cwe": patched["cwe"]})
        if not vuln["cwe"]:
            fail("vulnerable_has_no_cwe", {"pair_id": pair_id})

        key = (vuln["repo"], vuln["file"], vuln["qualname"], vuln["cwe"],
               body_fingerprint(vuln))
        if key in content_seen:
            fail("duplicate_content", {"pair_id": pair_id,
                                       "same_as": content_seen[key]})
        else:
            content_seen[key] = pair_id

    vuln_rows = [record for record in rows if record.get("label")]
    repos = Counter(record["repo"] for record in rows)
    classes = Counter(record["cwe"] for record in vuln_rows)
    tiers = Counter(record.get("evidence", "") for record in vuln_rows)

    summary = {
        "dataset": str(dataset),
        "sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "records": len(rows),
        "pairs": pairs,
        "repositories": len(repos),
        "groups": len({record["group"] for record in vuln_rows}),
        "classes": dict(sorted(classes.items())),
        "evidence_tiers": dict(sorted(tiers.items())),
        "pairs_per_repo": dict(sorted(Counter(
            record["repo"] for record in vuln_rows).items())),
        "checks": {
            "pair_completeness": "pass" if counts["incomplete_pair"] == 0 else "fail",
            "labels": "pass" if not (
                counts["vulnerable_not_positive"] + counts["patched_is_positive"]
            ) else "fail",
            "sources_parse": "pass" if counts["unparseable_source"] == 0 else "fail",
            "content_unique": "pass" if counts["duplicate_content"] == 0 else "fail",
        },
        "failure_counts": dict(sorted(counts.items())),
        "failures": failures,
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", default="data/corpus-v1.1.jsonl")
    parser.add_argument("--json", default=None, help="write the summary here")
    args = parser.parse_args(argv)

    summary = validate(Path(args.dataset))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.json:
        Path(args.json).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return 0 if not summary["failure_counts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
