"""Merge corpus stages into one de-duplicated JSONL corpus.

The stages are deliberately ordered: earlier inputs win.  ``data/corpus.jsonl``
is the frozen v1 corpus, so a pair that appears in both v1 and an expansion
keeps the v1 record (and therefore the v1 provenance and evidence tier).  New
pairs are appended from the later stages.

Records are joined on ``pair_id``, not on a provenance tuple: the patched side
of a pair carries ``cwe=""`` by construction, so grouping on
``(repo, commit, file, qualname, cwe)`` would split every pair into two
single-sided groups.  ``pair_id`` already encodes the vulnerable side's
``(repo, commit, file, qualname, cwe)`` and is identical on both records.

Two pairs are the same finding when either

* their provenance key ``(repo, commit, file, qualname, cwe)`` matches, or
* their **function body** and class match inside the same file.  The second
  test catches the same vulnerable function reached through a later follow-up
  commit, which the per-run builder already collapses but a merge across runs
  would otherwise count twice.  Module context is excluded from the body hash:
  the same function can acquire a different import block between commits.

Every pair must have exactly one ``vulnerable`` and one ``patched`` record.  An
incomplete pair is dropped and reported, never silently shipped.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def provenance(record: dict) -> tuple:
    return (
        record["repo"], record["commit"], record["file"],
        record["qualname"], record["cwe"],
    )


def body_fingerprint(record: dict) -> str:
    """Hash the function body, ignoring module context and line numbers."""
    try:
        tree = ast.parse(record["source"])
    except SyntaxError:
        return hashlib.sha256(record["source"].encode("utf-8")).hexdigest()
    name = record["function"]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            dumped = ast.dump(node, annotate_fields=True, include_attributes=False)
            return hashlib.sha256(dumped.encode("utf-8")).hexdigest()
    return hashlib.sha256(record["source"].encode("utf-8")).hexdigest()


def content(record: dict) -> tuple:
    return (
        record["repo"], record["file"], record["qualname"],
        record["cwe"], body_fingerprint(record),
    )


def group_pairs(rows: list[dict], source: str, stats: dict) -> list[dict]:
    """Return complete pairs keyed by ``pair_id``, preserving file order."""
    ordered: list[str] = []
    sides: dict[str, dict[str, dict]] = {}
    for record in rows:
        key = record.get("pair_id")
        if not key:
            stats["missing_pair_id"] += 1
            continue
        if key not in sides:
            sides[key] = {}
            ordered.append(key)
        side = record["kind"]
        if side in sides[key]:
            stats["duplicate_records"] += 1
            continue
        sides[key][side] = record
    pairs = []
    for key in ordered:
        pair = sides[key]
        if set(pair) != {"vulnerable", "patched"}:
            stats["incomplete_pairs"] += 1
            stats["incomplete_examples"].append(
                {"source": source, "pair_id": key, "sides": sorted(pair)}
            )
            continue
        vuln, patched = pair["vulnerable"], pair["patched"]
        if not vuln.get("label") or patched.get("label"):
            stats["label_mismatch"] += 1
            continue
        # The pair id is the vulnerable side's (advisory, provenance); a
        # patched record that disagrees with it belongs to another finding.
        joined = ":".join(
            (vuln["advisory_id"], vuln["commit"], vuln["file"],
             vuln["qualname"], vuln["cwe"])
        )
        if key != joined:
            stats["pair_id_mismatch"] += 1
            continue
        if (patched["repo"], patched["file"], patched["qualname"]) != (
            vuln["repo"], vuln["file"], vuln["qualname"]
        ):
            stats["pair_id_mismatch"] += 1
            continue
        pairs.append({"vulnerable": vuln, "patched": patched})
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputs", nargs="+", help="JSONL stages, earliest wins")
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", default=None)
    args = parser.parse_args(argv)

    stats = {
        "duplicate_records": 0,
        "missing_pair_id": 0,
        "incomplete_pairs": 0,
        "incomplete_examples": [],
        "label_mismatch": 0,
        "pair_id_mismatch": 0,
        "duplicate_provenance_pairs": 0,
        "duplicate_content_pairs": 0,
    }
    seen_provenance: set[tuple] = set()
    seen_content: set[tuple] = set()
    chosen: list[dict] = []
    per_input = []

    for raw_path in args.inputs:
        path = Path(raw_path)
        rows = load(path)
        pairs = group_pairs(rows, raw_path, stats)
        added = 0
        for pair in pairs:
            vuln = pair["vulnerable"]
            pkey, ckey = provenance(vuln), content(vuln)
            if pkey in seen_provenance:
                stats["duplicate_provenance_pairs"] += 1
                continue
            if ckey in seen_content:
                stats["duplicate_content_pairs"] += 1
                continue
            seen_provenance.add(pkey)
            seen_content.add(ckey)
            chosen.append(pair["vulnerable"])
            chosen.append(pair["patched"])
            added += 1
        per_input.append({
            "path": raw_path,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "records": len(rows),
            "pairs": len(pairs),
            "added_pairs": added,
        })

    chosen.sort(key=lambda r: (
        r["repo"], r["commit"], r["file"], r["qualname"], r["cwe"],
        0 if r["kind"] == "vulnerable" else 1,
    ))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in chosen),
        encoding="utf-8",
    )

    vuln = [r for r in chosen if r["kind"] == "vulnerable"]
    summary = {
        "inputs": per_input,
        "rule": ("group on pair_id; provenance then function-body dedup; "
                 "earlier input wins; incomplete pairs rejected"),
        "records": len(chosen),
        "pairs": len(vuln),
        "groups": len({r["group"] for r in vuln}),
        "repos": len({r["repo"] for r in chosen}),
        "classes": dict(sorted(Counter(r["cwe"] for r in vuln).items())),
        "evidence_tiers": dict(sorted(Counter(r.get("evidence", "") for r in vuln).items())),
        **stats,
    }
    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    # Dedup counters are expected; every other counter means a pair was
    # rejected. A merge that loses a pair must not exit green.
    rejected = (
        "duplicate_records", "missing_pair_id", "incomplete_pairs",
        "label_mismatch", "pair_id_mismatch",
    )
    return 0 if not any(stats[key] for key in rejected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
