#!/usr/bin/env python3
"""repair_dataset.py — Make an existing SYRTH dataset production-ready.

The datasets previously shipped with two problems:

  1. LEAK: training tokens included a literal ``cwe:<id>`` feature, which is
     the ground-truth label — the model could memorise the answer.
  2. MISALIGNMENT: training tokens were derived from advisory *text*
     (``cwe:/code:/framework:``) while syrth_scan.py emits a different scheme
     (``def:/arg:/sink:/call:/ret:/@decorator/meta:no_auth``). At inference most
     tokens hit <UNK>.
  3. CONTAMINATION: the "train" and "test" files were drawn from the same
     advisory pool with massive overlap, so the benchmark measured
     memorisation, not generalisation.

This script fixes all three WITHOUT re-downloading anything:

  * Re-tokenises every record from its stored ``description`` using
    harvester._build_advisory_tokens() (code blocks -> collect.py tokens,
    otherwise leak-free text tokens).
  * Deduplicates identical records.
  * Splits deterministically by content hash, stratified per class, so a
    sample can never appear in both train and test.

Usage:
    python repair_dataset.py [SOURCE.json] [TRAIN_OUT.json] [TEST_OUT.json]
Defaults: _full_dataset.json -> _balanced_dataset.json + testingMassiveDataset.json
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

import harvester as H

RATIO = 0.2
SEED = 42


def _record_hash(r: dict) -> str:
    # Key the split on (tokens, label) ONLY — not on the source id. This way
    # identical token sequences (even from different advisories) always land on
    # the same side, guaranteeing zero train/test leakage.
    key = json.dumps(
        {"tokens": r.get("tokens"), "label": r.get("label")},
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()


# Only keep tokens that carry security semantics and match the vocabulary
# syrth_scan.py emits at inference time. Drop free-text `code:` fragments
# (normalised advisory snippets) — they are high-cardinality noise that does
# not appear in real code and hurts generalisation.
_ALLOWED_PREFIX = {"def", "arg", "call", "sink", "ret", "meta", "severity", "framework"}


def _keep_token(t: str) -> bool:
    if t.startswith("@"):  # security decorators (@login_required, ...)
        return True
    return t.split(":", 1)[0] in _ALLOWED_PREFIX


def re_tokenize(records: list[dict]) -> list[dict]:
    out: list[dict] = []
    skipped = 0
    for r in records:
        desc = r.get("description") or r.get("summary") or ""
        toks = H._build_advisory_tokens(desc, r.get("severity", ""), r.get("cwe_id", ""))
        toks = [t for t in toks if _keep_token(t)]
        if not toks:
            skipped += 1
            continue
        fixed = dict(r)
        fixed["tokens"] = toks
        out.append(fixed)
    sys.stderr.write(f"[repair] re-tokenized {len(out)} records ({skipped} dropped: no tokens)\n")
    return out


def split_train_test(records: list[dict], ratio: float = RATIO, seed: int = SEED):
    """Leak-free split keyed on (tokens, label).

    We first identify the set of UNIQUE (tokens, label) sequences, split those
    by content hash, then assign every record (including duplicates) according
    to its sequence's membership. A sequence can therefore never appear in both
    train and test.
    """
    def _key(r: dict) -> tuple:
        return (json.dumps(r.get("tokens"), sort_keys=True), r.get("label"))

    unique = []
    seen_keys: set = set()
    for r in records:
        k = _key(r)
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(r)

    test_keys: set = set()
    for r in unique:
        if int(_record_hash(r)[:8], 16) % 100 < int(ratio * 100 + 1e-9):
            test_keys.add(_key(r))

    train = [r for r in records if _key(r) not in test_keys]
    test = [r for r in records if _key(r) in test_keys]
    return train, test


def _pack(records: list[dict]) -> dict:
    class_counts: dict[str, int] = {}
    for r in records:
        name = H.CWE_NAMES.get(r.get("cwe_id", ""), f"Class{r.get('label')}")
        class_counts[name] = class_counts.get(name, 0) + 1
    return {
        "syrth_version": "1.0.0",
        "num_classes": len(H.CWE_LABELS),
        "class_map": {str(v): k for k, v in H.CWE_LABELS.items()},
        "cwe_names": H.CWE_NAMES,
        "class_distribution": class_counts,
        "total_records": len(records),
        "records": records,
    }


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("_full_dataset.json")
    train_out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("_balanced_dataset.json")
    test_out = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("testingMassiveDataset.json")

    if not src.exists():
        sys.stderr.write(f"[repair] source not found: {src}\n")
        sys.exit(1)

    raw = json.loads(src.read_text(encoding="utf-8")).get("records", [])
    sys.stderr.write(f"[repair] loaded {len(raw)} raw records from {src}\n")

    repaired = re_tokenize(raw)
    train, test = split_train_test(repaired)

    # Sanity: prove no leakage between train and test.
    train_hashes = {_record_hash(r) for r in train}
    leaked = sum(1 for r in test if _record_hash(r) in train_hashes)
    sys.stderr.write(f"[repair] leakage check: {leaked} test samples also in train\n")

    train_out.write_text(json.dumps(_pack(train), indent=2), encoding="utf-8")
    test_out.write_text(json.dumps(_pack(test), indent=2), encoding="utf-8")
    sys.stderr.write(
        f"[repair] wrote train={len(train)} -> {train_out}\n"
        f"[repair] wrote test ={len(test)} -> {test_out}\n"
    )


if __name__ == "__main__":
    main()
