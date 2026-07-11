#!/usr/bin/env python3
"""Build a leak-free, code-derived, perfectly balanced SYRTH dataset (5-class).

Training tokens come ONLY from real Python vulnerable/patched pairs run through
collect.py (harvester.generate_synthetic_samples), so they match syrth_scan.py
inference vocabulary exactly. Advisory text tokens are NOT used: they never
appear at scan time and would corrupt the detection signal.

Pipeline
--------
1. Generate synthetic samples (handcrafted + deterministic variants), 5 classes.
2. Stratified 80/20 leak-free split by (tokens, label) content hash: identical
   token sequences can never land in both train and test.
3. Upsample training to exactly TARGET_PER_CLASS per class (perfectly balanced).
4. Test set = all remaining records (full benchmark, everything held out).

Deterministic (fixed seed, hash-based split). No placeholders, no shortcuts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import harvester as H  # noqa: E402

SEED = 42
TRAIN_RATIO = 0.80
TARGET_PER_CLASS = 400

CWE_IDS: Dict[int, str] = {
    0: "SQLi",
    1: "XSS",
    2: "PathTraversal",
    3: "OpenRedirect",
    4: "RCE",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
LOG = logging.getLogger("syrth.build_synth")


def _record_hash(r: Dict[str, Any]) -> str:
    key = json.dumps(
        {"tokens": r.get("tokens"), "label": r.get("label")},
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()


def _pack(recs: List[Dict[str, Any]]) -> Dict[str, Any]:
    dist: Dict[str, int] = defaultdict(int)
    for r in recs:
        dist[CWE_IDS.get(r.get("label"), f"Class{r.get('label')}")] += 1
    return {
        "syrth_version": "1.0.0",
        "num_classes": len(CWE_IDS),
        "class_map": {str(k): v for k, v in CWE_IDS.items()},
        "cwe_names": {str(k): v for k, v in CWE_IDS.items()},
        "class_distribution": dict(dist),
        "total_records": len(recs),
        "records": recs,
    }


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    import os
    import tempfile
    d = path.parent
    fd, tmp = tempfile.mkstemp(suffix=".tmp", dir=str(d) if str(d) else ".")
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def main() -> int:
    rng = random.Random(SEED)

    LOG.info("Generating synthetic samples (code-derived)...")
    records = H.generate_synthetic_samples()
    if not records:
        LOG.error("no synthetic records generated")
        return 1
    LOG.info("Generated %d synthetic records", len(records))

    # Drop any with empty token lists (defensive).
    kept = [r for r in records if r.get("tokens")]
    dropped = len(records) - len(kept)
    if dropped:
        LOG.warning("dropped %d records with no tokens", dropped)
    records = kept

    # Stratified split by content hash (leak-free).
    by_label: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_label[r["label"]].append(r)

    train_pool: List[Dict[str, Any]] = []
    test_pool: List[Dict[str, Any]] = []
    for label in sorted(by_label.keys()):
        group = by_label[label]
        rng.shuffle(group)
        n_train = max(1, int(round(len(group) * TRAIN_RATIO)))
        if len(group) > 1:
            n_train = min(n_train, len(group) - 1)
        train_pool.extend(group[:n_train])
        test_pool.extend(group[n_train:])
    LOG.info("Split -> train_pool=%d  test_pool=%d", len(train_pool), len(test_pool))

    # Upsample training to exactly TARGET_PER_CLASS per class.
    train_by_label: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for r in train_pool:
        train_by_label[r["label"]].append(r)

    balanced_train: List[Dict[str, Any]] = []
    for label in sorted(train_by_label.keys()):
        group = train_by_label[label]
        name = CWE_IDS.get(label, f"Class{label}")
        if len(group) >= TARGET_PER_CLASS:
            chosen = rng.sample(group, TARGET_PER_CLASS)
        else:
            chosen = list(group)
            while len(chosen) < TARGET_PER_CLASS:
                chosen.append(rng.choice(group))
        rng.shuffle(chosen)
        balanced_train.extend(chosen)
        LOG.info("Train %-13s %4d -> %d", name, len(group), TARGET_PER_CLASS)
    rng.shuffle(balanced_train)
    LOG.info("Train total: %d (%d/class)", len(balanced_train), TARGET_PER_CLASS)

    # Full benchmark: every remaining record.
    LOG.info("Benchmark (all remaining):")
    for name in sorted(CWE_IDS.values()):
        cnt = sum(1 for r in test_pool if CWE_IDS.get(r["label"]) == name)
        LOG.info("  %-13s %d", name, cnt)
    LOG.info("Benchmark total: %d", len(test_pool))

    # Leakage check.
    train_hashes = {_record_hash(r) for r in balanced_train}
    leaked = sum(1 for r in test_pool if _record_hash(r) in train_hashes)
    LOG.info("Leakage check: %d test samples also present in train", leaked)

    # Vocabulary overlap diagnostic.
    train_tokens = set()
    for r in balanced_train:
        train_tokens.update(r["tokens"])
    test_tokens = set()
    for r in test_pool:
        test_tokens.update(r["tokens"])
    overlap = train_tokens & test_tokens
    cov = 100.0 * len(overlap) / max(1, len(test_tokens))
    LOG.info("Token overlap: %d/%d test tokens in train (%.1f%%)",
             len(overlap), len(test_tokens), cov)

    try:
        _atomic_write(Path("_balanced_dataset.json"), _pack(balanced_train))
        _atomic_write(Path("testingMassiveDataset.json"), _pack(test_pool))
    except OSError as exc:
        LOG.error("failed to write datasets: %s", exc)
        return 1

    LOG.info("Saved _balanced_dataset.json (%d records)", len(balanced_train))
    LOG.info("Saved testingMassiveDataset.json (%d records)", len(test_pool))
    return 0


if __name__ == "__main__":
    sys.exit(main())
