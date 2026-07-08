#!/usr/bin/env python3
"""Build perfectly balanced training set + full benchmark set for SYRTH 5-class.

Production-hardened dataset builder. Deterministic, no placeholders.

Pipeline
--------
1. Load the merged 5-class raw records (synthetic + GitHub Advisory).
2. Re-tokenise every record through the SAME token vocabulary that
   syrth_scan.py / collect.py emit at inference
   (def:/arg:/call:/sink:/ret:/@decorator/meta:/severity:/framework:).
   Tokens outside that vocabulary are dropped (they never appear at scan time).
3. Stratified split: 80% of each class -> training pool, 20% -> benchmark pool.
   NOTE: training receives the LARGER slice so it owns the majority of the
   real-world vocabulary; the benchmark set keeps every remaining record.
4. Upsample the training pool to exactly TARGET_PER_CLASS per class so the
   model sees a perfectly balanced distribution (no majority-class bias).
5. Persist _balanced_dataset.json (training) and testingMassiveDataset.json
   (full benchmark) atomically.

No data leakage: a record can only land in train OR test, never both.
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Make the repo root importable whether run from WSL or Windows.
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import harvester as H  # noqa: E402

# --------------------------------------------------------------------------- #
# Configuration (deterministic)
# --------------------------------------------------------------------------- #
SEED = 42
TRAIN_RATIO = 0.80
TARGET_PER_CLASS = 500
MERGED_SRC = "_merged_5class.json"
TRAIN_OUT = "_balanced_dataset.json"
TEST_OUT = "testingMassiveDataset.json"

# Token prefixes that syrth_scan.py / collect.py actually emit at inference.
_ALLOWED_PREFIX = {"def", "arg", "call", "sink", "ret", "meta", "severity", "framework"}

# Stable label -> human name map (must match harvester.CWE_LABELS ordering).
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
LOG = logging.getLogger("syrth.build")


def _keep_token(token: str) -> bool:
    """Return True only for tokens that exist in the inference-time vocabulary.

    Decorators (``@...``) are always kept; everything else must use one of the
    prefixes collect.py emits. This guarantees training tokens are drawn from the
    exact same universe as production scanner output.
    """
    if not isinstance(token, str) or not token:
        return False
    if token.startswith("@"):
        return True
    return token.split(":", 1)[0] in _ALLOWED_PREFIX


def re_tokenize(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Re-tokenise records through the inference-aligned pipeline.

    Returns the kept records and the count dropped for lacking any valid token.
    """
    out: List[Dict[str, Any]] = []
    skipped = 0
    for r in records:
        if not isinstance(r, dict):
            skipped += 1
            continue
        desc = r.get("description") or r.get("summary") or ""
        try:
            toks = H._build_advisory_tokens(
                desc, r.get("severity", "") or "", r.get("cwe_id", "") or ""
            )
        except Exception as exc:  # noqa: BLE001 - never let one bad record abort the build
            LOG.warning("tokenise failed for record %s: %s", r.get("ghsa_id", "?"), exc)
            skipped += 1
            continue
        toks = [t for t in toks if _keep_token(t)]
        if not toks:
            skipped += 1
            continue
        fixed = dict(r)
        fixed["tokens"] = toks
        out.append(fixed)
    return out, skipped


def _pack(recs: List[Dict[str, Any]]) -> Dict[str, Any]:
    dist: Dict[str, int] = defaultdict(int)
    for r in recs:
        label = r.get("label")
        name = CWE_IDS.get(label, f"Class{label}")
        dist[name] += 1
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
    """Write JSON atomically: temp file in same dir, then os.replace."""
    path = Path(path)
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
    src = Path(MERGED_SRC)
    if not src.exists():
        LOG.error("merged source not found: %s", src)
        return 1

    try:
        raw = json.loads(src.read_text(encoding="utf-8")).get("records", [])
    except (json.JSONDecodeError, OSError) as exc:
        LOG.error("failed to read %s: %s", src, exc)
        return 1

    LOG.info("Loaded %d raw records from %s", len(raw), src)

    records, skipped = re_tokenize(raw)
    LOG.info("Re-tokenized: %d kept, %d dropped (no valid tokens)", len(records), skipped)
    if not records:
        LOG.error("no usable records after tokenisation")
        return 1

    # Group by label.
    by_label: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        lbl = r.get("label")
        if not isinstance(lbl, int):
            continue
        by_label[lbl].append(r)

    # Stratified split: training gets the 80% MAJORITY slice per class so it
    # owns most of the real-world token vocabulary.
    train_pool: List[Dict[str, Any]] = []
    test_pool: List[Dict[str, Any]] = []
    for label, group in sorted(by_label.items()):
        if not group:
            continue
        rng.shuffle(group)
        n_train = max(1, int(round(len(group) * TRAIN_RATIO)))
        n_train = min(n_train, len(group) - 1) if len(group) > 1 else len(group)
        train_pool.extend(group[:n_train])
        test_pool.extend(group[n_train:])

    LOG.info("Split -> train_pool=%d  test_pool=%d", len(train_pool), len(test_pool))

    # Upsample training pool to exactly TARGET_PER_CLASS per class.
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

    # Benchmark set: every remaining record, unmodified.
    LOG.info("Benchmark set (all remaining):")
    for name in sorted(CWE_IDS.values()):
        cnt = sum(1 for r in test_pool if CWE_IDS.get(r["label"]) == name)
        LOG.info("  %-13s %d", name, cnt)
    LOG.info("Benchmark total: %d", len(test_pool))

    # Vocabulary overlap diagnostic (higher = better generalisation signal).
    train_tokens: set = set()
    for r in balanced_train:
        train_tokens.update(r["tokens"])
    test_tokens: set = set()
    for r in test_pool:
        test_tokens.update(r["tokens"])
    overlap = train_tokens & test_tokens
    cov = 100.0 * len(overlap) / max(1, len(test_tokens))
    LOG.info(
        "Token overlap: %d/%d test tokens seen in train (%.1f%%)",
        len(overlap), len(test_tokens), cov,
    )

    # Sparsity diagnostic.
    if balanced_train:
        t_avg = sum(len(r["tokens"]) for r in balanced_train) / len(balanced_train)
        x_avg = sum(len(r["tokens"]) for r in test_pool) / max(1, len(test_pool))
        LOG.info("Avg tokens/record: train=%.1f  test=%.1f", t_avg, x_avg)

    try:
        _atomic_write(Path(TRAIN_OUT), _pack(balanced_train))
        _atomic_write(Path(TEST_OUT), _pack(test_pool))
    except OSError as exc:
        LOG.error("failed to write datasets: %s", exc)
        return 1

    LOG.info("Saved %s (%d records)", TRAIN_OUT, len(balanced_train))
    LOG.info("Saved %s (%d records)", TEST_OUT, len(test_pool))
    return 0


if __name__ == "__main__":
    sys.exit(main())
