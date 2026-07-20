"""Fast single-model training: train on ALL data, export bundle.

Usage: python train_final_only.py [--dataset _balanced_dataset.json]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).parent))
from train_model import (  # noqa: E402
    SyrthEncoder, SyrthTokenizer, VulnDataset, NUM_CLASSES,
    DEFAULT_EMBED_DIM, DEFAULT_FFN_DIM, DEFAULT_DROPOUT,
    DEFAULT_BATCH_SIZE, DEFAULT_EPOCHS, DEFAULT_LR, LABEL_SMOOTHING,
    EARLY_STOP_PATIENCE, train_final, export_joblib, export_c_header,
    LOGGER,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="_balanced_dataset.json")
    ap.add_argument("--joblib-path", default="syrth_model.joblib")
    ap.add_argument("--c-path", default="syrth_engine.h")
    args = ap.parse_args()

    records = json.load(open(args.dataset, encoding="utf-8"))
    records = records["records"] if "records" in records else records
    LOGGER.info("Dataset: %d records", len(records))

    tokenizer = SyrthTokenizer()
    tokenizer.fit([r["tokens"] for r in records])
    LOGGER.info("Vocab: %d tokens", tokenizer.vocab_size())

    X = np.array([tokenizer.encode(r["tokens"]) for r in records])
    y = np.array([r["label"] for r in records])
    X_t = torch.tensor(X, dtype=torch.long)
    y_t = torch.tensor(y, dtype=torch.long)

    # 10% val split for early stopping
    n_val = max(1, int(0.1 * len(records)))
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(records))
    val_idx, tr_idx = idx[:n_val], idx[n_val:]

    # Class weights for imbalance robustness
    counts = np.bincount(y, minlength=NUM_CLASSES).astype(float)
    w = torch.tensor(1.0 / np.maximum(counts, 1), dtype=torch.float32)
    w = w / w.mean()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = SyrthEncoder(vocab_size=tokenizer.vocab_size(), aux_dim=0)

    train_ds = TensorDataset(X_t[tr_idx], y_t[tr_idx])
    train_loader = DataLoader(train_ds, batch_size=DEFAULT_BATCH_SIZE, shuffle=True)

    model = train_final(
        model, train_loader,
        X_t[val_idx], y_t[val_idx],
        epochs=DEFAULT_EPOCHS, lr=DEFAULT_LR, device=device,
        class_weight=w,
    )

    metrics = {"heldout_note": "trained on full dataset; evaluate with eval_heldout.py"}
    export_joblib(model, tokenizer, metrics, args.joblib_path)
    export_c_header(model, tokenizer, args.c_path)
    LOGGER.info("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
