"""Evaluate the trained SYRTH model on a strictly held-out test set.

Usage:
    python eval_heldout.py [--model syrth_model.joblib] [--test testingMassiveDataset.json]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from train_model import SyrthEncoder, SyrthTokenizer, MAX_SEQ_LEN, NUM_CLASSES  # noqa: E402
from syrth_scan import CLASS_NAMES  # noqa: E402


def load_bundle(path: str) -> dict:
    import joblib
    return joblib.load(path)


def load_test(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    recs = data["records"] if isinstance(data, dict) and "records" in data else data
    out = []
    for r in recs:
        toks = r.get("tokens")
        if not toks:
            continue
        out.append((toks, r.get("label")))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="syrth_model.joblib")
    ap.add_argument("--test", default="testingMassiveDataset.json")
    args = ap.parse_args()

    bundle = load_bundle(args.model)
    cfg = bundle["model_config"]
    vocab = bundle["tokenizer_vocab"]

    tok = SyrthTokenizer()
    tok.vocab = vocab
    tok._next_id = max(vocab.values()) + 1

    import torch
    model = SyrthEncoder(
        vocab_size=cfg["vocab_size"],
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg.get("ffn_dim", 128),
        num_classes=cfg["num_classes"],
        dropout=0.0,
    )
    state = {k: torch.from_numpy(v.astype(np.float32)) for k, v in bundle["model_state_dict"].items()}
    model.load_state_dict(state)
    model.eval()

    samples = load_test(args.test)
    if not samples:
        print("No test samples found.")
        return 1

    correct = 0
    per_class_total = np.zeros(NUM_CLASSES, dtype=int)
    per_class_correct = np.zeros(NUM_CLASSES, dtype=int)
    pred_counts = np.zeros(NUM_CLASSES, dtype=int)

    with torch.no_grad():
        for toks, label in samples:
            ids = tok.encode(toks)
            x = torch.tensor([ids], dtype=torch.long)
            probs = torch.softmax(model(x), dim=-1)[0].numpy()
            pred = int(np.argmax(probs))
            if pred == label:
                correct += 1
                per_class_correct[label] += 1
            per_class_total[label] += 1
            pred_counts[pred] += 1

    n = len(samples)
    acc = correct / n
    print(f"Held-out test: {n} samples")
    print(f"Overall accuracy: {acc * 100:.1f}%")
    print()
    print("Per-class recall / distribution:")
    for i, name in enumerate(CLASS_NAMES):
        tot = per_class_total[i]
        cor = per_class_correct[i]
        rc = (cor / tot) if tot else 0.0
        print(f"  {name:<14} recall={rc * 100:5.1f}%  (n={tot})")
    print()
    print("Predicted class distribution:")
    for i, name in enumerate(CLASS_NAMES):
        print(f"  {name:<14} {pred_counts[i]:5d}  ({pred_counts[i] / n * 100:.1f}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
