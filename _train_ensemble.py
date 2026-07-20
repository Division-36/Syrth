"""Train ensemble of ML models with different seeds."""
import json, sys
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).parent))
from train_model import (
    SyrthEncoder, SyrthTokenizer, NUM_CLASSES,
    DEFAULT_EMBED_DIM, DEFAULT_FFN_DIM, DEFAULT_DROPOUT,
    DEFAULT_BATCH_SIZE, DEFAULT_EPOCHS, DEFAULT_LR, LABEL_SMOOTHING,
    EARLY_STOP_PATIENCE, train_final, export_joblib, export_c_header,
    LOGGER,
)

train = json.load(open("_balanced_dataset.json"))["records"]
test = json.load(open("testingMassiveDataset.json"))["records"]

LOGGER.info("Train: %d, Test: %d", len(train), len(test))

# Use same tokenizer for all models
tokenizer = SyrthTokenizer()
tokenizer.fit([r["tokens"] for r in train])

X = np.array([tokenizer.encode(r["tokens"]) for r in train])
y = np.array([r["label"] for r in train])
X_t = torch.tensor(X, dtype=torch.long)
y_t = torch.tensor(y, dtype=torch.long)

test_X = np.array([tokenizer.encode(r["tokens"]) for r in test])
test_y = np.array([r["label"] for r in test])
test_X_t = torch.tensor(test_X, dtype=torch.long)

counts = np.bincount(y, minlength=NUM_CLASSES).astype(float)
w = torch.tensor(1.0 / np.maximum(counts, 1), dtype=torch.float32)
w = w / w.mean()

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Train 5 models with different seeds
configs = [
    {"name": "s1", "seed": 42, "embed_dim": 256, "ffn_dim": 1024, "dropout": 0.2, "lr": 5e-3},
    {"name": "s2", "seed": 123, "embed_dim": 192, "ffn_dim": 768, "dropout": 0.25, "lr": 3e-3},
    {"name": "s3", "seed": 456, "embed_dim": 224, "ffn_dim": 896, "dropout": 0.3, "lr": 4e-3},
    {"name": "s4", "seed": 789, "embed_dim": 256, "ffn_dim": 768, "dropout": 0.2, "lr": 5e-3},
    {"name": "s5", "seed": 999, "embed_dim": 192, "ffn_dim": 1024, "dropout": 0.3, "lr": 3e-3},
]

ensemble_models = {}
for cfg in configs:
    rng = np.random.RandomState(cfg["seed"])
    n_val = max(1, int(0.1 * len(train)))
    idx = rng.permutation(len(train))
    val_idx, tr_idx = idx[:n_val], idx[n_val:]

    torch.manual_seed(cfg["seed"])
    model = SyrthEncoder(
        vocab_size=tokenizer.vocab_size(),
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg["ffn_dim"],
        dropout=cfg["dropout"],
        aux_dim=0,
    )
    LOGGER.info("Training %s (params=%d, seed=%d)...", cfg["name"], sum(p.numel() for p in model.parameters()), cfg["seed"])

    train_ds = TensorDataset(X_t[tr_idx], y_t[tr_idx])
    train_loader = DataLoader(train_ds, batch_size=DEFAULT_BATCH_SIZE, shuffle=True)

    model = train_final(
        model, train_loader,
        X_t[val_idx], y_t[val_idx],
        epochs=DEFAULT_EPOCHS, lr=cfg["lr"], device=device,
        class_weight=w,
    )

    # Held-out eval
    model.eval()
    with torch.no_grad():
        probs = model.predict_proba(test_X_t.to(device))
        preds = probs.argmax(dim=-1).cpu().numpy()
    acc = (preds == test_y).mean()
    LOGGER.info("  Held-out: %.1f%%", acc * 100)

    ensemble_models[cfg["name"]] = {
        "model": model,
        "config": cfg,
        "heldout_acc": float(acc),
    }

# Save all model states
ensemble_bundle = {
    "syrth_version": "1.1.0",
    "tokenizer_vocab": tokenizer.vocab,
    "vocab_size": tokenizer.vocab_size(),
    "ensemble": {},
}

for name, mdata in ensemble_models.items():
    model = mdata["model"]
    cfg = mdata["config"]
    ensemble_bundle["ensemble"][name] = {
        "config": cfg,
        "heldout_acc": mdata["heldout_acc"],
        "state_dict": {k: v.cpu().numpy() for k, v in model.state_dict().items()},
        "model_config": {
            "vocab_size": tokenizer.vocab_size(),
            "embed_dim": cfg["embed_dim"],
            "ffn_dim": cfg["ffn_dim"],
            "num_classes": NUM_CLASSES,
            "max_seq_len": 128,
            "aux_dim": 0,
        },
    }

import joblib
joblib.dump(ensemble_bundle, "syrth_ensemble.joblib", compress=3)
LOGGER.info("Ensemble saved → syrth_ensemble.joblib (5 models)")
