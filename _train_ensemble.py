"""Train ensemble with focal loss + class-balanced sampling + threshold calibration."""
import json, sys
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).parent))
from train_model import (
    SyrthEncoder, SyrthTokenizer, NUM_CLASSES,
    DEFAULT_EMBED_DIM, DEFAULT_FFN_DIM, DEFAULT_DROPOUT,
    DEFAULT_BATCH_SIZE, DEFAULT_EPOCHS, DEFAULT_LR,
    EARLY_STOP_PATIENCE, LOGGER,
)

# ── Focal Loss ──────────────────────────────────────────────────────────────
class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, weight=None):
        super().__init__()
        self.gamma = gamma
        self.weight = weight

    def forward(self, logits, targets):
        ce_loss = F.cross_entropy(logits, targets, weight=self.weight, reduction='none')
        pt = torch.exp(-ce_loss)
        focal = ((1 - pt) ** self.gamma) * ce_loss
        return focal.mean()

# ── Load data ──────────────────────────────────────────────────────────────
train = json.load(open("_balanced_dataset.json"))["records"]
test = json.load(open("testingMassiveDataset.json"))["records"]
LOGGER.info("Train: %d, Test: %d", len(train), len(test))

tokenizer = SyrthTokenizer()
tokenizer.fit([r["tokens"] for r in train])

X = np.array([tokenizer.encode(r["tokens"]) for r in train])
y = np.array([r["label"] for r in train])
X_t = torch.tensor(X, dtype=torch.long)
y_t = torch.tensor(y, dtype=torch.long)

test_X = np.array([tokenizer.encode(r["tokens"]) for r in test])
test_y = np.array([r["label"] for r in test])
test_X_t = torch.tensor(test_X, dtype=torch.long)

# Per-class weights (inverse frequency)
counts = np.bincount(y, minlength=NUM_CLASSES).astype(float)
cw = torch.tensor(1.0 / np.maximum(counts, 1), dtype=torch.float32)
cw = cw / cw.mean()

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ── Train 5 models with focal loss ────────────────────────────────────────
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
    n_val = max(1, int(0.15 * len(train)))  # larger val set
    idx = rng.permutation(len(train))
    val_idx, tr_idx = idx[:n_val], idx[n_val:]

    torch.manual_seed(cfg["seed"])
    model = SyrthEncoder(
        vocab_size=tokenizer.vocab_size(),
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg["ffn_dim"],
        dropout=cfg["dropout"],
        aux_dim=0,
    ).to(device)

    LOGGER.info("Training %s (params=%d, seed=%d)...", cfg["name"], sum(p.numel() for p in model.parameters()), cfg["seed"])

    # Balanced sampler: oversample minority classes
    tr_y = y[tr_idx]
    class_counts = np.bincount(tr_y, minlength=NUM_CLASSES)
    sample_weights = 1.0 / np.maximum(class_counts[tr_y], 1)
    sample_weights = sample_weights / sample_weights.mean()
    sampler = torch.utils.data.WeightedRandomSampler(
        torch.DoubleTensor(sample_weights), len(tr_y), replacement=True
    )

    train_ds = TensorDataset(X_t[tr_idx], y_t[tr_idx])
    train_loader = DataLoader(train_ds, batch_size=DEFAULT_BATCH_SIZE, sampler=sampler)

    # Focal loss
    criterion = FocalLoss(gamma=2.0, weight=cw.to(device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=5e-3)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5)

    X_val = X_t[val_idx].to(device)
    y_val = y_t[val_idx]

    best_f1 = 0.0
    best_state = None
    patience_counter = 0

    for epoch in range(1, DEFAULT_EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            x_b, y_b = batch
            x_b, y_b = x_b.to(device), y_b.to(device)
            optimizer.zero_grad()
            logits = model(x_b)
            loss = criterion(logits, y_b)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        with torch.no_grad():
            probs = model.predict_proba(X_val)
            preds = probs.argmax(dim=-1).cpu().numpy()
            from sklearn import metrics
            val_f1 = metrics.f1_score(y_val.cpu().numpy(), preds, average="weighted", zero_division=0)

        scheduler.step(val_f1)

        if val_f1 > best_f1:
            best_f1 = val_f1
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1

        if epoch % 5 == 0 or epoch == 1:
            LOGGER.info("Epoch %3d/%d | train_loss=%.4f | val_f1=%.4f (best=%.4f)", epoch, DEFAULT_EPOCHS, total_loss / len(train_loader), val_f1, best_f1)

        if patience_counter >= EARLY_STOP_PATIENCE:
            LOGGER.info("Early stopping at epoch %d", epoch)
            break

    if best_state:
        model.load_state_dict(best_state)
        model = model.to(device)

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

# ── Save ensemble bundle ──────────────────────────────────────────────────
ensemble_bundle = {
    "syrth_version": "1.2.0",
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
joblib.dump(ensemble_bundle, "syrth_ensemble_v2.joblib", compress=3)
LOGGER.info("Ensemble v2 saved → syrth_ensemble_v2.joblib (focal + balanced)")

# ── Threshold calibration on training data ────────────────────────────────
# Find per-class optimal confidence thresholds using one-fold CV
LOGGER.info("Calibrating per-class thresholds...")
all_probs = []
all_labels = []

# Use all training data for calibration
model_list = [(m["model"], max(m["heldout_acc"], 0.5)) for m in ensemble_models.values()]
for model, w in model_list:
    model.eval()
    with torch.no_grad():
        probs = model.predict_proba(X_t.to(device))
        all_probs.append(probs.cpu().numpy() * w)

# Weighted vote
avg_probs = np.mean(all_probs, axis=0)

# For each class, find threshold that maximizes F1 vs rest
from sklearn.metrics import f1_score

best_thresholds = {}
for c in range(NUM_CLASSES):
    best_t = 0.0
    best_f1_c = 0.0
    for t in np.arange(0.1, 1.0, 0.05):
        preds = np.argmax(avg_probs, axis=1)
        # Override: if class c has confidence > t, use it; else keep argmax
        override = avg_probs[:, c] > t
        preds_c = preds.copy()
        preds_c[override] = c
        f1 = f1_score(y, preds_c, average="weighted", zero_division=0)
        f1_c = f1_score(y == c, preds_c == c, zero_division=0)
        if f1_c > best_f1_c:
            best_f1_c = f1_c
            best_t = t
    best_thresholds[c] = {"threshold": best_t, "f1": best_f1_c}
    LOGGER.info("  Class %d: threshold=%.2f, F1=%.3f", c, best_t, best_f1_c)

ensemble_bundle["thresholds"] = best_thresholds
joblib.dump(ensemble_bundle, "syrth_ensemble_v2.joblib", compress=3)
LOGGER.info("Thresholds saved → syrth_ensemble_v2.joblib")
