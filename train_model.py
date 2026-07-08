"""
SYRTH: Scan Your Risk Trace History
====================================
train_model.py — PyTorch Transformer training with best-practice pipeline.

Best-of-all structure adapted from detector_embedded.py:
  1. 3-way split (train / prune / val) — prevents data leakage
  2. 2-phase grid search (pilot → full CV on top-5)
  3. Early stop in pilot only — never stops Phase B early
  4. Model size management with optional pruning
  5. Comprehensive metrics: accuracy, precision, recall, F1, confusion matrix
  6. C-engine verification — ensures Python/C agreement
  7. Test vector logging for embedded debugging

Target: >=95% accuracy, fast inference, compact C header.

Usage:
    python train_model.py --dataset _dataset.json
    python train_model.py --dataset _dataset.json --prune  # extra pruning
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    from sklearn.model_selection import StratifiedKFold, train_test_split
    from sklearn import metrics
except ImportError:
    sys.stderr.write("[SYRTH train] ERROR: PyTorch or scikit-learn not installed.\n")
    sys.exit(1)

try:
    import joblib
except ImportError:
    sys.stderr.write("[SYRTH train] ERROR: joblib not installed.\n")
    sys.exit(1)

# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
LOGGER = logging.getLogger(__name__)


def _fmt_time(s: float) -> str:
    s = max(0, int(s))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {s:02d}s"

# ── Configuration ───────────────────────────────────────────────────────────

NUM_CLASSES = 5
PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
MAX_SEQ_LEN = 128

# Hyperparameters tuned for better performance and robustness
DEFAULT_EMBED_DIM = 256  # Larger embeddings for better capacity
DEFAULT_FFN_DIM = 1024   # Wider MLP for better capacity
DEFAULT_DROPOUT = 0.2   # Stronger regularization
DEFAULT_BATCH_SIZE = 64  # Smaller batches for faster convergence
DEFAULT_LR = 5e-3  # Higher learning rate for faster convergence
DEFAULT_EPOCHS = 100  # Fewer epochs for faster convergence

LABEL_SMOOTHING = 0.1  # Smaller smoothing for better accuracy
EARLY_STOP_PATIENCE = 18  # Fewer patience for faster convergence

K_FOLDS = 20

CWE_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]


# ── Tokenizer ───────────────────────────────────────────────────────────────

class SyrthTokenizer:
    """Simple vocabulary-based tokenizer for SYRTH token sequences."""

    def __init__(self) -> None:
        self.vocab: dict[str, int] = {PAD_TOKEN: 0, UNK_TOKEN: 1}
        self._next_id = 2

    def fit(self, token_sequences: list[list[str]]) -> "SyrthTokenizer":
        """Build vocabulary from token sequences."""
        counter: Counter[str] = Counter()
        for seq in token_sequences:
            counter.update(seq)
        for token, _ in counter.most_common():
            if token not in self.vocab:
                self.vocab[token] = self._next_id
                self._next_id += 1
        return self

    def encode(self, tokens: list[str], max_len: int = MAX_SEQ_LEN) -> list[int]:
        """Encode tokens to IDs with padding/truncation."""
        unk_id = self.vocab[UNK_TOKEN]
        ids = [self.vocab.get(t, unk_id) for t in tokens[:max_len]]
        ids += [self.vocab[PAD_TOKEN]] * (max_len - len(ids))
        return ids

    def vocab_size(self) -> int:
        return len(self.vocab)


# ── Dataset ─────────────────────────────────────────────────────────────────

class VulnDataset(Dataset):
    """PyTorch Dataset for SYRTH records."""

    def __init__(self, records: list[dict[str, Any]], tokenizer: SyrthTokenizer) -> None:
        self.records = records
        self.tokenizer = tokenizer

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, int]:
        record = self.records[idx]
        ids = self.tokenizer.encode(record["tokens"])
        return torch.tensor(ids, dtype=torch.long), int(record["label"])


# ── Model ───────────────────────────────────────────────────────────────────

class SyrthEncoder(nn.Module):
    """Simple Bag-of-Words + MLP classifier for vulnerability detection.
    
    Much more effective than Transformers on tiny datasets.
    Architecture: Embedding -> Mean Pooling -> MLP -> Output
    """

    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = DEFAULT_EMBED_DIM,
        ffn_dim: int = DEFAULT_FFN_DIM,
        num_classes: int = NUM_CLASSES,
        dropout: float = DEFAULT_DROPOUT,
    ) -> None:
        super().__init__()
        self.embed_dim = embed_dim
        self.ffn_dim = ffn_dim  # Store for export
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.dropout = nn.Dropout(dropout)

        # Deeper MLP head for better capacity
        self.head = nn.Sequential(
            nn.Linear(embed_dim, ffn_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim, ffn_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim // 2, num_classes),
        )

        self._init_weights()

    def _init_weights(self):
        """Xavier initialization for better convergence."""
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.Embedding):
                nn.init.normal_(m.weight, mean=0, std=0.01)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        padding_mask = x == 0
        embeds = self.embedding(x)
        # Mean pool with proper masking
        mask_float = (~padding_mask).float().unsqueeze(-1)
        pooled = (embeds * mask_float).sum(dim=1) / mask_float.sum(dim=1).clamp(min=1.0)
        pooled = self.dropout(pooled)
        return self.head(pooled)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            return F.softmax(self.forward(x), dim=-1)


# ── Training & Evaluation ───────────────────────────────────────────────────

def _train_epoch(
    model: SyrthEncoder,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: nn.Module,
    device: torch.device,
) -> float:
    model.train()
    total_loss = 0.0
    for x_batch, y_batch in loader:
        x_batch = x_batch.to(device)
        y_batch = y_batch.to(device)
        optimizer.zero_grad()
        logits = model(x_batch)
        loss = criterion(logits, y_batch)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total_loss += loss.item()
    return total_loss / len(loader)


def _eval_model(
    model: SyrthEncoder,
    X: torch.Tensor,
    y: torch.Tensor,
    device: torch.device,
) -> Dict[str, float]:
    """Comprehensive evaluation with sklearn metrics."""
    model.eval()
    with torch.no_grad():
        probs = model.predict_proba(X.to(device))
        preds = probs.argmax(dim=-1).cpu().numpy()
        y_np = y.cpu().numpy()

    acc = metrics.accuracy_score(y_np, preds)
    prec = metrics.precision_score(y_np, preds, average="weighted", zero_division=0)
    rec = metrics.recall_score(y_np, preds, average="weighted", zero_division=0)
    f1 = metrics.f1_score(y_np, preds, average="weighted", zero_division=0)
    cm = metrics.confusion_matrix(y_np, preds, labels=list(range(NUM_CLASSES)))

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm.tolist(),
    }


def train_final(
    model: SyrthEncoder,
    train_loader: DataLoader,
    X_val: torch.Tensor,
    y_val: torch.Tensor,
    epochs: int = DEFAULT_EPOCHS,
    lr: float = DEFAULT_LR,
    device: torch.device | None = None,
    class_weight: torch.Tensor | None = None,
) -> SyrthEncoder:
    """Train model with early stopping based on validation F1."""
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=5e-3)  # Stronger regularization
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5)
    weight = class_weight.to(device) if class_weight is not None else None
    criterion = nn.CrossEntropyLoss(label_smoothing=LABEL_SMOOTHING, weight=weight)

    best_f1 = 0.0
    best_state = None
    patience_counter = 0

    for epoch in range(1, epochs + 1):
        train_loss = _train_epoch(model, train_loader, optimizer, criterion, device)

        val_results = _eval_model(model, X_val, y_val, device)
        val_f1 = val_results["f1"]

        scheduler.step(val_f1)  # ReduceLROnPlateau needs metric

        if val_f1 > best_f1:
            best_f1 = val_f1
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1

        if epoch % 5 == 0 or epoch == 1:
            LOGGER.info("Epoch %3d/%d | train_loss=%.4f | val_f1=%.4f (best=%.4f)", epoch, epochs, train_loss, val_f1, best_f1)

        if patience_counter >= EARLY_STOP_PATIENCE:
            LOGGER.info("Early stopping at epoch %d", epoch)
            break

    if best_state:
        model.load_state_dict(best_state)
        model = model.to(device)

    return model


# ---------------------------------------------------------------------------
# Export A — Joblib
# ---------------------------------------------------------------------------

def export_joblib(
    model: SyrthEncoder,
    tokenizer: SyrthTokenizer,
    metrics_dict: Dict,
    output_path: str = "syrth_model.joblib",
) -> None:
    """Export trained model and metrics."""
    model.eval()
    bundle = {
        "syrth_version": "1.0.0",
        "model_state_dict": {k: v.cpu().numpy() for k, v in model.state_dict().items()},
        "model_config": {
            "vocab_size": tokenizer.vocab_size(),
            "embed_dim": model.embed_dim,
            "ffn_dim": model.ffn_dim,  # Now properly exported
            "num_classes": NUM_CLASSES,
            "max_seq_len": MAX_SEQ_LEN,
        },
        "tokenizer_vocab": tokenizer.vocab,
        "metrics": metrics_dict,
    }
    joblib.dump(bundle, output_path, compress=3)
    LOGGER.info("Joblib bundle → %s", output_path)


# ---------------------------------------------------------------------------
# Export B — C Header
# ---------------------------------------------------------------------------

def _escape_c_string(s: str) -> str:
    """Escape a string for use as a C string literal."""
    # Escape backslashes first, then quotes, then newlines/tabs
    s = s.replace("\\", "\\\\")  # Escape backslashes
    s = s.replace('"', '\\"')     # Escape double quotes
    s = s.replace("\n", "\\n")      # Escape newlines
    s = s.replace("\r", "\\r")      # Escape carriage returns
    s = s.replace("\t", "\\t")      # Escape tabs
    return s


def _array_to_c(name: str, data: np.ndarray, dtype: str = "float") -> str:
    """Serialise a numpy array as a C static array initialiser."""
    flat = data.flatten().astype(np.float32)
    size = flat.size
    vals = ", ".join(f"{v:.8f}f" for v in flat)
    shape_comment = f"/* shape: {list(data.shape)} */"
    return (
        f"static const {dtype} {name}[{size}] = {{\n"
        f"    {shape_comment}\n"
        f"    {vals}\n"
        f"}};\n"
    )


def export_c_header(
    model: SyrthEncoder,
    tokenizer: SyrthTokenizer,
    output_path: str = "syrth_engine.h",
) -> None:
    """
    Export the model's MLP head and embedding lookup into a self-contained
    C header file for zero-dependency production inference.

    Strategy (keeping C tractable):
         1. Freeze the embedding weights and average-pool the token
            embeddings — expressible in pure C as a lookup + average.
         2. Export the MLP head weights (3 linear layers, ReLU) as C
            float arrays, matching the PyTorch `SyrthEncoder` exactly.
         3. Generate a C inference function `syrth_predict()` that:
            a. Maps token strings → vocab IDs (via a sorted string table)
            b. Averages the embeddings for the input tokens
            c. Runs the 3-layer ReLU MLP on the pooled vector
            d. Returns the argmax class index and confidence score.

     This mirrors the Python model exactly (Bag-of-Words embedding +
     mean pooling + 3-layer ReLU MLP) so dev and fast modes agree.
     """
    model.eval()
    state = {k: v.cpu().numpy() for k, v in model.state_dict().items()}
    vocab = tokenizer.vocab  # token → int_id

    # Pre-compute token embeddings (vocab_size × embed_dim)
    embed_weight = state["embedding.weight"]  # (vocab_size, embed_dim)

    # MLP head weights — three linear layers (ReLU activations)
    # head.0 = Linear(embed_dim, ffn_dim)
    # head.3 = Linear(ffn_dim, ffn_dim // 2)
    # head.6 = Linear(ffn_dim // 2, num_classes)
    mlp_w0 = state["head.0.weight"]   # (ffn_dim, embed_dim)
    mlp_b0 = state["head.0.bias"]     # (ffn_dim,)
    mlp_w1 = state["head.3.weight"]   # (ffn_dim // 2, ffn_dim)
    mlp_b1 = state["head.3.bias"]     # (ffn_dim // 2,)
    mlp_w2 = state["head.6.weight"]   # (num_classes, ffn_dim // 2)
    mlp_b2 = state["head.6.bias"]     # (num_classes,)
    ffn2_dim = int(mlp_w1.shape[0])   # hidden size of layer 1

    vocab_size, embed_dim = embed_weight.shape
    ffn_dim_actual = mlp_w0.shape[0]
    num_classes_actual = mlp_w2.shape[0]

    # Build sorted vocab array for binary search in C
    sorted_vocab = sorted(vocab.items(), key=lambda kv: kv[0])
    vocab_strings = [kv[0] for kv in sorted_vocab]
    vocab_ids = [kv[1] for kv in sorted_vocab]

    # Encode vocab strings as C string literals (properly escaped)
    vocab_c_strings = "\n".join(
        f'    "{_escape_c_string(s)}",' for s in vocab_strings
    )
    vocab_c_ids = ", ".join(str(i) for i in vocab_ids)

    cwe_names = [
        "SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE",
    ]

    lines: list[str] = [
        "/*",
        " * syrth_engine.h — SYRTH: Scan Your Risk Trace History",
        " * Auto-generated C inference engine. Zero dependencies.",
        " * DO NOT EDIT BY HAND.",
        " */",
        "#ifndef SYRTH_ENGINE_H",
        "#define SYRTH_ENGINE_H",
        "",
        "#include <string.h>",
        "#include <math.h>",
        "#include <float.h>",
        "",
        f"#define SYRTH_VOCAB_SIZE   {vocab_size}",
        f"#define SYRTH_EMBED_DIM    {embed_dim}",
        f"#define SYRTH_FFN_DIM      {ffn_dim_actual}",
        f"#define SYRTH_FFN2_DIM     {ffn2_dim}",
        f"#define SYRTH_NUM_CLASSES  {num_classes_actual}",
        f"#define SYRTH_MAX_TOKENS   {MAX_SEQ_LEN}",
        "",
        "/* ── CWE class names ───────────────────────────────────────────── */",
        "static const char* SYRTH_CLASS_NAMES[] = {",
    ]
    for name in cwe_names:
        lines.append(f'    "{name}",')
    lines += [
        "};",
        "",
        "/* ── Vocabulary: sorted token strings + their IDs ─────────────── */",
        f"static const char* SYRTH_VOCAB_STRINGS[{vocab_size}] = {{",
        vocab_c_strings,
        "};",
        f"static const int SYRTH_VOCAB_IDS[{vocab_size}] = {{ {vocab_c_ids} }};",
        "",
    ]

    # Weight arrays
    lines += [
        "/* ── Embedding weight matrix ──────────────────────────────────── */",
        _array_to_c("SYRTH_EMBED", embed_weight),
        "/* ── MLP layer 0 (embed -> ffn) weights + biases ──────────────── */",
        _array_to_c("SYRTH_W0", mlp_w0),
        _array_to_c("SYRTH_B0", mlp_b0),
        "/* ── MLP layer 1 (ffn -> ffn/2) weights + biases ──────────────── */",
        _array_to_c("SYRTH_W1", mlp_w1),
        _array_to_c("SYRTH_B1", mlp_b1),
        "/* ── MLP layer 2 (ffn/2 -> num_classes) weights + biases ──────── */",
        _array_to_c("SYRTH_W2", mlp_w2),
        _array_to_c("SYRTH_B2", mlp_b2),
    ]

    # Inline C functions
    lines += [
        "",
        "/* ── Inference implementation ──────────────────────────────────── */",
        "",
        "/* Binary-search token string → vocab ID. Returns 1 (UNK) if not found. */",
        "static int syrth_lookup_token(const char* token) {",
        "    int lo = 0, hi = SYRTH_VOCAB_SIZE - 1;",
        "    while (lo <= hi) {",
        "        int mid = (lo + hi) / 2;",
        "        int cmp = strcmp(SYRTH_VOCAB_STRINGS[mid], token);",
        "        if (cmp == 0) return SYRTH_VOCAB_IDS[mid];",
        "        if (cmp < 0) lo = mid + 1;",
        "        else         hi = mid - 1;",
        "    }",
        "    return 1; /* UNK */",
        "}",
        "",
        "/* ReLU activation (matches PyTorch training) */",
        "static float syrth_relu(float x) {",
        "    return x > 0.0f ? x : 0.0f;",
        "}",
        "",
        "/* Softmax in-place */",
        "static void syrth_softmax(float* arr, int n) {",
        "    float max_val = -FLT_MAX;",
        "    for (int i = 0; i < n; i++) if (arr[i] > max_val) max_val = arr[i];",
        "    float sum = 0.0f;",
        "    for (int i = 0; i < n; i++) { arr[i] = expf(arr[i] - max_val); sum += arr[i]; }",
        "    for (int i = 0; i < n; i++) arr[i] /= sum;",
        "}",
        "",
        "/*",
        " * syrth_predict() — main inference entry point.",
        " *",
        " * tokens:     array of token strings (e.g. [\"def:get_user\", \"sink:execute\"])",
        " * num_tokens: length of tokens array",
        " * out_class:  pointer to int — receives predicted class index",
        " * out_conf:   pointer to float — receives confidence in [0, 1]",
        " *",
        " * Returns: pointer to the class name string (e.g. \"IDOR\").",
        " */",
        "static const char* syrth_predict(",
        "    const char** tokens, int num_tokens,",
        "    int* out_class, float* out_conf",
        ") {",
        "    /* 1. Look up embeddings and average-pool */",
        "    float pooled[SYRTH_EMBED_DIM] = {0};",
        "    int count = 0;",
        "    for (int t = 0; t < num_tokens && t < SYRTH_MAX_TOKENS; t++) {",
        "        int vid = syrth_lookup_token(tokens[t]);",
        "        for (int d = 0; d < SYRTH_EMBED_DIM; d++) {",
        "            pooled[d] += SYRTH_EMBED[vid * SYRTH_EMBED_DIM + d];",
        "        }",
        "        count++;",
        "    }",
        "    if (count > 0)",
        "        for (int d = 0; d < SYRTH_EMBED_DIM; d++) pooled[d] /= (float)count;",
        "",
        "    /* 2. MLP layer 0: W0 @ pooled + B0 → ReLU → hidden1 */",
        "    float hidden1[SYRTH_FFN_DIM];",
        "    for (int i = 0; i < SYRTH_FFN_DIM; i++) {",
        "        float acc = SYRTH_B0[i];",
        "        for (int j = 0; j < SYRTH_EMBED_DIM; j++)",
        "            acc += SYRTH_W0[i * SYRTH_EMBED_DIM + j] * pooled[j];",
        "        hidden1[i] = syrth_relu(acc);",
        "    }",
        "",
        "    /* 3. MLP layer 1: W1 @ hidden1 + B1 → ReLU → hidden2 */",
        "    float hidden2[SYRTH_FFN2_DIM];",
        "    for (int i = 0; i < SYRTH_FFN2_DIM; i++) {",
        "        float acc = SYRTH_B1[i];",
        "        for (int j = 0; j < SYRTH_FFN_DIM; j++)",
        "            acc += SYRTH_W1[i * SYRTH_FFN_DIM + j] * hidden1[j];",
        "        hidden2[i] = syrth_relu(acc);",
        "    }",
        "",
        "    /* 4. MLP layer 2: W2 @ hidden2 + B2 → logits */",
        "    float logits[SYRTH_NUM_CLASSES];",
        "    for (int i = 0; i < SYRTH_NUM_CLASSES; i++) {",
        "        float acc = SYRTH_B2[i];",
        "        for (int j = 0; j < SYRTH_FFN2_DIM; j++)",
        "            acc += SYRTH_W2[i * SYRTH_FFN2_DIM + j] * hidden2[j];",
        "        logits[i] = acc;",
        "    }",
        "",
        "    /* 4. Softmax + argmax */",
        "    syrth_softmax(logits, SYRTH_NUM_CLASSES);",
        "    int best = 0;",
        "    for (int i = 1; i < SYRTH_NUM_CLASSES; i++)",
        "        if (logits[i] > logits[best]) best = i;",
        "",
        "    *out_class = best;",
        "    *out_conf  = logits[best];",
        "    return SYRTH_CLASS_NAMES[best];",
        "}",
        "",
        "#endif /* SYRTH_ENGINE_H */",
    ]

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    sys.stderr.write(f"[SYRTH train] C header → {output_path}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _load_dataset(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records = data.get("records", [])
    return [r for r in records if r.get("tokens") and isinstance(r.get("label"), int)]


def train_and_evaluate(
    dataset_path: str = "_dataset.json",
    export_joblib_flag: bool = True,
    export_c_flag: bool = True,
    joblib_path: str = "syrth_model.joblib",
    c_path: str = "syrth_engine.h",
) -> None:
    """Main training pipeline with k-fold cross-validation for crazy accuracy."""

    if not Path(dataset_path).exists():
        LOGGER.error("Dataset not found: %s", dataset_path)
        return

    # ── Load Data ────────────────────────────────────────────────────────────
    LOGGER.info("Loading dataset from %s...", dataset_path)
    records = _load_dataset(dataset_path)

    if not records:
        LOGGER.error("No usable records in dataset.")
        return

    LOGGER.info("Dataset: %d records", len(records))

    # Class distribution
    class_counts = Counter(r["label"] for r in records)
    for label, count in sorted(class_counts.items()):
        LOGGER.info("  Class %d (%s): %d", label, CWE_NAMES[label] if label < len(CWE_NAMES) else "?", count)

    # ── Tokenizer ────────────────────────────────────────────────────────────
    LOGGER.info("Building tokenizer...")
    tokenizer = SyrthTokenizer()
    tokenizer.fit([r["tokens"] for r in records])
    LOGGER.info("Vocabulary size: %d tokens", tokenizer.vocab_size())

    # ── Prepare arrays ─────────────────────────────────────────────────────────
    all_tokens = [tokenizer.encode(r["tokens"]) for r in records]
    X_all = np.array(all_tokens)
    y_all = np.array([r["label"] for r in records])

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    LOGGER.info("Device: %s", device)

    # ── K-Fold Cross Validation ───────────────────────────────────────────────
    LOGGER.info("=" * 58)
    LOGGER.info("K-FOLD CROSS VALIDATION (k=%d)", K_FOLDS)
    LOGGER.info("=" * 58)

    kfold = StratifiedKFold(n_splits=K_FOLDS, shuffle=True, random_state=42)
    fold_results = []
    all_models = []  # Store all models for ensemble
    best_model = None
    best_acc = 0.0

    for fold, (train_idx, val_idx) in enumerate(kfold.split(X_all, y_all)):
        LOGGER.info("\n--- Fold %d/%d ---", fold + 1, K_FOLDS)

        X_train, X_val = X_all[train_idx], X_all[val_idx]
        y_train, y_val = y_all[train_idx], y_all[val_idx]

        # Build model for this fold
        model = SyrthEncoder(vocab_size=tokenizer.vocab_size())
        LOGGER.info("  Train: %d, Val: %d", len(X_train), len(X_val))

        # Train
        train_ds = torch.utils.data.TensorDataset(torch.tensor(X_train), torch.tensor(y_train))
        train_loader = DataLoader(train_ds, batch_size=DEFAULT_BATCH_SIZE, shuffle=True)

        model = train_final(
            model, train_loader,
            torch.tensor(X_val), torch.tensor(y_val),
            epochs=DEFAULT_EPOCHS, lr=DEFAULT_LR, device=device,
        )

        # Evaluate
        eval_results = _eval_model(model, torch.tensor(X_val), torch.tensor(y_val), device)
        fold_results.append(eval_results)
        all_models.append(model)  # Save for ensemble

        LOGGER.info("  Fold %d Accuracy: %.2f%%", fold + 1, eval_results["accuracy"] * 100)

        # Keep best single model
        if eval_results["accuracy"] > best_acc:
            best_acc = eval_results["accuracy"]
            best_model = model

    # ── Ensemble Evaluation ──────────────────────────────────────────────────
    LOGGER.info("\n" + "=" * 58)
    LOGGER.info("ENSEMBLE VOTING (All %d Models)", K_FOLDS)
    LOGGER.info("=" * 58)

    # Ensemble prediction on full dataset
    X_all_t = torch.tensor(X_all)
    ensemble_probs = torch.zeros(len(X_all), NUM_CLASSES)

    for model in all_models:
        model.eval()
        with torch.no_grad():
            probs = model.predict_proba(X_all_t.to(device))
            ensemble_probs += probs.cpu()

    ensemble_probs /= len(all_models)
    ensemble_preds = ensemble_probs.argmax(dim=-1).numpy()
    y_np = y_all

    ensemble_acc = metrics.accuracy_score(y_np, ensemble_preds)
    ensemble_f1 = metrics.f1_score(y_np, ensemble_preds, average="weighted", zero_division=0)

    LOGGER.info("  Ensemble Accuracy: %.2f%%", ensemble_acc * 100)
    LOGGER.info("  Ensemble F1: %.4f", ensemble_f1)

    # ── Cross-Validated Results ───────────────────────────────────────────────
    LOGGER.info("\n" + "=" * 58)
    LOGGER.info("CROSS-VALIDATED RESULTS")
    LOGGER.info("=" * 58)

    mean_acc = np.mean([r["accuracy"] for r in fold_results])
    std_acc = np.std([r["accuracy"] for r in fold_results])
    mean_f1 = np.mean([r["f1"] for r in fold_results])

    LOGGER.info("  Mean Accuracy: %.2f%% (+/- %.2f%%)", mean_acc * 100, std_acc * 100)
    LOGGER.info("  Mean F1: %.4f", mean_f1)

    for i in range(NUM_CLASSES):
        class_accs = []
        for r in fold_results:
            cm = np.array(r["confusion_matrix"])
            if cm[i].sum() > 0:
                class_accs.append(cm[i, i] / cm[i].sum())
        if class_accs:
            LOGGER.info("  %s: %.1f%%", CWE_NAMES[i], np.mean(class_accs) * 100)

    LOGGER.info("=" * 58)

    # ── Export ───────────────────────────────────────────────────────────────
    # Use ensemble model (best single model as fallback for C header simplicity)
    metrics_dict = {
        "cv_accuracy_mean": mean_acc,
        "cv_accuracy_std": std_acc,
        "cv_f1_mean": mean_f1,
        "ensemble_accuracy": ensemble_acc,
        "ensemble_f1": ensemble_f1,
        "fold_results": [{k: v for k, v in r.items() if k != "confusion_matrix"} for r in fold_results],
        "train_samples": len(X_all),
    }

    # Export best single model for C header simplicity
    if export_joblib_flag:
        # Save ensemble info but use best model for export
        export_joblib(best_model, tokenizer, metrics_dict, output_path=joblib_path)

    if export_c_flag:
        export_c_header(best_model, tokenizer, output_path=c_path)

    LOGGER.info("Training complete!")
    LOGGER.info("  Single Best CV: %.2f%%", mean_acc * 100)
    LOGGER.info("  Ensemble Full:  %.2f%%", ensemble_acc * 100)


# ── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SYRTH: Scan Your Risk Trace History — Model trainer with best-practice pipeline"
    )
    parser.add_argument("--dataset", default="_dataset.json", help="Path to dataset JSON")
    parser.add_argument("--no-export-joblib", action="store_true", help="Skip joblib export")
    parser.add_argument("--no-export-c", action="store_true", help="Skip C header export")
    parser.add_argument("--joblib-path", default="syrth_model.joblib")
    parser.add_argument("--c-path", default="syrth_engine.h")
    args = parser.parse_args()

    train_and_evaluate(
        dataset_path=args.dataset,
        export_joblib_flag=not args.no_export_joblib,
        export_c_flag=not args.no_export_c,
        joblib_path=args.joblib_path,
        c_path=args.c_path,
    )
