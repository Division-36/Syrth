"""Code-only ablation: prove whether SYRTH's accuracy comes from real code
signal or from advisory description text.

We take the SAME train/test records used in production, but DROP every
description-derived feature (txt:, txt2:, severity:, framework:, code:) and keep
ONLY the code/taint tokens that syrth_scan.py actually emits at inference
(def:/arg:/sink:/call:/ret:/@/meta:/flow:/tainted:). We retrain a fresh model
(on a TEMP path, never overwriting syrth_model.joblib) and measure:

  * held-out accuracy with code-only features  (vs 94.2% description-inclusive)
  * real-code accuracy via collect.py on real CVE code blocks (vs 69.1%)

If code-only stays well above the 20% random floor (~53% RCE majority), the
model is a genuine code analyzer. If it collapses, the headline number was
mostly description-driven.
"""
import json
import sys
import numpy as np
import torch
from pathlib import Path
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).parent))
from train_model import (
    SyrthEncoder, SyrthTokenizer, NUM_CLASSES,
    DEFAULT_EMBED_DIM, DEFAULT_FFN_DIM, DEFAULT_DROPOUT,
    DEFAULT_BATCH_SIZE, DEFAULT_EPOCHS, DEFAULT_LR, LABEL_SMOOTHING,
    EARLY_STOP_PATIENCE, train_final, LOGGER,
)
import collect

CODE_PREFIX = {"def", "arg", "sink", "call", "ret", "meta", "flow", "tainted"}
CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]


def code_only(tokens):
    out = []
    for t in tokens:
        if t.startswith("@"):
            out.append(t)
        else:
            pre = t.split(":", 1)[0]
            if pre in CODE_PREFIX:
                out.append(t)
    return out


def load_code_only(path):
    recs = json.load(open(path, encoding="utf-8"))["records"]
    out = []
    dropped = 0
    for r in recs:
        toks = code_only(r.get("tokens", []))
        if toks:
            rr = dict(r)
            rr["tokens"] = toks
            out.append(rr)
        else:
            dropped += 1
    return out, dropped


def evaluate(model, tokenizer, records):
    model.eval()
    correct = total = 0
    import torch.nn.functional as F
    for r in records:
        x = torch.tensor([[tokenizer.vocab.get(t, 0) for t in r["tokens"]]])
        with torch.no_grad():
            p = int(F.softmax(model(x), 1)[0].argmax())
        total += 1
        correct += (p == r["label"])
    return correct / total if total else 0.0


def real_code_accuracy(model, tokenizer):
    import re
    import torch.nn.functional as F
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
    total = correct = 0
    for r in recs:
        desc = r.get("description") or ""
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            try:
                ft = collect.extract_traces_from_source(block, label="x")
            except Exception:
                continue
            seq = []
            for fn in ft.functions:
                s = fn.to_token_sequence()
                if s:
                    seq.extend(s)
            if not seq:
                continue
            x = torch.tensor([[tokenizer.vocab.get(t, 0) for t in seq]])
            with torch.no_grad():
                p = int(F.softmax(model(x), 1)[0].argmax())
            total += 1
            correct += (p == r["label"])
    return (correct / total if total else 0.0), total


def main():
    train, d1 = load_code_only("_balanced_dataset.json")
    test, d2 = load_code_only("testingMassiveDataset.json")
    print(f"[ablation] train records (code-only): {len(train)} ({d1} dropped, no code tokens)")
    print(f"[ablation] test  records (code-only): {len(test)} ({d2} dropped)")

    tokenizer = SyrthTokenizer()
    tokenizer.fit([r["tokens"] for r in train])
    print(f"[ablation] code-only vocab: {tokenizer.vocab_size()} tokens")
    # majority baseline
    counts = np.bincount([r["label"] for r in test], minlength=NUM_CLASSES)
    print(f"[ablation] majority-class baseline on test: {100*counts.max()/counts.sum():.1f}% "
          f"(random 5-class = 20%)")

    X = np.array([tokenizer.encode(r["tokens"]) for r in train])
    y = np.array([r["label"] for r in train])
    Xt, yt = torch.tensor(X, dtype=torch.long), torch.tensor(y, dtype=torch.long)
    n_val = max(1, int(0.1 * len(train)))
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(train))
    val_idx, tr_idx = idx[:n_val], idx[n_val:]
    w = torch.tensor(1.0 / np.maximum(np.bincount(y, minlength=NUM_CLASSES).astype(float), 1),
                     dtype=torch.float32)
    w = w / w.mean()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = SyrthEncoder(vocab_size=tokenizer.vocab_size())
    tl = DataLoader(TensorDataset(Xt[tr_idx], yt[tr_idx]), batch_size=DEFAULT_BATCH_SIZE, shuffle=True)
    model = train_final(model, tl, Xt[val_idx], yt[val_idx], epochs=DEFAULT_EPOCHS,
                        lr=DEFAULT_LR, device=device, class_weight=w)

    held = evaluate(model, tokenizer, test)
    rc, n = real_code_accuracy(model, tokenizer)
    print(f"\n[ablation] HELD-OUT accuracy (code-only features): {100*held:.1f}%")
    print(f"[ablation] REAL-CODE accuracy (real CVE blocks):      {100*rc:.1f}%  (n={n})")
    print(f"[reference] production model: held-out 94.2% (desc-inclusive), real-code 69.1%")


if __name__ == "__main__":
    main()
