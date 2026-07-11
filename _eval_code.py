"""Real-code evaluation: scan ACTUAL Python code from real CVE advisories.

Extracts fenced python code blocks from real OSV advisory descriptions,
runs them through the SAME pipeline syrth_scan.py uses (collect.py ->
SyrthTokenizer -> SyrthEncoder), and tallies predicted class vs the
advisory's true CWE. This tests the scanner on real vulnerability *code*,
not on advisory text descriptions.
"""
import json
import re
import sys
import tempfile
from pathlib import Path

import torch
import torch.nn.functional as F
import joblib
import collect
import train_model as T
import harvester as H

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

BUNDLE = joblib.load("syrth_model.joblib")
TOK = T.SyrthTokenizer()
TOK.vocab = BUNDLE["tokenizer_vocab"]
UNK = TOK.vocab.get("<UNK>", 0)
MODEL = T.SyrthEncoder(vocab_size=len(TOK.vocab))
MODEL.load_state_dict({k: torch.as_tensor(v) for k, v in BUNDLE["model_state_dict"].items()})
MODEL.eval()

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)


def predict_code(src: str):
    try:
        ft = collect.extract_traces_from_source(src, label="x")
    except Exception:
        return None
    seq = []
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            seq.extend(s)
    if not seq:
        return None
    x = torch.tensor([[TOK.vocab.get(t, UNK) for t in seq]])
    with torch.no_grad():
        out = MODEL(x)
    probs = F.softmax(out, 1)[0]
    return int(probs.argmax()), float(probs.max())


def main():
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    from collections import Counter, defaultdict
    total = 0
    correct = 0
    conf_correct = []
    conf_wrong = []
    per_true = defaultdict(Counter)
    by_class_n = Counter()
    for r in recs:
        desc = r.get("description") or ""
        label = r["label"]
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            pred = predict_code(block)
            if pred is None:
                continue
            p, conf = pred
            total += 1
            by_class_n[label] += 1
            per_true[label][p] += 1
            if p == label:
                correct += 1
                conf_correct.append(conf)
            else:
                conf_wrong.append(conf)

    print(f"\n=== REAL-CODE EVAL (actual CVE code blocks) ===")
    print(f"Scanned code samples : {total}")
    if total == 0:
        print("No parseable code blocks found.")
        return
    print(f"Overall accuracy    : {100*correct/total:.1f}%")
    print("\nPer true class -> predicted distribution:")
    for lab in sorted(by_class_n):
        name = CLASS_NAMES[lab]
        row = per_true[lab]
        print(f"  {name:14s} (n={by_class_n[lab]:4d}): " +
              ", ".join(f"{CLASS_NAMES[p][:4]}={c}" for p, c in row.most_common()))
    if conf_correct:
        print(f"\nMean confidence on CORRECT : {sum(conf_correct)/len(conf_correct):.2f}")
    if conf_wrong:
        print(f"Mean confidence on WRONG   : {sum(conf_wrong)/len(conf_wrong):.2f}")


if __name__ == "__main__":
    main()
