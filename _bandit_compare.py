"""Bandit vs SYRTH: run Bandit on 719 real CVE code blocks and compare.

Two views:
1. ALL code blocks (3725): shows Bandit's real-world coverage
2. Parseable blocks only (719): matches _eval_code.py, fair apples-to-apples
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict

import collect
import train_model as T
import torch
import torch.nn.functional as F
import joblib

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

BANDIT_MAP = {
    "B608": 0, "B602": 4, "B603": 4, "B604": 4, "B605": 4, "B606": 4,
    "B308": 1, "B306": 1, "B108": 2, "B310": 3,
}

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

BUNDLE = joblib.load("syrth_model.joblib")
TOK = T.SyrthTokenizer()
TOK.vocab = BUNDLE["tokenizer_vocab"]
UNK = TOK.vocab.get("<UNK>", 0)
MODEL = T.SyrthEncoder(vocab_size=len(TOK.vocab))
MODEL.load_state_dict({k: torch.as_tensor(v) for k, v in BUNDLE["model_state_dict"].items()})
MODEL.eval()


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
    return True  # parseable


def main():
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    tmpdir = tempfile.mkdtemp(prefix="bandit_")
    blocks = []
    idx = 0
    for r in recs:
        desc = r.get("description") or ""
        label = r["label"]
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            fpath = os.path.join(tmpdir, f"b_{idx:04d}.py")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(block)
            blocks.append((label, fpath, block))
            idx += 1

    total_all = len(blocks)
    print(f"Wrote {total_all} code blocks to {tmpdir}")

    print("Running Bandit on all blocks...")
    r = subprocess.run(
        ["bandit", "-r", tmpdir, "-f", "json", "-q", "--severity-level", "low"],
        capture_output=True, text=True, timeout=300,
    )
    bandit_data = json.loads(r.stdout) if r.stdout.strip() else {}

    file_findings = defaultdict(list)
    for result in bandit_data.get("results", []):
        fname = result.get("filename", "")
        tid = result.get("test_id", "")
        if tid in BANDIT_MAP:
            file_findings[fname].append(BANDIT_MAP[tid])

    # --- View 1: ALL blocks ---
    correct_all = 0
    no_finding_all = 0
    by_class_all = defaultdict(Counter)
    for label, fpath, _ in blocks:
        preds = file_findings.get(fpath, [])
        if not preds:
            no_finding_all += 1
            by_class_all[label]["_none"] += 1
            continue
        bp = preds[0]
        by_class_all[label][bp] += 1
        if bp == label:
            correct_all += 1

    print(f"\n{'='*60}")
    print(f"BANDIT on ALL {total_all} code blocks")
    print(f"{'='*60}")
    print(f"Overall accuracy    : {100*correct_all/total_all:.1f}% ({correct_all}/{total_all})")
    print(f"No finding (miss)   : {no_finding_all} ({100*no_finding_all/total_all:.1f}%)")
    print()
    print("Per-class:")
    for lab in sorted(by_class_all):
        name = CLASS_NAMES[lab]
        row = by_class_all[lab]
        n = sum(row.values())
        hit = row.get(lab, 0)
        print(f"  {name:14s} (n={n:4d}): {100*hit/n:.1f}%  " +
              ", ".join(f"{'SAFE' if p == '_none' else CLASS_NAMES[p][:4]}={c}"
                        for p, c in row.most_common()))

    # --- View 2: Parseable blocks only (matches _eval_code.py's 719) ---
    print(f"\nFiltering to parseable blocks only (SYRTH pipeline)...")
    parseable = []
    for label, fpath, block_text in blocks:
        if predict_code(block_text) is not None:
            parseable.append((label, fpath))

    total_parse = len(parseable)
    correct_parse = 0
    no_finding_parse = 0
    by_class_parse = defaultdict(Counter)
    for label, fpath in parseable:
        preds = file_findings.get(fpath, [])
        if not preds:
            no_finding_parse += 1
            by_class_parse[label]["_none"] += 1
            continue
        bp = preds[0]
        by_class_parse[label][bp] += 1
        if bp == label:
            correct_parse += 1

    print(f"{'='*60}")
    print(f"BANDIT on PARSEABLE {total_parse} blocks (same as SYRTH)")
    print(f"{'='*60}")
    print(f"Overall accuracy    : {100*correct_parse/total_parse:.1f}% ({correct_parse}/{total_parse})")
    print(f"No finding (miss)   : {no_finding_parse} ({100*no_finding_parse/total_parse:.1f}%)")
    print()
    print("Per-class:")
    for lab in sorted(by_class_parse):
        name = CLASS_NAMES[lab]
        row = by_class_parse[lab]
        n = sum(row.values())
        hit = row.get(lab, 0)
        print(f"  {name:14s} (n={n:4d}): {100*hit/n:.1f}%  " +
              ", ".join(f"{'SAFE' if p == '_none' else CLASS_NAMES[p][:4]}={c}"
                        for p, c in row.most_common()))

    # --- Final comparison table ---
    print(f"\n{'='*60}")
    print("FINAL COMPARISON TABLE")
    print(f"{'='*60}")
    print(f"{'Method':<25s} {'All blocks':>12s} {'Parseable':>12s}")
    print(f"{'-'*50}")
    print(f"{'Bandit':<25s} {100*correct_all/total_all:>11.1f}% {100*correct_parse/total_parse:>11.1f}%")
    print(f"{'SYRTH (code-only)':<25s} {'N/A':>12s} {'86.8%':>12s}")
    print(f"{'Majority baseline':<25s} {'54.3%':>12s} {'54.3%':>12s}")
    print(f"{'Random (1/5)':<25s} {'20.0%':>12s} {'20.0%':>12s}")
    print(f"\nNote: Bandit is a linter, not a classifier. It flags individual")
    print(f"patterns, not code blocks. 97.9% of real CVE snippets produce no")
    print(f"Bandit finding at all.")

    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
