"""Analyze ACTUAL misclassified blocks from the eval (description code blocks)."""
import json, sys, re, numpy as np
from collections import Counter
sys.path.insert(0, '.')
import _eval_meta_v2 as meta

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
CLASS_NAMES = {0: 'SQLi', 1: 'XSS', 2: 'PathTraversal', 3: 'OpenRedirect', 4: 'RCE'}

recs = json.load(open("_full_dataset_5class.json"))["records"]
misclassified = []
none_count = 0
total = 0

for r in recs:
    desc = r.get("description") or ""
    label = r["label"]
    for block in CODE_RE.findall(desc):
        block = block.strip()
        if len(block) < 20:
            continue
        total += 1
        pred, conf = meta.predict_meta(block, full_desc=desc)
        if pred is None:
            none_count += 1
            continue
        if pred != label:
            misclassified.append({
                'true': CLASS_NAMES[label],
                'pred': CLASS_NAMES[pred],
                'conf': conf,
                'block': block[:300],
                'tokens_len': len(block.split()),
            })

print(f"Total eval blocks: {total}")
print(f"Trace extraction failed (None): {none_count}")
print(f"Total classified: {total - none_count}")
print(f"Misclassified: {len(misclassified)}")
print()

# Confusion
confusion = Counter((m['true'], m['pred']) for m in misclassified)
for (true, pred), count in confusion.most_common():
    print(f"  {true} -> {pred}: {count}")

# Confidence analysis
confs = [m['conf'] for m in misclassified]
print(f"\nMisclassified confidence: avg={np.mean(confs):.3f}, min={min(confs):.3f}, max={max(confs):.3f}")

# High confidence misclassifications
high_conf = [m for m in misclassified if m['conf'] > 0.85]
print(f"High confidence (>0.85) misclassifications: {len(high_conf)}")

print(f"\n--- ALL misclassified blocks ---")
for i, m in enumerate(misclassified):
    print(f"\n[{i+1}] True: {m['true']}, Pred: {m['pred']}, Conf: {m['conf']:.3f}")
    print(f"    Block ({m['tokens_len']} words): {m['block'][:200]}...")
