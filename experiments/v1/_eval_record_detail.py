"""Detailed breakdown: 1-block vs multi-block records."""
import json, re, sys
from collections import Counter, defaultdict
sys.path.insert(0, '.')
import _eval_meta_v2 as meta

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
CLASS_NAMES = {0: 'SQLi', 1: 'XSS', 2: 'PathTraversal', 3: 'OpenRedirect', 4: 'RCE'}

recs = json.load(open("_full_dataset_5class.json"))["records"]

one_block = []
multi_block = []

for r in recs:
    desc = r.get("description") or ""
    label = r["label"]
    blocks = []
    for block in CODE_RE.findall(desc):
        block = block.strip()
        if len(block) < 20:
            continue
        pred, conf = meta.predict_meta(block, full_desc=desc)
        if pred is not None:
            blocks.append({"pred": pred, "conf": conf})
    if not blocks:
        continue
    if len(blocks) == 1:
        one_block.append({"label": label, "pred": blocks[0]["pred"], "conf": blocks[0]["conf"]})
    else:
        weighted = defaultdict(float)
        for b in blocks:
            weighted[b["pred"]] += b["conf"]
        agg_pred = max(weighted, key=weighted.get)
        multi_block.append({"label": label, "agg_pred": agg_pred, "block_preds": [b["pred"] for b in blocks], "n_blocks": len(blocks)})

# 1-block records
ob_correct = sum(1 for r in one_block if r["pred"] == r["label"])
print(f"1-block records: {len(one_block)}")
print(f"  Accuracy: {100*ob_correct/len(one_block):.1f}% ({ob_correct}/{len(one_block)})")
ob_per_class = Counter()
ob_per_class_c = Counter()
for r in one_block:
    ob_per_class[r["label"]] += 1
    if r["pred"] == r["label"]:
        ob_per_class_c[r["label"]] += 1
for lab in sorted(ob_per_class):
    n = ob_per_class[lab]
    c = ob_per_class_c.get(lab, 0)
    print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")

# Multi-block records
mb_correct = sum(1 for r in multi_block if r["agg_pred"] == r["label"])
print(f"\nMulti-block records: {len(multi_block)}")
print(f"  Accuracy (weighted vote): {100*mb_correct/len(multi_block):.1f}% ({mb_correct}/{len(multi_block)})")
mb_per_class = Counter()
mb_per_class_c = Counter()
for r in multi_block:
    mb_per_class[r["label"]] += 1
    if r["agg_pred"] == r["label"]:
        mb_per_class_c[r["label"]] += 1
for lab in sorted(mb_per_class):
    n = mb_per_class[lab]
    c = mb_per_class_c.get(lab, 0)
    print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")

# Which multi-block records were fixed by aggregation?
print(f"\n--- Records FIXED by aggregation (wrong block-level, right record-level) ---")
fixed = []
for r in multi_block:
    block_majority = Counter(r["block_preds"]).most_common(1)[0][0]
    if block_majority != r["label"] and r["agg_pred"] == r["label"]:
        fixed.append(r)
print(f"Fixed: {len(fixed)} records")
for r in fixed[:10]:
    block_majority = Counter(r["block_preds"]).most_common(1)[0][0]
    print(f"  True: {CLASS_NAMES[r['label']]}, Block majority: {CLASS_NAMES[block_majority]}, Agg: {CLASS_NAMES[r['agg_pred']]}, Blocks: {r['n_blocks']}, Preds: {r['block_preds']}")

# Which records were HURT by aggregation?
print(f"\n--- Records HURT by aggregation (right block-level, wrong record-level) ---")
hurt = []
for r in multi_block:
    block_majority = Counter(r["block_preds"]).most_common(1)[0][0]
    if block_majority == r["label"] and r["agg_pred"] != r["label"]:
        hurt.append(r)
print(f"Hurt: {len(hurt)} records")
for r in hurt[:10]:
    block_majority = Counter(r["block_preds"]).most_common(1)[0][0]
    print(f"  True: {CLASS_NAMES[r['label']]}, Block majority: {CLASS_NAMES[block_majority]}, Agg: {CLASS_NAMES[r['agg_pred']]}, Blocks: {r['n_blocks']}, Preds: {r['block_preds']}")
