"""
Record-level aggregation: classify all blocks per record, aggregate predictions.
Tests multiple aggregation methods and compares with block-level accuracy.
"""
import json, re, sys, numpy as np
from collections import Counter, defaultdict
sys.path.insert(0, '.')
import _eval_meta_v2 as meta

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
CLASS_NAMES = {0: 'SQLi', 1: 'XSS', 2: 'PathTraversal', 3: 'OpenRedirect', 4: 'RCE'}
NUM_CLASSES = 5

recs = json.load(open("_full_dataset_5class.json"))["records"]

# ============================================================
# Step 1: Get per-block predictions for all records
# ============================================================
record_data = []  # list of {label, blocks: [{pred, conf, block}]}

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
            blocks.append({"pred": pred, "conf": conf, "block": block[:100]})
    if blocks:
        record_data.append({"label": label, "blocks": blocks})

print(f"Records with predictions: {len(record_data)}")
print(f"Total blocks: {sum(len(rd['blocks']) for rd in record_data)}")

# ============================================================
# Step 2: Block-level baseline
# ============================================================
block_correct = 0
block_total = 0
for rd in record_data:
    for b in rd["blocks"]:
        block_total += 1
        if b["pred"] == rd["label"]:
            block_correct += 1
print(f"\nBlock-level baseline: {100*block_correct/block_total:.1f}% ({block_correct}/{block_total})")

# ============================================================
# Step 3: Aggregation methods
# ============================================================
def aggregate_majority(block_preds):
    """Majority vote: most common prediction wins."""
    votes = Counter(b["pred"] for b in block_preds)
    return votes.most_common(1)[0][0]

def aggregate_weighted(block_preds):
    """Weighted vote: confidence-weighted prediction."""
    weighted = defaultdict(float)
    for b in block_preds:
        weighted[b["pred"]] += b["conf"]
    return max(weighted, key=weighted.get)

def aggregate_taint_priority(block_preds, block_details):
    """Taint priority: if any block has taint hit (conf=0.90), use that."""
    for i, b in enumerate(block_details):
        if b["conf"] == 0.90:  # taint rule confidence
            return block_preds[i]
    return aggregate_majority(block_details)

def aggregate_max_conf(block_preds, block_details):
    """Max confidence: prediction with highest confidence wins."""
    best_idx = max(range(len(block_details)), key=lambda i: block_details[i]["conf"])
    return block_preds[best_idx]

def aggregate_softmax(block_preds, block_details):
    """Softmax average: average probabilities, then argmax."""
    probas = np.zeros(NUM_CLASSES)
    for b in block_details:
        # Convert confidence to approximate probability distribution
        p = np.zeros(NUM_CLASSES)
        p[b["pred"]] = b["conf"]
        # Spread remaining probability evenly
        remaining = (1.0 - b["conf"]) / (NUM_CLASSES - 1)
        for i in range(NUM_CLASSES):
            if i != b["pred"]:
                p[i] = remaining
        probas += p
    return int(np.argmax(probas / len(block_details)))

# ============================================================
# Step 4: Evaluate each method
# ============================================================
methods = {
    "majority_vote": lambda preds, details: aggregate_majority(details),
    "weighted_vote": lambda preds, details: aggregate_weighted(details),
    "taint_priority": lambda preds, details: aggregate_taint_priority(preds, details),
    "max_confidence": lambda preds, details: aggregate_max_conf(preds, details),
    "softmax_avg": lambda preds, details: aggregate_softmax(preds, details),
}

print(f"\n{'='*60}")
print(f"RECORD-LEVEL AGGREGATION RESULTS")
print(f"{'='*60}")
print(f"{'Method':<25s} {'Accuracy':>10s} {'Correct':>10s} {'Total':>8s}")
print(f"{'-'*55}")

best_method = None
best_acc = 0

for name, method in methods.items():
    correct = 0
    total = 0
    per_class_c = Counter()
    per_class_t = Counter()
    errors = Counter()

    for rd in record_data:
        label = rd["label"]
        preds = [b["pred"] for b in rd["blocks"]]
        details = rd["blocks"]
        agg_pred = method(preds, details)

        total += 1
        per_class_t[label] += 1
        if agg_pred == label:
            correct += 1
            per_class_c[label] += 1
        else:
            errors[(CLASS_NAMES[label], CLASS_NAMES[agg_pred])] += 1

    acc = 100 * correct / total
    print(f"{name:<25s} {acc:>9.1f}% {correct:>8d}/{total}")

    if acc > best_acc:
        best_acc = acc
        best_method = name
        best_errors = errors
        best_per_class_c = per_class_c
        best_per_class_t = per_class_t

print(f"\n{'='*60}")
print(f"BEST: {best_method} ({best_acc:.1f}%)")
print(f"{'='*60}")

# Per-class breakdown of best method
print(f"\nPer-class ({best_method}):")
for lab in sorted(best_per_class_t):
    n = best_per_class_t[lab]
    c = best_per_class_c.get(lab, 0)
    print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")

print(f"\nTop confusions ({best_method}):")
for (t, p), cnt in best_errors.most_common(10):
    print(f"  {t:14s} -> {p:14s}: {cnt}")

# ============================================================
# Step 5: Compare block-level vs record-level per-class
# ============================================================
print(f"\n{'='*60}")
print(f"COMPARISON: Block-level vs Record-level ({best_method})")
print(f"{'='*60}")
print(f"{'Class':<14s} {'Block':>10s} {'Record':>10s} {'Delta':>8s}")
print(f"{'-'*44}")

for lab in range(NUM_CLASSES):
    # Block-level
    bc = sum(1 for rd in record_data if rd["label"] == lab for b in rd["blocks"] if b["pred"] == lab)
    bt = sum(1 for rd in record_data if rd["label"] == lab for _ in rd["blocks"])
    b_acc = 100 * bc / bt if bt > 0 else 0

    # Record-level
    r_acc = 100 * best_per_class_c.get(lab, 0) / best_per_class_t[lab] if best_per_class_t[lab] > 0 else 0

    delta = r_acc - b_acc
    print(f"  {CLASS_NAMES[lab]:12s} {b_acc:>9.1f}% {r_acc:>9.1f}% {delta:>+7.1f}%")

# ============================================================
# Step 6: Multi-block records only
# ============================================================
print(f"\n{'='*60}")
print(f"MULTI-BLOCK RECORDS ONLY (2+ blocks)")
print(f"{'='*60}")
multi = [rd for rd in record_data if len(rd["blocks"]) >= 2]
print(f"Records: {len(multi)}")

for name, method in methods.items():
    correct = sum(1 for rd in multi if method([b["pred"] for b in rd["blocks"]], rd["blocks"]) == rd["label"])
    total = len(multi)
    print(f"  {name:<25s}: {100*correct/total:.1f}% ({correct}/{total})")
