"""Evaluate rule-based classifier on 719 real CVE code blocks."""
import json, re, collect
from collections import Counter
from _rules import classify_by_rules, CLASS_NAMES

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
recs = json.load(open("_full_dataset_5class.json"))["records"]

total = 0
correct = 0
per_class = Counter()
per_class_correct = Counter()
by_strategy = Counter()

for r in recs:
    desc = r.get("description") or ""
    label = r["label"]
    for block in CODE_RE.findall(desc):
        block = block.strip()
        if len(block) < 20:
            continue
        try:
            ft = collect.extract_traces_from_source(block, label="x")
        except:
            continue
        seq = []
        for fn in ft.functions:
            s = fn.to_token_sequence()
            if s:
                seq.extend(s)
        if not seq:
            continue

        total += 1
        result = classify_by_rules(seq)
        pred = result.predicted_class
        per_class[label] += 1
        if pred == label:
            correct += 1
            per_class_correct[label] += 1
        # Track which signal drove the decision
        top_reason = result.reasons[0].split(":")[0] if result.reasons else "none"
        by_strategy[top_reason] += 1

print(f"=== RULE-BASED CLASSIFIER ===")
print(f"Total: {total}")
print(f"Accuracy: {100*correct/total:.1f}% ({correct}/{total})")
print()
print("By class:")
for lab in sorted(per_class):
    n = per_class[lab]
    c = per_class_correct.get(lab, 0)
    print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")
print()
print("By signal:")
for strat, cnt in by_strategy.most_common():
    print(f"  {strat:8s}: {100*cnt/total:.1f}% ({cnt})")
