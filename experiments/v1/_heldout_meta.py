"""Measure meta-learner held-out accuracy."""
import json, numpy as np, sys, joblib
sys.path.insert(0, '.')
from _eval_meta import meta_lr, extract_meta_features

test = json.load(open("testingMassiveDataset.json"))["records"]
correct = 0
for r in test:
    tokens = r.get("tokens", [])
    if not tokens or len(tokens) < 1:
        continue
    feats = extract_meta_features(tokens)
    pred = int(meta_lr.predict(feats)[0])
    if pred == r["label"]:
        correct += 1

print(f"Held-out meta-learner: {100*correct/len(test):.1f}% ({correct}/{len(test)})")
print(f"Held-out single model: 70.0% (best prior)")
