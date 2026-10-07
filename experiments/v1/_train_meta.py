"""Stacking meta-learner: train logistic regression to combine ensemble + taint + rules."""
import json, sys, re, torch, joblib, numpy as np
from pathlib import Path
from collections import Counter
sys.path.insert(0, str(Path(__file__).parent))
import train_model as T
from _eval_ensemble import predict_ensemble, TOK, UNK, ensemble
from _rules import classify_by_rules
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]
NUM_CLASSES = 5

# --- Build meta-features from training data ---
train = json.load(open("_balanced_dataset.json"))["records"]
LOGGER = T.LOGGER

def extract_meta_features(tokens, label):
    """Extract features from tokens for meta-learning."""
    seq_ids = [TOK.vocab.get(t, 1) for t in tokens]
    pred, conf, votes = predict_ensemble(tokens, seq_ids)

    # Rule-based
    rule_result = classify_by_rules(tokens)
    rule_class = rule_result.predicted_class
    rule_conf = rule_result.confidence
    rule_votes_total = rule_result.votes.total()

    # Taint
    has_taint = any(t.startswith("tainted:") for t in tokens)

    features = []
    # [0-4] Ensemble per-class votes
    features.extend(float(votes[i]) for i in range(NUM_CLASSES))
    # [5] Ensemble confidence
    features.append(conf)
    # [6] Ensemble predicted class (one-hot)
    features.extend(1.0 if i == pred else 0.0 for i in range(NUM_CLASSES))
    # [11] Has taint
    features.append(1.0 if has_taint else 0.0)
    # [12] Rule confidence
    features.append(rule_conf)
    # [13] Rule votes total (normalized)
    features.append(min(rule_votes_total / 10.0, 1.0))
    # [14-18] Rule predicted class (one-hot)
    if rule_votes_total > 0:
        features.extend(1.0 if i == rule_class else 0.0 for i in range(NUM_CLASSES))
    else:
        features.extend([0.0] * NUM_CLASSES)
    # [19] Has any rule signal
    features.append(1.0 if rule_votes_total > 0 else 0.0)

    return features

# Extract features from ALL training data
LOGGER.info("Extracting meta-features from %d training records...", len(train))
X_meta = []
y_meta = []
n_skip = 0

for i, r in enumerate(train):
    tokens = r.get("tokens", [])
    if not tokens or len(tokens) < 1:
        n_skip += 1
        continue
    try:
        feats = extract_meta_features(tokens, r["label"])
    except Exception as e:
        n_skip += 1
        continue
    X_meta.append(feats)
    y_meta.append(r["label"])

X_meta = np.array(X_meta, dtype=np.float32)
y_meta = np.array(y_meta)
LOGGER.info("Meta-features shape: %s (%d skipped)", X_meta.shape, n_skip)

# --- Train meta-learner ---
# 3-fold CV to avoid overfitting
from sklearn.model_selection import StratifiedKFold
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

fold_scores = []
meta_models = []

for fold, (tr_idx, val_idx) in enumerate(skf.split(X_meta, y_meta)):
    X_tr, X_val = X_meta[tr_idx], X_meta[val_idx]
    y_tr, y_val = y_meta[tr_idx], y_meta[val_idx]

    # Logistic regression with class balancing
    lr = LogisticRegression(
        solver='lbfgs',
        max_iter=1000,
        class_weight='balanced',
        C=1.0,
        random_state=42 + fold,
    )
    lr.fit(X_tr, y_tr)
    preds = lr.predict(X_val)
    acc = accuracy_score(y_val, preds)
    f1 = f1_score(y_val, preds, average='weighted')
    fold_scores.append((acc, f1))
    meta_models.append(lr)
    LOGGER.info("  Fold %d: acc=%.3f, f1=%.3f", fold, acc, f1)

LOGGER.info("CV scores: acc=%.3f ± %.3f, f1=%.3f ± %.3f",
            np.mean([s[0] for s in fold_scores]), np.std([s[0] for s in fold_scores]),
            np.mean([s[1] for s in fold_scores]), np.std([s[1] for s in fold_scores]))

# Train final meta-model on all data
final_lr = LogisticRegression(
    solver='lbfgs',
    max_iter=1000,
    class_weight='balanced',
    C=1.0,
    random_state=42,
)
final_lr.fit(X_meta, y_meta)
train_pred = final_lr.predict(X_meta)
LOGGER.info("Final meta-model training acc: %.3f", accuracy_score(y_meta, train_pred))

# --- Save meta-learner ---
meta_bundle = {
    "syrth_version": "1.3.0",
    "meta_model": {
        "coef": final_lr.coef_,
        "intercept": final_lr.intercept_,
        "classes": final_lr.classes_.tolist(),
    },
    "meta_config": {
        "num_features": X_meta.shape[1],
        "num_classes": NUM_CLASSES,
        "feature_names": [
            "vote_0", "vote_1", "vote_2", "vote_3", "vote_4",
            "ensemble_conf",
            "pred_0", "pred_1", "pred_2", "pred_3", "pred_4",
            "has_taint",
            "rule_conf",
            "rule_votes_norm",
            "rule_pred_0", "rule_pred_1", "rule_pred_2", "rule_pred_3", "rule_pred_4",
            "has_rule_signal",
        ],
    },
    "cv_scores": fold_scores,
}
joblib.dump(meta_bundle, "syrth_meta.joblib", compress=3)
LOGGER.info("Meta-learner saved → syrth_meta.joblib")
