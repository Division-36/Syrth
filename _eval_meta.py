"""Evaluate stacking meta-learner on real 719 blocks."""
import json, re, collect, torch, joblib, numpy as np
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
import train_model as T
from _eval_ensemble import predict_ensemble, TOK, UNK, ensemble
from _rules import classify_by_rules
from sklearn.linear_model import LogisticRegression

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]
NUM_CLASSES = 5

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

# Load meta-learner
meta_bundle = joblib.load("syrth_meta.joblib")
meta_lr = LogisticRegression(solver='lbfgs', max_iter=1000, class_weight='balanced', C=1.0, random_state=42)
meta_lr.coef_ = np.array(meta_bundle["meta_model"]["coef"])
meta_lr.intercept_ = np.array(meta_bundle["meta_model"]["intercept"])
meta_lr.classes_ = np.array(meta_bundle["meta_model"]["classes"])
meta_lr.n_features_in_ = meta_bundle["meta_config"]["num_features"]

def extract_meta_features(tokens):
    seq_ids = [TOK.vocab.get(t, 1) for t in tokens]
    pred, conf, votes = predict_ensemble(tokens, seq_ids)

    rule_result = classify_by_rules(tokens)
    rule_class = rule_result.predicted_class
    rule_conf = rule_result.confidence
    rule_votes_total = rule_result.votes.total()

    has_taint = any(t.startswith("tainted:") for t in tokens)

    feats = []
    feats.extend(float(votes[i]) for i in range(NUM_CLASSES))
    feats.append(conf)
    feats.extend(1.0 if i == pred else 0.0 for i in range(NUM_CLASSES))
    feats.append(1.0 if has_taint else 0.0)
    feats.append(rule_conf)
    feats.append(min(rule_votes_total / 10.0, 1.0))
    if rule_votes_total > 0:
        feats.extend(1.0 if i == rule_class else 0.0 for i in range(NUM_CLASSES))
    else:
        feats.extend([0.0] * NUM_CLASSES)
    feats.append(1.0 if rule_votes_total > 0 else 0.0)
    return np.array(feats, dtype=np.float32).reshape(1, -1)


def predict_meta(src):
    """Predict using meta-learner."""
    try:
        ft = collect.extract_traces_from_source(src, label="x")
    except:
        return None, None

    seq = []
    taint_hits = []
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            seq.extend(s)
            for t in s:
                if t.startswith("tainted:"):
                    sink_name = t.split(":", 1)[1]
                    if sink_name in ("execute", "cursor.execute", "raw", "extra"):
                        taint_hits.append(0)
                    elif sink_name in ("render", "HttpResponse", "mark_safe", "render_template"):
                        taint_hits.append(1)
                    elif sink_name in ("open", "send_file"):
                        taint_hits.append(2)
                    elif sink_name in ("redirect", "HttpResponseRedirect", "RedirectResponse"):
                        taint_hits.append(3)
                    elif sink_name in ("os.system", "subprocess.run", "subprocess.Popen", "eval", "exec", "popen"):
                        taint_hits.append(4)

    if not seq:
        return None, None

    # Taint highest precision
    if taint_hits:
        return Counter(taint_hits).most_common(1)[0][0], 0.90

    # Meta-learner
    feats = extract_meta_features(seq)
    proba = meta_lr.predict_proba(feats)[0]
    pred = int(meta_lr.predict(feats)[0])
    conf = float(proba[pred])
    return pred, conf


def main():
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    total = 0
    correct = 0
    per_class = Counter()
    per_class_correct = Counter()
    per_class_errors = Counter()

    for r in recs:
        desc = r.get("description") or ""
        label = r["label"]
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            pred, conf = predict_meta(block)
            if pred is None:
                continue
            total += 1
            per_class[label] += 1
            if pred == label:
                correct += 1
                per_class_correct[label] += 1
            else:
                per_class_errors[(CLASS_NAMES[label], CLASS_NAMES[pred])] += 1

    print(f"\n{'='*58}")
    print(f"META-LEARNER (stacking: ensemble + taint + rules)")
    print(f"{'='*58}")
    print(f"Total blocks     : {total}")
    print(f"Overall accuracy : {100*correct/total:.1f}% ({correct}/{total})")
    print()
    print("By class:")
    for lab in sorted(per_class):
        n = per_class[lab]
        c = per_class_correct.get(lab, 0)
        print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")
    print()
    print("Top confusions:")
    for (t, p), cnt in per_class_errors.most_common(10):
        print(f"  {t:14s} -> {p:14s}: {cnt}")
    print(f"\n{'='*58}")
    print(f"{'Method':<25s} {'Accuracy':>10s}")
    print(f"{'-'*37}")
    print(f"{'Meta-learner':<25s} {100*correct/total:>9.1f}%")
    print(f"{'Ensemble v1':<25s} {'89.2':>9s}%")
    print(f"{'Best single ML':<25s} {'87.2':>9s}%")


if __name__ == "__main__":
    main()
