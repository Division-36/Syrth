"""Ensemble: weighted vote of 5 ML models. Rules as fallback only."""
import json, re, collect, torch, joblib
import torch.nn.functional as F
import train_model as T
from collections import Counter
from _rules import classify_by_rules, CLASS_NAMES as RN, CLASS_SQLI, CLASS_XSS, CLASS_PATH, CLASS_REDIR, CLASS_RCE

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

bundle = joblib.load("syrth_ensemble.joblib")
TOK = T.SyrthTokenizer()
TOK.vocab = bundle["tokenizer_vocab"]
UNK = TOK.vocab.get("<UNK>", 0)

# Load models with weights = held-out accuracy
ensemble = []
for name, mdata in bundle["ensemble"].items():
    cfg = mdata["config"]
    model = T.SyrthEncoder(
        vocab_size=mdata["model_config"]["vocab_size"],
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg["ffn_dim"],
        num_classes=T.NUM_CLASSES,
        aux_dim=0,
    )
    state = {k: torch.as_tensor(v) for k, v in mdata["state_dict"].items()}
    model.load_state_dict(state)
    model.eval()
    ensemble.append((model, max(mdata["heldout_acc"], 0.5)))  # weight

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

TAINT_MAP = {
    "tainted:execute": 0, "tainted:cursor.execute": 0,
    "tainted:raw": 0, "tainted:extra": 0,
    "tainted:render": 1, "tainted:HttpResponse": 1, "tainted:mark_safe": 1,
    "tainted:open": 2, "tainted:send_file": 2,
    "tainted:os.system": 4, "tainted:subprocess.run": 4,
    "tainted:subprocess.Popen": 4, "tainted:eval": 4, "tainted:exec": 4,
    "tainted:redirect": 3, "tainted:HttpResponseRedirect": 3,
    "tainted:RedirectResponse": 3,
}


def predict_ensemble(tokens):
    """Predict using weighted voting from 5 ML models."""
    seq_ids = [TOK.vocab.get(t, UNK) for t in tokens]
    x = torch.tensor([seq_ids])
    with torch.no_grad():
        votes = torch.zeros(5)
        for model, weight in ensemble:
            probs = model.predict_proba(x)[0]
            votes += probs * weight
    pred = int(votes.argmax())
    conf = float(votes[pred] / votes.sum()) if votes.sum() > 0 else 0.0
    return pred, conf, votes


def predict_mixed(src):
    """Taint > weighted ML > rules fallback."""
    try:
        ft = collect.extract_traces_from_source(src, label="x")
    except:
        return None, None, None

    seq = []
    taint_classes = []
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            seq.extend(s)
            for t in s:
                if t.startswith("tainted:") and t in TAINT_MAP:
                    taint_classes.append(TAINT_MAP[t])

    if not seq:
        return None, None, None

    # Level 1: Taint (highest precision)
    if taint_classes:
        return Counter(taint_classes).most_common(1)[0][0], 0.90, "taint"

    # Level 2: Weighted ML ensemble
    pred, conf, votes = predict_ensemble(seq)

    # Level 3: Rules as fallback if ML is weak
    if conf < 0.4:
        rule_result = classify_by_rules(seq)
        if rule_result.votes.total() > 0 and rule_result.confidence > 0.7:
            return rule_result.predicted_class, rule_result.confidence, "rules"

    if conf < 0.25:
        return CLASS_RCE, 0.2, "fallback"

    return pred, conf, "ml"


def main():
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    total = 0
    correct = 0
    by_strategy = Counter()
    per_class = Counter()
    per_class_correct = Counter()
    strategy_results = Counter()
    confidences = {"correct": [], "wrong": []}
    per_class_errors = Counter()  # class -> (predicted) -> count

    for r in recs:
        desc = r.get("description") or ""
        label = r["label"]
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            pred, conf, strategy = predict_mixed(block)
            if pred is None:
                continue
            total += 1
            by_strategy[strategy] += 1
            per_class[label] += 1
            is_correct = pred == label
            if is_correct:
                correct += 1
                per_class_correct[label] += 1
                confidences["correct"].append(conf)
            else:
                confidences["wrong"].append(conf)
                per_class_errors[(CLASS_NAMES[label], CLASS_NAMES[pred])] += 1
            strategy_results[f"{strategy}_{'ok' if is_correct else 'ko'}"] += 1

    print(f"\n{'='*58}")
    print(f"ENSEMBLE: WEIGHTED 5-ML VOTE")
    print(f"{'='*58}")
    print(f"Total blocks     : {total}")
    print(f"Overall accuracy : {100*correct/total:.1f}% ({correct}/{total})")
    print()

    print("By strategy:")
    for strat, cnt in by_strategy.most_common():
        ok = strategy_results.get(f"{strat}_ok", 0)
        ko = strategy_results.get(f"{strat}_ko", 0)
        n = ok + ko
        print(f"  {strat:10s}: {100*ok/n:.1f}% ({ok}/{n})")

    print()
    print("By class:")
    for lab in sorted(per_class):
        n = per_class[lab]
        c = per_class_correct.get(lab, 0)
        print(f"  {CLASS_NAMES[lab]:14s}: {100*c/n:.1f}% ({c}/{n})")

    print()
    print("Top confusions (true -> predicted):")
    for (t, p), cnt in per_class_errors.most_common(10):
        print(f"  {t:14s} -> {p:14s}: {cnt}")

    if confidences["correct"]:
        print(f"\nMean confidence (correct): {sum(confidences['correct'])/len(confidences['correct']):.2f}")
    if confidences["wrong"]:
        print(f"Mean confidence (wrong)  : {sum(confidences['wrong'])/len(confidences['wrong']):.2f}")

    print(f"\n{'='*58}")
    print("COMPARISON")
    print(f"{'='*58}")
    print(f"{'Method':<25s} {'Accuracy':>10s}")
    print(f"{'-'*37}")
    print(f"{'Weighted ensemble':<25s} {100*correct/total:>9.1f}%")
    print(f"{'Best single ML':<25s} {'87.2':>9s}%")
    print(f"{'Rules alone':<25s} {'65.0':>9s}%")
    print(f"{'Taint alone':<25s} {'89.5':>9s}%")
    print(f"{'Bandit':<25s} {'3.2':>9s}%")
    print(f"{'Random':<25s} {'20.0':>9s}%")


if __name__ == "__main__":
    main()
