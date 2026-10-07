"""Surgical ensemble: v1 + targeted confusion rules only."""
import json, re, collect, torch, joblib
import numpy as np
import train_model as T
from collections import Counter
from _rules import classify_by_rules, CLASS_SQLI, CLASS_XSS, CLASS_PATH, CLASS_REDIR, CLASS_RCE

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

bundle = joblib.load("syrth_ensemble.joblib")
TOK = T.SyrthTokenizer()
TOK.vocab = bundle["tokenizer_vocab"]
UNK = TOK.vocab.get("<UNK>", 0)

ensemble = []
for name, mdata in bundle["ensemble"].items():
    cfg = mdata["model_config"]
    model = T.SyrthEncoder(
        vocab_size=cfg["vocab_size"],
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg["ffn_dim"],
        num_classes=T.NUM_CLASSES,
        aux_dim=0,
    )
    state = {k: torch.as_tensor(v) for k, v in mdata["state_dict"].items()}
    model.load_state_dict(state)
    model.eval()
    ensemble.append((model, max(mdata["heldout_acc"], 0.5)))

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

# ── Surgical confusion overrides ───────────────────────────────────────────
# Only fire when we have strong counter-evidence that ML missed
IMPORT_TO_CLASS = {
    "import:sqlite3": CLASS_SQLI,
    "import:MySQLdb": CLASS_SQLI,
    "import:psycopg2": CLASS_SQLI,
    "import:aiomysql": CLASS_SQLI,
    "import:sqlalchemy": CLASS_SQLI,
    "import:os": CLASS_PATH,
    "import:pathlib": CLASS_PATH,
    "import:shutil": CLASS_PATH,
    "import:subprocess": CLASS_RCE,
}

# Override only when ML misses a very clear signal
CONFUSION_RULES = [
    # RCE→PT: block has path traversal code but ML says RCE
    {
        "from": CLASS_RCE, "to": CLASS_PATH,
        "signals": ["sink:open", "call:open", "SCAT:FILE"],
        "min_votes": 2, "conf_threshold": 0.75,
    },
    # RCE→SQLi: block has SQL code but ML says RCE  
    {
        "from": CLASS_RCE, "to": CLASS_SQLI,
        "signals": ["sink:cursor.execute", "call:cursor.execute",
                     "call:connection.cursor", "SCAT:SQL"],
        "min_votes": 2, "conf_threshold": 0.70,
    },
    # RCE→XSS: block has XSS code but ML says RCE
    {
        "from": CLASS_RCE, "to": CLASS_XSS,
        "signals": ["sink:render", "sink:HttpResponse", "SCAT:XSS"],
        "min_votes": 2, "conf_threshold": 0.70,
    },
    # RCE→OR: block has redirect code but ML says RCE
    {
        "from": CLASS_RCE, "to": CLASS_REDIR,
        "signals": ["sink:redirect", "SCAT:REDIRECT"],
        "min_votes": 1, "conf_threshold": 0.80,
    },
]

TAINT_MAP = {
    "tainted:execute": CLASS_SQLI, "tainted:cursor.execute": CLASS_SQLI,
    "tainted:raw": CLASS_SQLI, "tainted:extra": CLASS_SQLI,
    "tainted:render": CLASS_XSS, "tainted:HttpResponse": CLASS_XSS,
    "tainted:mark_safe": CLASS_XSS, "tainted:render_template": CLASS_XSS,
    "tainted:open": CLASS_PATH, "tainted:send_file": CLASS_PATH,
    "tainted:os.system": CLASS_RCE, "tainted:subprocess.run": CLASS_RCE,
    "tainted:subprocess.Popen": CLASS_RCE, "tainted:eval": CLASS_RCE,
    "tainted:exec": CLASS_RCE, "tainted:popen": CLASS_RCE,
    "tainted:redirect": CLASS_REDIR, "tainted:HttpResponseRedirect": CLASS_REDIR,
    "tainted:RedirectResponse": CLASS_REDIR,
}


def predict_ensemble(tokens, seq_ids):
    x = torch.tensor([seq_ids])
    with torch.no_grad():
        votes = torch.zeros(5)
        for model, weight in ensemble:
            probs = model.predict_proba(x)[0]
            votes += probs * weight
        avg = votes / votes.sum()
    return int(avg.argmax()), float(avg.max()), avg


def predict_mixed(src):
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
                if t in TAINT_MAP:
                    taint_hits.append(TAINT_MAP[t])

    if not seq:
        return None, None

    seq_ids = [TOK.vocab.get(t, UNK) for t in seq]
    token_set = set(seq)

    # Level 1: Taint
    if taint_hits:
        return Counter(taint_hits).most_common(1)[0][0], 0.90

    # Level 2: ML ensemble
    pred, conf, votes = predict_ensemble(seq, seq_ids)

    # Level 3: Confusion rules (only when ML confidence is NOT sky-high)
    for rule in CONFUSION_RULES:
        if pred != rule["from"]:
            continue
        if conf > rule["conf_threshold"]:
            continue
        match_count = sum(1 for s in rule["signals"] if s in token_set)
        if match_count >= rule["min_votes"]:
            # Only override if the target class has non-trivial vote
            if float(votes[rule["to"]]) > 0.1:
                return rule["to"], min(conf + 0.1, 0.85)

    # Level 4: Rules as fallback for very low confidence
    if conf < 0.3:
        rule_result = classify_by_rules(seq)
        if rule_result.votes.total() > 0 and rule_result.confidence > 0.6:
            return rule_result.predicted_class, rule_result.confidence

    if conf < 0.2:
        return CLASS_RCE, 0.2

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
            pred, conf = predict_mixed(block)
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
    print(f"SURGICAL ENSEMBLE: v1 + targeted confusion rules only")
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
    print(f"{'Surgical':<25s} {100*correct/total:>9.1f}%")
    print(f"{'Ensemble v1':<25s} {'89.2':>9s}%")
    print(f"{'Best single ML':<25s} {'87.2':>9s}%")


if __name__ == "__main__":
    main()
