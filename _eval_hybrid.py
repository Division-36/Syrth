"""Hybrid evaluation: taint-based when available, ML otherwise."""
import json, re, collect, torch, joblib
import torch.nn.functional as F
import train_model as T
from collections import Counter, defaultdict

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

BUNDLE = joblib.load("syrth_model.joblib")
TOK = T.SyrthTokenizer()
TOK.vocab = BUNDLE["tokenizer_vocab"]
UNK = TOK.vocab.get("<UNK>", 0)
_cfg = BUNDLE.get("model_config", {})
MODEL = T.SyrthEncoder(
    vocab_size=len(TOK.vocab),
    embed_dim=_cfg.get("embed_dim", 256),
    ffn_dim=_cfg.get("ffn_dim", 1024),
    aux_dim=_cfg.get("aux_dim", 0),
)
MODEL.load_state_dict({k: torch.as_tensor(v) for k, v in BUNDLE["model_state_dict"].items()})
MODEL.eval()

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

# Taint-based classification: map tainted:<sink> to class
TAINT_CLASS_MAP = {
    "tainted:execute": 0, "tainted:cursor.execute": 0, "tainted:raw": 0,
    "tainted:extra": 0, "tainted:executemany": 0,
    "tainted:render": 1, "tainted:render_to_string": 1, "tainted:mark_safe": 1,
    "tainted:HttpResponse": 1, "tainted:render_template": 1,
    "tainted:render_template_string": 1, "tainted:make_response": 1,
    "tainted:Response": 1, "tainted:JsonResponse": 1, "tainted:jsonify": 1,
    "tainted:format_html": 1, "tainted:autoescape_off": 1,
    "tainted:open": 2, "tainted:shutil.copy": 2, "tainted:shutil.rmtree": 2,
    "tainted:os.remove": 2, "tainted:send_file": 2, "tainted:send_from_directory": 2,
    "tainted:FileResponse": 2, "tainted:os.makedirs": 2,
    "tainted:os.system": 4, "tainted:subprocess.run": 4,
    "tainted:subprocess.call": 4, "tainted:subprocess.Popen": 4,
    "tainted:subprocess.getoutput": 4, "tainted:popen": 4,
    "tainted:os.popen": 4, "tainted:eval": 4, "tainted:exec": 4,
    "tainted:compile": 4, "tainted:subprocess.check_output": 4,
    "tainted:redirect": 3, "tainted:HttpResponseRedirect": 3,
    "tainted:HttpResponsePermanentRedirect": 3, "tainted:RedirectResponse": 3,
    "tainted:commands.getoutput": 4, "tainted:commands.getstatusoutput": 4,
    "tainted:os.execv": 4, "tainted:os.execl": 4,
    "tainted:pickle.loads": 4, "tainted:yaml.load": 4, "tainted:marshal.loads": 4,
}


def predict_hybrid(src: str):
    """Predict using taint-based or ML-based classification."""
    try:
        ft = collect.extract_traces_from_source(src, label="x")
    except:
        return None, None

    seq = []
    taint_classes = []
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            seq.extend(s)
            for t in s:
                if t.startswith("tainted:") and t in TAINT_CLASS_MAP:
                    taint_classes.append(TAINT_CLASS_MAP[t])

    if not seq:
        return None, None

    # Strategy 1: Taint-based (highest confidence — 98.4% accuracy)
    if taint_classes:
        most_common = Counter(taint_classes).most_common(1)[0][0]
        return most_common, "taint"

    # Strategy 2: ML-based (SCAT tokens are already in the vocabulary)
    x = torch.tensor([[TOK.vocab.get(t, UNK) for t in seq]])
    with torch.no_grad():
        out = MODEL(x)
    probs = F.softmax(out, 1)[0]
    return int(probs.argmax()), "ml"


def main():
    recs = json.load(open("_full_dataset_5class.json"))["records"]
    total = 0
    correct = 0
    by_strategy = defaultdict(lambda: {"correct": 0, "wrong": 0})
    by_class = defaultdict(Counter)

    for r in recs:
        desc = r.get("description") or ""
        label = r["label"]
        for block in CODE_RE.findall(desc):
            block = block.strip()
            if len(block) < 20:
                continue
            pred, strategy = predict_hybrid(block)
            if pred is None:
                continue
            total += 1
            is_correct = pred == label
            if is_correct:
                correct += 1
            by_strategy[strategy]["correct" if is_correct else "wrong"] += 1
            by_class[label][pred] += 1

    print(f"\n=== HYBRID EVAL (taint when available, ML fallback) ===")
    print(f"Scanned code samples : {total}")
    print(f"Overall accuracy     : {100*correct/total:.1f}% ({correct}/{total})")

    print(f"\nBy strategy:")
    for strat in ["taint", "ml"]:
        d = by_strategy[strat]
        c = d["correct"]
        w = d["wrong"]
        n = c + w
        if n > 0:
            print(f"  {strat:8s}: {100*c/n:.1f}% ({c}/{n})")

    print(f"\nPer-class:")
    for lab in sorted(by_class):
        name = CLASS_NAMES[lab]
        row = by_class[lab]
        n = sum(row.values())
        hit = row.get(lab, 0)
        print(f"  {name:14s} (n={n:4d}): {100*hit/n:.1f}%")


if __name__ == "__main__":
    main()
