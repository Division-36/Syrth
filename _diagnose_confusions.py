"""Diagnose confusion patterns in ensemble predictions."""
import json, sys, re
from collections import Counter, defaultdict

sys.path.insert(0, '.')
from _eval_ensemble import predict_ensemble, ensemble, TOK, UNK, CLASS_NAMES
from collect import extract_traces_from_source

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
recs = json.load(open("_full_dataset_5class.json"))["records"]
confusion_examples = defaultdict(list)

for r in recs:
    desc = r.get("description") or ""
    label = r["label"]
    for block in CODE_RE.findall(desc):
        block = block.strip()
        if len(block) < 20:
            continue
        try:
            ft = extract_traces_from_source(block, label="x")
        except:
            continue
        seq = []
        for fn in ft.functions:
            s = fn.to_token_sequence()
            if s:
                seq.extend(s)
        if not seq:
            continue
        seq_ids = [TOK.vocab.get(t, UNK) for t in seq]
        pred, conf, _ = predict_ensemble(seq, seq_ids)
        if pred != label:
            key = (CLASS_NAMES[label], CLASS_NAMES[pred])
            all_tokens = set(seq)
            key_tokens = {t for t in all_tokens if t.startswith(("sink:", "SCAT:", "call:", "tainted:", "import:")) or t == "meta:no_auth"}
            confusion_examples[key].append((key_tokens, block[:200]))

for (true_cls, pred_cls), examples in sorted(confusion_examples.items(), key=lambda x: -len(x[1])):
    counts = len(examples)
    print(f"\n=== {true_cls:12s} -> {pred_cls:12s} ({counts} total) ===")
    all_keys = []
    for ex_tokens, _ in examples:
        all_keys.extend(ex_tokens)
    common = Counter(all_keys).most_common(15)
    print(f"  Common tokens:")
    for tok, cnt in common:
        pct = 100 * cnt / counts
        print(f"    {tok:40s}: {pct:.0f}% ({cnt})")
    for i, (_, blk) in enumerate(examples[:3]):
        blk_s = blk.replace("\n", " | ")
        if len(blk_s) > 180:
            blk_s = blk_s[:180] + "..."
        print(f"  eg{i+1}: {blk_s}")
