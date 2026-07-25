"""Debug: check what tainted: tokens are actually generated."""
import json, sys
from collections import Counter
sys.path.insert(0, '.')
import collect

with open('_full_dataset_5class.json') as f:
    raw = json.load(f)
data = raw['records']

all_taint_sinks = []
for r in data:
    src = r.get('vulnerable_src', '')
    if not src:
        continue
    try:
        ft = collect.extract_traces_from_source(src, label='x')
    except:
        continue
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            for t in s:
                if t.startswith("tainted:"):
                    all_taint_sinks.append(t)

print(f"Total tainted: tokens: {len(all_taint_sinks)}")
print(f"Unique tainted: tokens: {len(set(all_taint_sinks))}")
print()
for t, c in Counter(all_taint_sinks).most_common():
    print(f"  {t}: {c}")
