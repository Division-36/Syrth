"""Quick check: does the eval script produce the same feature count as training?"""
import json, numpy as np, sys
sys.path.insert(0, '.')
import _eval_meta_v2 as m
import joblib

meta = joblib.load('syrth_meta.joblib')
expected = meta['meta_config']['num_features']
print(f'Model expects: {expected} features')

with open('_full_dataset_5class.json') as f:
    raw = json.load(f)
data = raw['records']

import collect
count = 0
for r in data:
    src = r.get('vulnerable_src', '')
    if not src or len(src) < 50:
        continue
    try:
        ft = collect.extract_traces_from_source(src, label='x')
    except:
        continue
    seq = []
    for fn in ft.functions:
        s = fn.to_token_sequence()
        if s:
            seq.extend(s)
    if not seq:
        continue
    full_desc = r.get('description', '') + ' ' + r.get('extended_description', '')
    feats = m.extract_meta_features(seq, source_code=full_desc)
    print(f'Eval produces: {len(feats)} features, expected: {expected}, match: {len(feats) == expected}')
    if len(feats) != expected:
        print('MISMATCH!')
        break
    count += 1
    if count >= 3:
        break
