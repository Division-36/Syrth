"""Analyze why OpenRedirect is 100% and others aren't."""
import json
import numpy as np
from collections import Counter

with open('_full_dataset_5class.json') as f:
    raw = json.load(f)

data = raw.get('records', raw) if isinstance(raw, dict) else raw

by_class = {}
for r in data:
    label = r.get('label', 0)
    if label not in by_class:
        by_class[label] = []
    by_class[label].append(r)

class_names = ['SQLi', 'XSS', 'PathTraversal', 'OpenRedirect', 'RCE']

print('=' * 70)
print('CLASS ANALYSIS: OpenRedirect (100%) vs Others')
print('=' * 70)

for label in range(5):
    records = by_class.get(label, [])
    name = class_names[label]
    print(f'\n--- {name} ({len(records)} blocks) ---')

    all_tokens = []
    sink_tokens = []
    taint_tokens = []
    scat_tokens = []
    for r in records:
        tokens = r.get('tokens', [])
        all_tokens.extend(tokens)
        for t in tokens:
            if t.startswith('sink:'):
                sink_tokens.append(t)
            elif t.startswith('tainted:'):
                taint_tokens.append(t)
            elif t.startswith('SCAT:'):
                scat_tokens.append(t)

    sink_counts = Counter(sink_tokens)
    print(f'  Sink tokens: {len(sink_tokens)} total, {len(set(sink_tokens))} unique')
    for s, c in sink_counts.most_common(10):
        print(f'    {s}: {c}')

    taint_counts = Counter(taint_tokens)
    print(f'  Taint tokens: {len(taint_tokens)} total')
    for t, c in taint_counts.most_common(5):
        print(f'    {t}: {c}')

    scat_counts = Counter(scat_tokens)
    print(f'  SCAT tokens: {len(scat_tokens)} total, {len(set(scat_counts))} unique')
    for s, c in scat_counts.most_common(5):
        print(f'    {s}: {c}')

    token_counts = [len(r.get('tokens', [])) for r in records]
    print(f'  Token count: min={min(token_counts)}, max={max(token_counts)}, avg={np.mean(token_counts):.1f}')

    has_desc = sum(1 for r in records if r.get('description'))
    print(f'  Has description: {has_desc}/{len(records)} ({100*has_desc/len(records):.1f}%)')

    has_src = sum(1 for r in records if r.get('vulnerable_src'))
    print(f'  Has source code: {has_src}/{len(records)} ({100*has_src/len(records):.1f}%)')

    arg_tokens = [t for t in all_tokens if t.startswith('arg:')]
    print(f'  arg: tokens: {len(arg_tokens)} total, {len(set(arg_tokens))} unique')
    for a, c in Counter(arg_tokens).most_common(5):
        print(f'    {a}: {c}')

    call_tokens = [t for t in all_tokens if t.startswith('call:')]
    print(f'  call: tokens: {len(call_tokens)} total, {len(set(call_tokens))} unique')
    for c, n in Counter(call_tokens).most_common(5):
        print(f'    {c}: {n}')

    def_tokens = [t for t in all_tokens if t.startswith('def:')]
    print(f'  def: tokens: {len(def_tokens)} total, {len(set(def_tokens))} unique')
    for d, c in Counter(def_tokens).most_common(5):
        print(f'    {d}: {c}')

    # meta tokens
    meta_tokens = [t for t in all_tokens if t.startswith('meta:')]
    print(f'  meta: tokens: {len(meta_tokens)} total, {len(set(meta_tokens))} unique')
    for m, c in Counter(meta_tokens).most_common(5):
        print(f'    {m}: {c}')

# Now look at specific confusion: what makes SQLi look like RCE?
print('\n' + '=' * 70)
print('CONFUSION ANALYSIS: SQLi -> RCE (15 blocks)')
print('=' * 70)

sqli_records = by_class.get(0, [])
# We need to re-analyze with the meta-learner to find which SQLi blocks are misclassified as RCE
import sys
sys.path.insert(0, '.')
import _eval_meta_v2 as meta

sqli_as_rce = []
for r in sqli_records:
    tokens = r.get('tokens', [])
    src = r.get('vulnerable_src', '')
    full_desc = r.get('description', '') + ' ' + r.get('extended_description', '')
    label, conf = meta.predict_meta(src, full_desc)
    if label == 4:  # RCE
        sqli_as_rce.append(r)

print(f'\n{len(sqli_as_rce)} SQLi blocks classified as RCE:')
for i, r in enumerate(sqli_as_rce[:10]):
    tokens = r.get('tokens', [])
    sinks = [t for t in tokens if t.startswith('sink:')]
    taints = [t for t in tokens if t.startswith('tainted:')]
    print(f'\n  Block {i+1}:')
    print(f'    Sinks: {sinks[:5]}')
    print(f'    Taints: {taints[:3]}')
    print(f'    Desc snippet: {r.get("description", "")[:100]}')

# Same for XSS -> RCE
print('\n' + '=' * 70)
print('CONFUSION ANALYSIS: XSS -> RCE (7 blocks)')
print('=' * 70)

xss_records = by_class.get(1, [])
xss_as_rce = []
for r in xss_records:
    tokens = r.get('tokens', [])
    src = r.get('vulnerable_src', '')
    full_desc = r.get('description', '') + ' ' + r.get('extended_description', '')
    label, conf = meta.predict_meta(src, full_desc)
    if label == 4:
        xss_as_rce.append(r)

print(f'\n{len(xss_as_rce)} XSS blocks classified as RCE:')
for i, r in enumerate(xss_as_rce[:10]):
    tokens = r.get('tokens', [])
    sinks = [t for t in tokens if t.startswith('sink:')]
    taints = [t for t in tokens if t.startswith('tainted:')]
    print(f'\n  Block {i+1}:')
    print(f'    Sinks: {sinks[:5]}')
    print(f'    Taints: {taints[:3]}')
    print(f'    Desc snippet: {r.get("description", "")[:100]}')

# Same for PT -> RCE
print('\n' + '=' * 70)
print('CONFUSION ANALYSIS: PT -> RCE (16 blocks)')
print('=' * 70)

pt_records = by_class.get(2, [])
pt_as_rce = []
for r in pt_records:
    tokens = r.get('tokens', [])
    src = r.get('vulnerable_src', '')
    full_desc = r.get('description', '') + ' ' + r.get('extended_description', '')
    label, conf = meta.predict_meta(src, full_desc)
    if label == 4:
        pt_as_rce.append(r)

print(f'\n{len(pt_as_rce)} PT blocks classified as RCE:')
for i, r in enumerate(pt_as_rce[:10]):
    tokens = r.get('tokens', [])
    sinks = [t for t in tokens if t.startswith('sink:')]
    taints = [t for t in tokens if t.startswith('tainted:')]
    print(f'\n  Block {i+1}:')
    print(f'    Sinks: {sinks[:5]}')
    print(f'    Taints: {taints[:3]}')
    print(f'    Desc snippet: {r.get("description", "")[:100]}')
