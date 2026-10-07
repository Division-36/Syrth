"""Deep analysis: what do the 72 misclassified blocks actually look like?"""
import json, sys, numpy as np
from collections import Counter
sys.path.insert(0, '.')
import collect
import _rules
from _eval_ensemble import predict_ensemble, TOK, ensemble
import _eval_meta_v2 as meta

with open('_full_dataset_5class.json') as f:
    raw = json.load(f)
data = raw['records']

class_names = ['SQLi', 'XSS', 'PathTraversal', 'OpenRedirect', 'RCE']

misclassified = []
for r in data:
    src = r.get('vulnerable_src', '')
    full_desc = (r.get('description', '') or '') + ' ' + (r.get('extended_description', '') or '')
    true_label = r['label']
    
    pred, conf = meta.predict_meta(src, full_desc)
    if pred is None:
        continue
    if pred != true_label:
        misclassified.append({
            'true': class_names[true_label],
            'pred': class_names[pred],
            'conf': conf,
            'src': src[:200] if src else '(no src)',
            'desc': full_desc[:200],
            'tokens': r.get('tokens', []),
        })

print(f'Total misclassified: {len(misclassified)}')
print()

# Analyze: how many have src code?
has_src = sum(1 for m in misclassified if m['src'] != '(no src)')
print(f'Has source code: {has_src}/{len(misclassified)}')

# Average confidence
avg_conf = np.mean([m['conf'] for m in misclassified])
print(f'Average confidence: {avg_conf:.3f}')

# How many have taint?
has_taint = 0
has_sink = 0
has_call = 0
has_scat = 0
for m in misclassified:
    tokens = m['tokens']
    has_taint += 1 if any(t.startswith('tainted:') for t in tokens) else 0
    has_sink += 1 if any(t.startswith('sink:') for t in tokens) else 0
    has_call += 1 if any(t.startswith('call:') for t in tokens) else 0
    has_scat += 1 if any(t.startswith('SCAT:') for t in tokens) else 0

print(f'Has taint: {has_taint}/{len(misclassified)}')
print(f'Has sink: {has_sink}/{len(misclassified)}')
print(f'Has call: {has_call}/{len(misclassified)}')
print(f'Has SCAT: {has_scat}/{len(misclassified)}')

# Confusion matrix
print(f'\nConfusion matrix:')
confusion = Counter((m['true'], m['pred']) for m in misclassified)
for (true, pred), count in confusion.most_common():
    print(f'  {true} -> {pred}: {count}')

# Show some examples
print(f'\n--- Sample misclassified blocks ---')
for i, m in enumerate(misclassified[:10]):
    tokens = m['tokens']
    sinks = [t for t in tokens if t.startswith('sink:')]
    taints = [t for t in tokens if t.startswith('tainted:')]
    calls = [t for t in tokens if t.startswith('call:')]
    print(f'\n[{i+1}] True: {m["true"]}, Pred: {m["pred"]}, Conf: {m["conf"]:.3f}')
    print(f'    Sinks: {sinks[:5]}')
    print(f'    Taints: {taints[:3]}')
    print(f'    Calls: {calls[:5]}')
    print(f'    Desc: {m["desc"][:120]}...')
