"""Analyze call chain context to distinguish SQLi vs RCE."""
import json
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

# Look at call: tokens near sink:execute/sink:exec for each class
for label in [0, 4]:  # SQLi and RCE
    name = class_names[label]
    records = by_class.get(label, [])
    print(f'\n{"="*70}')
    print(f'{name} — call: tokens that contain execute/exec/eval')
    print(f'{"="*70}')

    execute_calls = []
    for r in records:
        tokens = r.get('tokens', [])
        # Find all call: tokens
        calls = [t for t in tokens if t.startswith('call:')]
        for c in calls:
            if any(kw in c.lower() for kw in ['exec', 'eval', 'open', 'system', 'popen', 'subprocess']):
                execute_calls.append(c)

    print(f'Total relevant calls: {len(execute_calls)}')
    for c, n in Counter(execute_calls).most_common(30):
        print(f'  {c}: {n}')

# Also look at full token sequences for a few blocks
print(f'\n{"="*70}')
print('SAMPLE TOKEN SEQUENCES — SQLi blocks with sink:execute')
print(f'{"="*70}')

sqli_records = by_class.get(0, [])
count = 0
for r in sqli_records:
    tokens = r.get('tokens', [])
    if 'sink:execute' in tokens and count < 5:
        print(f'\n--- Block (label=SQLi) ---')
        print(f'  Tokens: {tokens}')
        count = 100  # stop

print(f'\n{"="*70}')
print('SAMPLE TOKEN SEQUENCES — RCE blocks with sink:execute')
print(f'{"="*70}')

rce_records = by_class.get(4, [])
count = 0
for r in rce_records:
    tokens = r.get('tokens', [])
    if 'sink:execute' in tokens and count < 5:
        print(f'\n--- Block (label=RCE) ---')
        print(f'  Tokens: {tokens}')
        count += 1
        if count >= 5:
            break

# Now look at what's around sink:exec
print(f'\n{"="*70}')
print('SAMPLE TOKEN SEQUENCES — SQLi blocks with sink:exec')
print(f'{"="*70}')

count = 0
for r in sqli_records:
    tokens = r.get('tokens', [])
    if 'sink:exec' in tokens and count < 5:
        print(f'\n--- Block (label=SQLi) ---')
        print(f'  Tokens: {tokens}')
        count += 1
        if count >= 5:
            break

print(f'\n{"="*70}')
print('SAMPLE TOKEN SEQUENCES — RCE blocks with sink:exec')
print(f'{"="*70}')

count = 0
for r in rce_records:
    tokens = r.get('tokens', [])
    if 'sink:exec' in tokens and count < 5:
        print(f'\n--- Block (label=RCE) ---')
        print(f'  Tokens: {tokens}')
        count += 1
        if count >= 5:
            break

# Look at what sinks each class has that the others don't
print(f'\n{"="*70}')
print('UNIQUE SINKS PER CLASS (not in RCE)')
print(f'{"="*70}')

rce_sinks = set()
for r in by_class.get(4, []):
    for t in r.get('tokens', []):
        if t.startswith('sink:'):
            rce_sinks.add(t)

for label in [0, 1, 2, 3]:
    name = class_names[label]
    class_sinks = set()
    for r in by_class.get(label, []):
        for t in r.get('tokens', []):
            if t.startswith('sink:'):
                class_sinks.add(t)
    unique = class_sinks - rce_sinks
    if unique:
        print(f'\n{name} unique sinks (not in RCE):')
        for s in sorted(unique):
            count = sum(1 for r in by_class.get(label, []) if s in r.get('tokens', []))
            print(f'  {s}: {count} blocks')
    else:
        print(f'\n{name}: no unique sinks')

# Look at call: tokens that are unique per class
print(f'\n{"="*70}')
print('UNIQUE CALL TOKENS PER CLASS (not in RCE)')
print(f'{"="*70}')

rce_calls = set()
for r in by_class.get(4, []):
    for t in r.get('tokens', []):
        if t.startswith('call:'):
            rce_calls.add(t)

for label in [0, 1, 2]:
    name = class_names[label]
    class_calls = set()
    for r in by_class.get(label, []):
        for t in r.get('tokens', []):
            if t.startswith('call:'):
                class_calls.add(t)
    unique = class_calls - rce_calls
    if unique:
        print(f'\n{name} unique call tokens (not in RCE):')
        for c in sorted(unique):
            count = sum(1 for r in by_class.get(label, []) if c in r.get('tokens', []))
            if count >= 3:
                print(f'  {c}: {count} blocks')
    else:
        print(f'\n{name}: no unique call tokens')
