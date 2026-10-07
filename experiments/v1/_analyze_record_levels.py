"""Analyze block-per-record distribution for record-level aggregation."""
import json, re
from collections import Counter

CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

recs = json.load(open("_full_dataset_5class.json"))["records"]
class_names = {0: 'SQLi', 1: 'XSS', 2: 'PathTraversal', 3: 'OpenRedirect', 4: 'RCE'}

blocks_per_record = []
records_with_blocks = 0
records_with_1_block = 0
records_with_2plus = 0

for r in recs:
    desc = r.get("description") or ""
    blocks = [b.strip() for b in CODE_RE.findall(desc) if len(b.strip()) >= 20]
    if blocks:
        records_with_blocks += 1
        blocks_per_record.append(len(blocks))
        if len(blocks) == 1:
            records_with_1_block += 1
        else:
            records_with_2plus += 1

print(f"Total records: {len(recs)}")
print(f"Records with blocks: {records_with_blocks}")
print(f"Records with 1 block: {records_with_1_block}")
print(f"Records with 2+ blocks: {records_with_2plus}")
print(f"Avg blocks/record: {sum(blocks_per_record)/len(blocks_per_record):.1f}")
print(f"Max blocks: {max(blocks_per_record)}")
print(f"\nBlocks per record distribution:")
for n, count in sorted(Counter(blocks_per_record).items()):
    print(f"  {n} blocks: {count} records")

# Also check: how many records have vulnerable_src?
has_src = sum(1 for r in recs if r.get("vulnerable_src"))
print(f"\nRecords with vulnerable_src: {has_src}/{len(recs)}")

# Check block overlap: do different blocks in same record have different tokens?
print(f"\n--- Example: record with multiple blocks ---")
for r in recs:
    desc = r.get("description") or ""
    blocks = [b.strip() for b in CODE_RE.findall(desc) if len(b.strip()) >= 20]
    if len(blocks) >= 3:
        print(f"OSV: {r.get('osv_id', '?')}, Label: {class_names[r['label']]}, Blocks: {len(blocks)}")
        for i, b in enumerate(blocks[:4]):
            print(f"  Block {i}: {b[:100]}...")
        break
