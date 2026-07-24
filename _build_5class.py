import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import harvester as H

MAX_PER = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("_full_dataset_5class.json")

print("[build] harvesting OSV PyPI feed (all packages)...", file=sys.stderr)
osv = H.fetch_osv_records()
print(f"[build] got {len(osv)} raw OSV records", file=sys.stderr)

print("[build] adding synthetic code-only records (inference-aligned vocab)...", file=sys.stderr)
synth = H.generate_synthetic_samples()
for r in synth:
    if not r.get("ghsa_id"):
        r["ghsa_id"] = f"GHSA-synth-{r.get('variant', 'x')}"

by_label: dict[int, list] = {}
for r in osv + synth:
    if r["label"] < 0:
        continue
    by_label.setdefault(r["label"], []).append(r)

kept: list[dict] = []
for label, group in sorted(by_label.items()):
    group_sorted = sorted(group, key=lambda r: str(r.get("ghsa_id") or r.get("osv_id") or ""))
    take = group_sorted[:MAX_PER] if len(group_sorted) > MAX_PER else group_sorted
    kept.extend(take)
    name = H.CWE_NAMES.get([k for k, v in H.CWE_LABELS.items() if v == label][0], f"C{label}")
    print(f"[build] class {label} ({name}): kept {len(take)} / {len(group_sorted)}", file=sys.stderr)

from collections import Counter
print("[build] final label distribution:", dict(Counter(r["label"] for r in kept)), file=sys.stderr)

OUT.write_text(json.dumps({
    "syrth_version": "1.0.0",
    "num_classes": len(H.CWE_LABELS),
    "class_map": {str(v): k for k, v in H.CWE_LABELS.items()},
    "cwe_names": H.CWE_NAMES,
    "total_records": len(kept),
    "records": kept,
}, indent=2), encoding="utf-8")
print(f"[build] wrote {len(kept)} records -> {OUT}", file=sys.stderr)
