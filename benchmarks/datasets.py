"""
Real benchmark dataset loaders
==============================
Loaders for the public vulnerability datasets used in the SYRTH paper
validation (BigVul / Devign / RealVuln), plus a synthetic fallback when the
files are not available locally.

Expected formats:
- BigVul JSONL:    ``{"function_before": "...", "vul": true/false, ...}``
- Devign JSON:     ``{"func": "...", "target": 0/1, ...}``
- RealVuln JSONL:  ``{"code": "...", "label": 0/1, ...}``

Place datasets under ``datasets/<name>`` (see project README / docs).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .synthetic import generate_dataset

BIGVUL_DEFAULT = Path("datasets") / "bigvul.jsonl"
DEVIGN_DEFAULT = Path("datasets") / "devign.json"
REALVULN_DEFAULT = Path("datasets") / "realvuln.jsonl"

DATASET_SPECS: dict[str, dict] = {
    "bigvul": {
        "path": BIGVUL_DEFAULT,
        "kind": "jsonl",
        "code_key": "function_before",
        "label_key": "vul",
        "label_map": {True: 1, False: 0},
        "cwe_key": "CWE",
    },
    "devign": {
        "path": DEVIGN_DEFAULT,
        "kind": "json",
        "code_key": "func",
        "label_key": "target",
        "label_map": {True: 1, False: 0},
        "cwe_key": None,
    },
    "realvuln": {
        "path": REALVULN_DEFAULT,
        "kind": "jsonl",
        "code_key": "code",
        "label_key": "label",
        "label_map": {True: 1, False: 0},
        "cwe_key": None,
    },
}


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_dataset(
    name: str,
    path: str | None = None,
    limit: int | None = None,
    allow_synthetic: bool = True,
) -> list[dict]:
    """
    Load a benchmark dataset.

    Args:
        name: "bigvul" | "devign" | "realvuln" (or "synthetic")
        path: optional explicit path (defaults to datasets/<name>)
        limit: optional max sample count
        allow_synthetic: when True and the dataset file is missing, a
            deterministic synthetic dataset is returned instead

    Returns:
        list of dicts: {id, code, label, cwe?}
    """
    if name == "synthetic":
        return generate_dataset(limit or 200, max(10, (limit or 200) // 2))

    spec = DATASET_SPECS.get(name)
    if spec is None:
        raise ValueError(f"Unknown dataset {name!r}; choose from {list(DATASET_SPECS)}")

    target = Path(path) if path else spec["path"]
    if not target.exists():
        if allow_synthetic:
            return generate_dataset(limit or 200, max(10, (limit or 200) // 2))
        raise FileNotFoundError(
            f"Dataset {name!r} not found at {target}. "
            f"Place the dataset file there or pass --dataset-synthetic."
        )

    code_key = spec["code_key"]
    label_key = spec["label_key"]
    label_map = spec["label_map"]
    cwe_key = spec["cwe_key"]

    records: list[dict] = []
    if spec["kind"] == "jsonl":
        iterator = _iter_jsonl(target)
    else:  # single JSON array
        with open(target, encoding="utf-8") as fh:
            data = json.load(fh)
        iterator = data if isinstance(data, list) else [data]

    for i, item in enumerate(iterator):
        if limit is not None and len(records) >= limit:
            break
        code = item.get(code_key)
        if not code:
            continue
        label = label_map.get(item.get(label_key), None)
        if label is None:
            continue
        cwe = item.get(cwe_key) if cwe_key else None
        records.append({
            "id": f"{name}-{i}",
            "code": code,
            "label": int(label),
            "cwe": str(cwe) if cwe else None,
        })
    return records


if __name__ == "__main__":
    import sys

    name = sys.argv[1] if len(sys.argv) > 1 else "synthetic"
    data = load_dataset(name, limit=50)
    print(f"{name}: {len(data)} samples, "
          f"{sum(s['label'] for s in data)} vulnerable")
