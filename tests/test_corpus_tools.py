"""The corpus tools must fail loudly when their input is broken.

Both tools were added with the v1.1 expansion. Each has a failure mode that a
hand run hides: the validator used to crash while fingerprinting a source it had
already marked unparseable, and the merge used to exit green after dropping a
pair. These tests use two-record corpora, so they cost nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.merge_corpus import main as merge
from tools.validate_corpus import validate


def _record(*, kind: str, label: str, cwe: str, source: str) -> dict:
    return {
        "pair_id": "GHSA-test:" + "0" * 40 + ":a.py:f:CWE-22",
        "group": "GHSA-test",
        "source": source,
        "label": label,
        "cwe": cwe,
        "repo": "repo",
        "advisory_id": "GHSA-test",
        "commit": "0" * 40,
        "file": "a.py",
        "function": "f",
        "qualname": "f",
        "kind": kind,
        "origin_source": "test",
        "sink_call": "open",
        "evidence": "direct-sink",
        "module_sink": "open",
    }


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def test_unparseable_source_yields_a_report(tmp_path: Path) -> None:
    path = tmp_path / "broken.jsonl"
    _write(path, [
        _record(kind="vulnerable", label="CWE-22", cwe="CWE-22", source="def f(:"),
        _record(kind="patched", label="", cwe="", source="def f(): pass"),
    ])
    summary = validate(path)
    assert summary["failure_counts"]["unparseable_source"] == 1
    assert summary["checks"]["sources_parse"] == "fail"


def test_swapped_labels_make_the_merge_fail(tmp_path: Path) -> None:
    path = tmp_path / "swapped.jsonl"
    _write(path, [
        _record(kind="vulnerable", label="CWE-22", cwe="CWE-22", source="def f(): pass"),
        _record(kind="patched", label="CWE-22", cwe="CWE-22", source="def f(): pass\n"),
    ])
    out = tmp_path / "out.jsonl"
    code = merge([str(path), "--out", str(out)])
    assert code == 1
