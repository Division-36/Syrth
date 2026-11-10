"""Tests for the corpus freezer's reproducibility promise.

The frozen corpus is quoted by the paper as one object with one hash. That is
only true if building it twice from the same inputs is inert: a gzip timestamp,
a reordered tar member, or an inherited owner name all make "the frozen corpus"
name two different objects, and nothing else in the suite runs the freezer to
notice.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _corpus() -> pathlib.Path:
    path = ROOT / "data" / "corpus.jsonl"
    if not path.exists():
        pytest.skip("benchmark corpus is not generated in this checkout")
    return path


def test_freeze_is_byte_reproducible(tmp_path: pathlib.Path) -> None:
    """Two freezes of the same corpus must agree on every published field."""
    sys.path.insert(0, str(ROOT))
    from tools.freeze_corpus import freeze

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first = freeze(_corpus(), first_dir, ROOT)
    second = freeze(_corpus(), second_dir, ROOT)

    # The one differing key is the output location, which is expected.
    assert first["archive"] != second["archive"]
    assert {k: v for k, v in first.items() if k != "archive"} == {
        k: v for k, v in second.items() if k != "archive"
    }
    # The shipped checksums are part of the snapshot, so they agree too.
    assert (
        (first_dir / "SHA256SUMS").read_text(encoding="utf-8")
        == (second_dir / "SHA256SUMS").read_text(encoding="utf-8")
    )
