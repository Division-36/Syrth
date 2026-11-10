"""The published measurement files must be reproducible by their harness.

`data/*.json` is what the documentation quotes, and the paper quotes the
documentation. If a published number drifts away from the harness that
produced it, every reader who re-runs the harness sees a different number
from the one published, and nothing in the tree says so.

`benchmarks/verify_published.py` is the tool that checks this. These tests
cover the parts of it that decide whether a difference is a difference: the
fields that cannot be reproduced, the paths that are written with a
different separator on another platform, and the corpus fields that name a
file rather than a measurement.

The expensive part -- re-running every harness -- is covered by the tool
itself and by CI; what is tested here is the decision logic, so a change to
the comparison rules cannot quietly turn a mismatch into a pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from benchmarks.verify_published import (
    CORPUS_FIELDS,
    EXPECTED_KEYS,
    VOLATILE_KEYS,
    Check,
    _compare,
    _file_name,
    _run_check,
    _verify_published_files,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

requires_corpus = pytest.mark.skipif(
    not (DATA / "corpus.jsonl").exists(),
    reason="the corpus is not present",
)


class TestComparisonRules:
    """Which differences count."""

    def test_a_changed_number_is_a_difference(self):
        differences = _compare({"kill_rate": 0.89}, {"kill_rate": 0.9})
        assert differences
        assert "kill_rate" in differences[0]

    def test_a_timing_is_not_a_difference(self):
        """Wall-clock time cannot be reproduced, so it is not compared.

        The alternative is a check that fails on every run, which is a check
        nobody reads.
        """
        differences = _compare(
            {"seconds": 12.5, "kill_rate": 0.89}, {"seconds": 19.1, "kill_rate": 0.89}
        )
        assert differences == []

    def test_every_volatile_field_is_skipped(self):
        for key in VOLATILE_KEYS:
            differences = _compare({key: 1}, {key: 2})
            assert differences == [], key

    def test_a_missing_field_is_a_difference(self):
        differences = _compare({"records": 350}, {})
        assert differences
        assert "records" in differences[0]

    def test_an_extra_field_is_a_difference(self):
        differences = _compare({}, {"records": 350})
        assert differences
        assert "records" in differences[0]


class TestPaths:
    """A path is the same path on every platform."""

    def test_a_separator_is_not_a_difference(self):
        differences = _compare(
            {"corpus": "data\\corpus.jsonl"}, {"corpus": "data/corpus.jsonl"}
        )
        assert differences == []

    def test_the_file_name_is_read_through_either_separator(self):
        assert _file_name("data\\corpus.jsonl") == "corpus.jsonl"
        assert _file_name("data/corpus.jsonl") == "corpus.jsonl"
        assert _file_name("corpus.jsonl") == "corpus.jsonl"

    def test_a_different_corpus_file_is_a_difference(self):
        differences = _compare(
            {"dataset": "data/corpus.jsonl"}, {"dataset": "data/other.jsonl"}
        )
        assert differences

    def test_the_corpus_fields_are_the_ones_that_name_the_corpus(self):
        assert "dataset" in CORPUS_FIELDS
        assert "corpus" in CORPUS_FIELDS


class TestPublishedFiles:
    """The published files themselves."""

    def test_every_published_file_is_expected(self):
        """Each published measurement file is covered by the checker.

        A new published file that nobody verifies is a number nobody can
        check, so the checker must know about it.
        """
        try:
            completed = subprocess.run(
                ["git", "ls-files", "data"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):  # pragma: no cover
            pytest.skip("git is not available")
        published = {
            Path(line).name
            for line in completed.stdout.splitlines()
            if line.endswith(".json")
        }
        known = {Path(name).name for name in EXPECTED_KEYS}
        # The manifest describes the corpus; it is not a measurement.
        assert published - known <= {"corpus_manifest.json"}, published - known

    def test_a_missing_field_is_reported(self, tmp_path):
        target = tmp_path / "data"
        target.mkdir()
        for name in EXPECTED_KEYS:
            source = DATA / Path(name).name
            if source.exists():
                shutil.copy(source, target / Path(name).name)
        path = target / "patch_study.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        del document["flow_traded"]
        path.write_text(json.dumps(document), encoding="utf-8")
        status, notes = _verify_published_files(tmp_path)
        assert status == "MISMATCH"
        assert any("flow_traded" in note for note in notes)

    def test_the_unmodified_files_pass(self, tmp_path):
        target = tmp_path / "data"
        target.mkdir()
        for name in EXPECTED_KEYS:
            source = DATA / Path(name).name
            if source.exists():
                shutil.copy(source, target / Path(name).name)
        status, notes = _verify_published_files(tmp_path)
        assert status == "OK", notes


@requires_corpus
class TestReDerivation:
    """A published number that no longer matches its harness is caught."""

    def test_the_patch_study_is_reproduced(self):
        check = Check(
            "real-commit patch study",
            "data/patch_study.json",
            "benchmarks.patch_study",
            ("--dataset", "{dataset}"),
        )
        status, notes = _run_check(check, "data/corpus.jsonl", ROOT)
        assert status == "OK", notes

    def test_a_tampered_number_is_reported(self, tmp_path):
        target = tmp_path / "data"
        target.mkdir()
        shutil.copy(DATA / "patch_study.json", target / "patch_study.json")
        path = target / "patch_study.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["flow_persists"] = document["flow_persists"] + 1
        path.write_text(json.dumps(document), encoding="utf-8")
        check = Check(
            "real-commit patch study",
            "data/patch_study.json",
            "benchmarks.patch_study",
            ("--dataset", "{dataset}"),
        )
        status, notes = _run_check(check, str(DATA / "corpus.jsonl"), tmp_path)
        assert status == "MISMATCH"
        assert any("flow_persists" in note for note in notes)
