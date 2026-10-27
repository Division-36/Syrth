"""The competitor harness must survive being read as evidence.

The mitigation column had a bug that reported ``0/0`` -- indistinguishable, in a
table, from a tool that never fires. Both were wrong: the harness was keying on
``record_id`` (which encodes the side) and then looking up a bare ``pair_id``, so no
pair ever matched. A measurement that silently measures nothing is worse than no
measurement, so the invariants that make the numbers mean something are pinned here.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from benchmarks.competitors import (
    Coverage,
    ToolResult,
    assert_pairs_are_distinct,
    mitigation_counts,
    record_id,
)

VULNERABLE = """
import os

def load(name):
    return open(os.path.join("/srv", name))
"""

# The sink is still present, but a containment check now dominates it. That is the
# shape a real patch has: the call site does not go away.
PATCHED = """
import os

def load(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside")
    return open(target)
"""

UNCHANGED = VULNERABLE


def _records(vulnerable: str, patched: str, pair: str = "p1") -> list[dict]:
    return [
        {"pair_id": pair, "kind": "vulnerable", "source": vulnerable},
        {"pair_id": pair, "kind": "patched", "source": patched},
    ]


class TestPairValidation:
    def test_distinct_pair_is_accepted(self):
        assert assert_pairs_are_distinct(_records(VULNERABLE, PATCHED)) == 1

    def test_identical_sides_refuse_to_measure(self):
        # A "patch" that changes nothing would dilute every tool's rate toward the
        # mean, and produce a number that looks like a result.
        with pytest.raises(SystemExit, match="identical"):
            assert_pairs_are_distinct(_records(VULNERABLE, UNCHANGED))

    def test_vulnerable_record_without_a_mate_refuses_to_measure(self):
        with pytest.raises(SystemExit, match="no patched mate"):
            assert_pairs_are_distinct([{"pair_id": "lonely", "kind": "vulnerable",
                                        "source": VULNERABLE}])


class TestMitigationCounts:
    def _result(self, named: dict[str, set[str]]) -> ToolResult:
        return ToolResult(name="t", named=named)

    def test_a_tool_that_notices_the_fix_is_counted_as_noticed(self):
        records = _records(VULNERABLE, PATCHED)
        result = self._result({
            record_id(records[0]): {"CWE-22"},
            record_id(records[1]): set(),
        })
        assert mitigation_counts(records, result, {}) == (1, 0, 1)

    def test_a_tool_that_keeps_reporting_is_counted_as_missed(self):
        records = _records(VULNERABLE, PATCHED)
        result = self._result({
            record_id(records[0]): {"CWE-22"},
            record_id(records[1]): {"CWE-22"},
        })
        assert mitigation_counts(records, result, {}) == (1, 1, 0)

    def test_a_tool_that_never_fired_is_out_of_the_population_not_a_pass(self):
        # This is the bug the harness had: 0/0 read as "noticed everything".
        records = _records(VULNERABLE, PATCHED)
        result = self._result({record_id(records[1]): {"CWE-22"}})
        assert mitigation_counts(records, result, {}) == (0, 0, 0)

    def test_only_the_named_classes_are_compared(self):
        # A tool naming a different class on the patched side has still stopped
        # reporting *this* class, which is what the column measures.
        records = _records(VULNERABLE, PATCHED)
        result = self._result({
            record_id(records[0]): {"CWE-22"},
            record_id(records[1]): {"CWE-89"},
        })
        assert mitigation_counts(records, result, {}) == (1, 0, 1)


class TestMitigationPercent:
    def test_zero_population_does_not_read_as_a_perfect_score(self):
        assert Coverage(name="t", measurable_pairs=0).mitigation_percent == 0.0

    def test_half_noticed(self):
        coverage = Coverage(
            name="t", measurable_pairs=10, noticed_mitigation=5, missed_mitigations=5
        )
        assert coverage.mitigation_percent == 50.0

class TestPublishedComparisonIsComplete:
    """Every instrument that ran must be documented, and its figures must match.

    The competitor table grew from three instruments to six, and a comparison that
    quietly drops an instrument is worse than one that never ran it: excluding ruff
    because it publishes no CWE would have removed the second-best sink score from
    the table. These assertions fail if a run produces a tool the docs do not
    mention, or if a published figure disagrees with the JSON it came from.
    """

    EXPECTED = {"syrth", "bandit", "semgrep", "semgrep-owasp", "semgrep-python", "ruff"}

    @staticmethod
    def _report() -> dict:
        import json

        path = pathlib.Path(__file__).resolve().parents[1] / "data" / "competitor_benchmark.json"
        assert path.exists(), "run benchmarks/competitors.py --json before this check"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_every_measured_instrument_is_documented(self):
        report = self._report()
        assert set(report["tools"]) == self.EXPECTED, (
            "the published comparison and the instruments disagree; a tool that ran "
            "but is not in the table is a comparison that was curated"
        )

    def test_published_figures_match_the_json(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        report = self._report()
        for name in ("README.md", "docs/benchmark.md"):
            text = (root / name).read_text(encoding="utf-8")
            for instrument, values in report["tools"].items():
                assert f"{values['covered']}/{values['expected']}" in text, (
                    f"{name} does not carry {instrument}'s class coverage"
                )
                assert f"{values['sinks_covered']}/{values['sinks_expected']}" in text, (
                    f"{name} does not carry {instrument}'s sink coverage"
                )

    def test_sink_axis_is_measurable_for_every_instrument(self):
        # A tool with no CWE metadata must still be scorable on sinks, which is the
        # reason the axis exists. If any instrument reports zero expected sinks, the
        # axis has silently stopped measuring anything.
        report = self._report()
        for instrument, values in report["tools"].items():
            assert values["sinks_expected"] > 0, (
                f"{instrument} has no expected sinks; the sink axis is not measuring"
            )

    def test_a_tool_without_cwe_metadata_is_still_present(self):
        # ruff names 111 findings and publishes no CWE. If it is ever scored 0/0 on
        # the class axis and dropped from the table, the comparison has been curated
        # to flatter SYRTH.
        report = self._report()
        assert "ruff" in report["tools"]
        assert report["tools"]["ruff"]["unmapped_findings"] > 0, (
            "ruff suddenly reports CWE metadata; revisit how the class axis is set up"
        )
