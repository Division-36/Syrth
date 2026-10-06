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
