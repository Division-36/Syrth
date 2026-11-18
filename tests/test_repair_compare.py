"""The direct comparison must use the same contract on both arms.

The comparison between machine patches and the real developer patches is only
meaningful if both arms are judged by the same code on the same source. These
tests cover the accounting, so a later refactor cannot silently score one arm
with different rules.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULT = ROOT / "data" / "repair_compare.json"


class TestDirectComparison:
    """Both arms, one contract."""

    def test_the_file_is_published_and_complete(self):
        assert RESULT.exists()
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        assert data["contract"]["same_population"] is True
        assert data["contract"]["same_analyser"] is True
        assert data["contract"]["same_conditions"] is True

    def test_both_arms_have_the_same_denominator(self):
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        machine = data["arms"]["machine"]
        developer = data["arms"]["developer"]
        assert machine["attempted"] == developer["attempted"] == data["compared"]

    def test_every_rate_carries_its_denominator(self):
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        for arm in data["arms"].values():
            for name, rate in arm["rates"].items():
                assert rate["of"] == arm["attempted"], name
                assert len(rate["ci95"]) == 2, name

    def test_the_documented_numbers_are_the_published_numbers(self):
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        machine = data["arms"]["machine"]
        developer = data["arms"]["developer"]
        assert (machine["flow_gone"], developer["flow_gone"]) == (31, 7)
        assert (machine["guard_only"], developer["guard_only"]) == (21, 44)

    def test_no_quality_claim_is_made(self):
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        assert data["contract"]["descriptive_not_hypothesis_test"] is True
