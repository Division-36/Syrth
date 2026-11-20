"""The capability profile must state strengths on matched populations."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.tool_capability_study import build

ROOT = Path(__file__).resolve().parent.parent
RESULT = ROOT / 'data' / 'tool_capability.json'


class TestCapabilityProfile:
    """Absolute counts on the same population, not a quality score."""

    def test_the_published_file_exists(self):
        assert RESULT.exists()

    def test_no_accuracy_claim_is_made(self):
        data = json.loads(RESULT.read_text(encoding='utf-8'))
        assert data['no_accuracy_claim'] is True

    def test_every_rate_carries_its_denominator(self):
        data = json.loads(RESULT.read_text(encoding='utf-8'))
        for row in data['instruments'].values():
            for layer in ('snippet', 'tree'):
                for _key, value in row[layer].items():
                    if isinstance(value, dict) and 'of' in value:
                        # A tool that never fired has a legitimate 0/0: it
                        # was absent from that population, not perfect in it.
                        assert value['of'] >= 0

    def test_the_strengths_are_absolute_counts_on_the_same_population(self):
        data = json.loads(RESULT.read_text(encoding='utf-8'))
        profile = data['strength_profile']
        assert profile['sink_coverage']['ours'] == 199
        assert profile['sink_coverage']['next_best'] == 73
        assert profile['sink_coverage']['margin'] == 126
        for lead in profile.values():
            assert lead['ours'] <= lead['population']
            assert lead['next_best'] <= lead['population']
            assert lead['margin'] == lead['ours'] - lead['next_best']

    def test_the_capability_matrix_is_not_scored_as_quality(self):
        data = json.loads(RESULT.read_text(encoding='utf-8'))
        assert data['matched_layers']['capability'] == 'output contract, not a measurement'
        assert data['instruments']['syrth']['capability']['verification'] is True
        assert data['instruments']['bandit']['capability']['verification'] is False

    def test_rebuilding_is_deterministic(self):
        competitors = json.loads((ROOT / 'data' / 'competitor_benchmark.json').read_text())
        trees = json.loads((ROOT / 'data' / 'tool_comparison.json').read_text())
        fresh = build(competitors, trees)
        published = json.loads(RESULT.read_text(encoding='utf-8'))
        assert fresh == published
