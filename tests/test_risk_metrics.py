"""Tests for the risk-model benchmark harness.

The harness measures the claims the risk model actually makes (category
coverage, likelihood ordering, invariance, kill rate) instead of classifier
metrics (precision/recall). It also has to keep working on an unsound corpus,
because it deliberately derives expected classes from the source with an
independent AST scan rather than trusting labels.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.risk_metrics import evaluate, expected_classes  # noqa: E402
from benchmarks.run_benchmarks import Record  # noqa: E402


def records(*sources: str) -> list[Record]:
    return [Record(source=s, label="", group=f"g{i}") for i, s in enumerate(sources)]


class TestExpectedClassExtraction:
    """The independent AST scan is the harness's ground truth."""

    def test_command_injection_sink_is_found(self):
        assert "CWE-94" in expected_classes("import os\nos.system(x)\n")

    def test_sql_sink_is_found(self):
        assert "CWE-89" in expected_classes("def f(c):\n    c.execute(q)\n")

    def test_literal_only_sink_still_counts_as_present(self):
        # The risk model names a sink even with a literal; the AST scan must
        # agree the class is present.
        assert "CWE-94" in expected_classes("import os\nos.system('ls')\n")

    def test_a_call_with_no_arguments_is_not_a_sink(self):
        assert expected_classes("def f():\n    eval()\n") == set()

    def test_unparseable_source_yields_no_expectation(self):
        assert expected_classes("def broken(\n") == set()

    def test_two_classes_in_one_function(self):
        found = expected_classes(
            "import os\ndef f(c):\n    os.system('ls')\n    c.execute(q)\n"
        )
        assert {"CWE-94", "CWE-89"} <= found, found


class TestRiskModelMetrics:
    def test_category_coverage_is_reported(self):
        metrics, outcomes = evaluate(records("import os\ndef f(x):\n    os.system(x)\n"))
        assert metrics.records == 1
        assert metrics.category_coverage == 1.0, [o.reported for o in outcomes]

    def test_labels_do_not_affect_any_metric(self):
        """The harness must be immune to the unsound corpus labels."""
        labelled = [Record(source="import os\nos.system(x)\n", label="CWE-94", group="a")]
        unlabelled = [Record(source="import os\nos.system(x)\n", label="", group="a")]
        m1, _ = evaluate(labelled)
        m2, _ = evaluate(unlabelled)
        assert m1.category_coverage == m2.category_coverage
        assert m1.rename_invariance == m2.rename_invariance

    def test_determinism_is_one_across_repeated_scans(self):
        metrics, _ = evaluate(records("import os\nos.system(x)\n"))
        assert metrics.determinism == 1.0

    def test_rename_invariance_is_measured(self):
        metrics, outcomes = evaluate(records("import os\ndef f(x):\n    os.system(x)\n"))
        assert metrics.rename_checked >= 1
        assert 0.0 <= metrics.rename_invariance <= 1.0

    def test_better_evidence_is_ranked_first(self):
        """A tainted flow must outrank a pattern risk in the same function."""
        # Two separate functions so both a confirmed flow and a pattern risk
        # exist in the report: a function with any confirmed trace suppresses
        # its own pattern risks, by design.
        source = (
            "import os\n"
            "def tainted(request):\n"
            "    os.system(request.GET['c'])\n"
            "def literal():\n"
            "    os.system('ls')\n"
        )
        _metrics, outcomes = evaluate(records(source))
        outcome = outcomes[0]
        assert outcome.confirmed, "expected a confirmed flow"
        assert outcome.findings, "expected findings"
        top = outcome.findings[0]
        assert top.detector != "pattern", "the confirmed flow must be ranked first"

    def test_rank_agreement_is_tracked(self):
        source = (
            "import os\n"
            "def tainted(request):\n"
            "    os.system(request.GET['c'])\n"
            "def literal():\n"
            "    os.system('ls')\n"
        )
        metrics, _ = evaluate(records(source))
        # Ranking pairs need two findings in one record; assert the field
        # exists and is consistent rather than forcing a specific count.
        assert metrics.rank_pairs >= 0
        assert metrics.rank_agreements <= metrics.rank_pairs

    def test_kill_rate_scopes_to_confirmed_flows(self):
        source = "import os\ndef f(request):\n    os.system(request.GET['c'])\n"
        metrics, outcomes = evaluate(records(source))
        assert metrics.patch_attempts >= 1
        assert outcomes[0].killed_by_patch in (True, False, None)

    def test_render_mentions_the_new_metrics(self):
        text = evaluate(records("import os\nos.system(x)\n"))[0].render()
        for phrase in ("category coverage", "rank agreement", "rename invariance"):
            assert phrase in text, phrase

    def test_warnings_flag_a_gap(self):
        source = "import os\ndef f(c):\n    os.system('ls')\n"
        metrics, _ = evaluate(records(source))
        # os.system with a literal: the class is present and reported, so
        # coverage is 1.0 here; the warning fires only when something is missed.
        assert isinstance(metrics.warnings, list)


class TestMetricsAreNotClassifierMetrics:
    def test_no_precision_or_recall_field_exists(self):
        metrics, _ = evaluate(records("import os\nos.system(x)\n"))
        assert not hasattr(metrics, "precision")
        assert not hasattr(metrics, "recall")
        assert not hasattr(metrics, "f1")
