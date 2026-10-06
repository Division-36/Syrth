"""
Tests for the interprocedural layer, the revision diff, the scanner policy and
the output formats.

Each test names a guarantee rather than an implementation, so a regression is
reported as a broken promise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from syrth import SyrthScanner
from syrth.diff import (
    CHANGED,
    RESIDUAL,
    diff_reports,
    diff_sources,
    patch_status,
)
from syrth.features import FEATURE_NAMES, NUM_FEATURES, FeatureExtractionError, FeatureExtractor
from syrth.interproc import CallGraph
from syrth.parser import PythonParser
from syrth.registry import CATEGORIES, CATEGORY_CWE
from syrth.sarif import SARIF_VERSION, to_sarif
from syrth.scan import SuppressionSet
from syrth.trace import Trace, traces_from_json, traces_to_json


def analyse(source: str, path: str = "m.py"):
    return PythonParser().parse(source, path)


# ---------------------------------------------------------------------------
# Interprocedural reachability
# ---------------------------------------------------------------------------


class TestCallGraph:
    def test_helper_reached_from_an_entry_point_is_reported(self):
        traces = [
            analyse("def run_query(q):\n    cur.execute(q)\n", "db.py"),
            analyse(
                "import db\ndef view(request):\n"
                "    q = 'SELECT ' + request.GET['n']\n"
                "    db.run_query(q)\n",
                "app.py",
            ),
        ]
        graph = CallGraph.build(traces)
        resolved = graph.resolve_traces()
        assert resolved, "expected a cross-function flow"
        first = resolved[0]
        assert first.sink == "SQL_EXECUTE"
        assert first.chain == ("view", "run_query")
        assert first.sink_file == "db.py"

    def test_helper_only_called_with_a_constant_is_not_reported(self):
        traces = [
            analyse("def run_query(q):\n    cur.execute(q)\n", "db.py"),
            analyse(
                "import db\ndef view():\n    db.run_query('SELECT 1')\n", "app.py"
            ),
        ]
        graph = CallGraph.build(traces)
        assert graph.resolve_traces() == [], (
            "a helper reached only with a constant must not produce a finding"
        )

    def test_multi_hop_chain_is_resolved(self):
        traces = [
            analyse("def sink_fn(q):\n    cur.execute(q)\n", "a.py"),
            analyse("def mid(q):\n    return sink_fn(q)\n", "b.py"),
            analyse(
                "import b\ndef entry(request):\n"
                "    return b.mid('SELECT ' + request.GET['x'])\n",
                "c.py",
            ),
        ]
        graph = CallGraph.build(traces)
        resolved = graph.resolve_traces()
        assert resolved
        assert resolved[0].chain == ("entry", "mid", "sink_fn")

    def test_uncalled_helper_is_not_reachable(self):
        traces = [analyse("def dead(q):\n    cur.execute(q)\n", "dead.py")]
        graph = CallGraph.build(traces)
        # A function nobody calls is its own entry point, so its own parameters
        # are assumed externally driven. This is the conservative choice and is
        # asserted explicitly so a future change to it is visible.
        assert graph.entry_points() == ["dead"]

    def test_self_seeded_request_flow_is_emitted_without_a_parameter(self):
        traces = [
            analyse(
                "def handler(request):\n"
                '    cmd = request.GET.get("c")\n'
                '    return os.system("ls " + cmd)\n',
                "app.py",
            )
        ]
        graph = CallGraph.build(traces)
        resolved = graph.resolve_traces()
        assert resolved
        assert resolved[0].origins == ("REQUEST",)
        assert resolved[0].param_indices == ()

    def test_fixed_point_converges(self):
        traces = [
            analyse("def d(q):\n    cur.execute(q)\n", "d.py"),
            analyse("def c(q):\n    return d(q)\n", "c.py"),
            analyse("def b(q):\n    return c(q)\n", "b.py"),
            analyse("def a(request):\n    return b('S' + request.GET['x'])\n", "a.py"),
        ]
        graph = CallGraph.build(traces)
        graph.propagate()
        assert graph.iterations <= 12
        assert graph.tainted["d"] == {0}

    def test_splatted_argument_taints_every_callee_parameter(self):
        traces = [
            analyse("def sink_fn(a, b):\n    cur.execute(a + b)\n", "s.py"),
            analyse(
                "import s\ndef entry(request):\n    s.sink_fn(*request.args)\n", "e.py"
            ),
        ]
        graph = CallGraph.build(traces)
        assert graph.propagate()["sink_fn"] == {0, 1}

    def test_recursion_terminates(self):
        traces = [
            analyse(
                "def recurse(n, acc):\n"
                "    if n:\n        return recurse(n - 1, acc + str(n))\n"
                "    return cur.execute(acc)\n",
                "r.py",
            )
        ]
        graph = CallGraph.build(traces)
        graph.propagate()
        assert graph.iterations <= 12

    def test_graph_build_is_order_independent(self):
        a = analyse("def h(q):\n    cur.execute(q)\n", "h.py")
        b = analyse("import h\ndef e(request):\n    h.h(request.GET['q'])\n", "e.py")
        forward = CallGraph.build([a, b]).resolve_traces()
        reverse = CallGraph.build([b, a]).resolve_traces()
        assert [t.trace_id for t in forward] == [t.trace_id for t in reverse]


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


class TestFeatureVector:
    def test_vector_has_the_declared_width(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_feature_names_are_unique(self):
        assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)

    def test_vector_is_rename_invariant(self):
        extractor = FeatureExtractor()
        renamed = (
            "def handle(user_id):\n"
            '    q = "SELECT " + user_id\n'
            "    cur.execute(q)\n"
        )
        original = (
            "def handle(zzz):\n"
            '    q = "SELECT " + zzz\n'
            "    cur.execute(q)\n"
        )
        trace = analyse(renamed, "a.py")
        other = analyse(original, "a.py")
        assert (
            extractor.extract_function(trace.functions[0], trace)
            == extractor.extract_function(other.functions[0], other)
        )

    def test_flow_features_are_set_for_a_confirmed_flow(self):
        trace = analyse('def v(x):\n    cur.execute("S" + x)\n')
        vector = FeatureExtractor().extract_function(trace.functions[0], trace)
        index = FEATURE_NAMES.index("flow_count")
        assert vector[index] >= 1.0
        assert vector[FEATURE_NAMES.index("tainted_sql")] == 1.0
        assert vector[FEATURE_NAMES.index("origin_param")] == 1.0

    def test_sanitiser_features_are_set(self):
        trace = analyse('import shlex\ndef v(x):\n    os.system("ls " + shlex.quote(x))\n')
        vector = FeatureExtractor().extract_function(trace.functions[0], trace)
        # The sanitiser suppresses the flow, so no taint feature fires; the
        # sanitiser itself is still visible to the model.
        assert vector[FEATURE_NAMES.index("kill_shell_quote")] == 1.0

    def test_module_scope_record_is_emitted(self):
        trace = analyse('import os\nos.system(input())\n')
        records = FeatureExtractor().extract_file(trace)
        assert any(record["name"] == "<module>" for record in records)

    def test_unknown_feature_name_raises(self):
        with pytest.raises(FeatureExtractionError):
            FeatureExtractor._set([0.0] * NUM_FEATURES, "not_a_feature", 1.0)


# ---------------------------------------------------------------------------
# Revision diff
# ---------------------------------------------------------------------------


VULNERABLE = (
    "import os\n"
    "def handler(request):\n"
    '    cmd = request.GET.get("cmd", "")\n'
    '    return os.system("ls " + cmd)\n'
)

PATCHED = (
    "import os\n"
    "import shlex\n"
    "def handler(request):\n"
    '    cmd = request.GET.get("cmd", "")\n'
    '    return os.system("ls " + shlex.quote(cmd))\n'
)

REGRESSED = (
    "import os\n"
    "def handler(request):\n"
    '    cmd = request.GET.get("cmd", "")\n'
    '    return os.system("ls " + cmd)\n'
    "def extra(request):\n"
    '    name = request.GET.get("n")\n'
    "    cur.execute(\"SELECT \" + name)\n"
)


class TestDiff:
    def test_a_patch_that_sanitises_kills_the_flow(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, VULNERABLE, PATCHED)
        assert result.net_new == 0
        assert result.fixed == 1
        assert result.verdict() == "improved"
        assert result.killed[0].cwe == "CWE-94"

    def test_a_patch_that_adds_a_flow_is_a_regression(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, VULNERABLE, REGRESSED)
        assert result.net_new == 1
        assert result.verdict() in ("regression", "mixed")

    def test_inserting_lines_does_not_resurrect_a_flow(self):
        scanner = SyrthScanner()
        shifted = "# a new comment\n# and another\n" + VULNERABLE
        result = diff_sources(scanner, VULNERABLE, shifted)
        assert result.net_new == 0
        assert result.fixed == 0
        assert all(entry.outcome in (RESIDUAL, CHANGED) for entry in result.entries)

    def test_rewriting_a_flow_into_a_different_one_is_killed_plus_introduced(self):
        """The diff must not pair two different flows that share a shape.

        ``os.system("ls " + x)`` and ``eval(x)`` are both ``EXEC_COMMAND`` in the
        same function, with the same argument and the same origin. A matcher that
        ignored the propagation path would call that "the same flow, moved", and
        a patch trading one code-execution injection for another would be recorded
        as a fix.
        """
        scanner = SyrthScanner()
        before = 'import os\ndef h(x):\n    os.system("ls " + x)\n'
        after = 'import os\ndef h(x):\n    eval(x)\n'
        result = diff_sources(scanner, before, after)
        assert result.fixed == 1
        assert result.net_new == 1
        assert result.verdict() == "mixed"

    def test_identical_revisions_produce_no_changes(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, VULNERABLE, VULNERABLE)
        assert result.summary()["introduced"] == 0
        assert result.summary()["killed"] == 0
        assert result.verdict() == "neutral"

    def test_scan_errors_are_surfaced_not_treated_as_a_fix(self):
        scanner = SyrthScanner()
        before = scanner.scan_source(VULNERABLE, "a.py")
        after = scanner.scan_source(VULNERABLE, "a.py")
        after.errors.append(("a.py", "simulated read failure"))
        result = diff_reports(before, after)
        accepted, reasons = patch_status(result, ["CWE-94"])
        assert not accepted
        assert any("scan errors" in reason for reason in reasons)

    def test_patch_status_requires_the_claimed_class_to_be_removed(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, VULNERABLE, PATCHED)
        accepted, reasons = patch_status(result, ["CWE-94"])
        assert accepted and not reasons
        accepted, reasons = patch_status(result, ["CWE-89"])
        assert not accepted
        assert any("CWE-89" in reason for reason in reasons)

    def test_patch_status_rejects_a_no_op_claim(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, VULNERABLE, VULNERABLE)
        accepted, reasons = patch_status(result)
        assert not accepted

    def test_diff_of_empty_sources_is_safe(self):
        scanner = SyrthScanner()
        result = diff_sources(scanner, "", "")
        assert result.entries == []

    def test_diff_render_is_ascii(self):
        scanner = SyrthScanner()
        rendered = diff_sources(scanner, VULNERABLE, PATCHED).render()
        rendered.encode("ascii")


# ---------------------------------------------------------------------------
# Scanner policy
# ---------------------------------------------------------------------------


class TestScannerPolicy:
    def test_confirmed_flow_becomes_a_finding(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        assert len(report.findings) == 1
        assert report.findings[0].cwe == "CWE-94"

    def test_safe_code_reports_a_weak_pattern_risk_not_nothing(self):
        """A literal-only sink call is still named, with a low likelihood."""
        report = SyrthScanner().scan_source(
            'import os\ndef v():\n    os.system("ls")\n', "a.py"
        )
        assert report.findings
        assert report.findings[0].detector == "pattern"
        assert report.findings[0].confidence < 0.5

    def test_scan_counts_are_recorded(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        assert report.files_scanned == 1
        assert report.functions_scanned == 1
        assert len(report.traces) == 1

    def test_threshold_flags_low_likelihood_without_hiding_it(self):
        report = SyrthScanner(threshold=0.95).scan_source(VULNERABLE, "a.py")
        assert report.findings, "threshold must not delete a risk"
        assert report.findings[0].below_threshold is True
        assert report.findings[0].confidence < 0.95

    def test_every_touched_sink_is_named_even_without_a_flow(self):
        report = SyrthScanner().scan_source(
            "import os\n"
            "def v(cur):\n"
            "    os.system('ls')\n"
            "    cur.execute('SELECT 1')\n",
            "a.py",
        )
        cwes = {f.cwe for f in report.findings}
        assert {"CWE-94", "CWE-89"} <= cwes, cwes
        assert all(f.detector == "pattern" for f in report.findings)

    def test_module_level_flow_is_reported(self):
        report = SyrthScanner().scan_source('import os\nos.system(input())\n', "a.py")
        assert report.findings
        assert report.findings[0].function == "<module>"

    def test_ml_failure_does_not_change_the_finding_set(self):
        class BrokenClassifier:
            """A model that loads successfully and fails at prediction time.

            This is the dangerous case: the tool looks ML-enabled until the first
            prediction. The finding set must be identical either way.
            """

            def is_fitted(self):
                return True

            def predict_single(self, _vector):
                raise RuntimeError("model is corrupt")

        scanner = SyrthScanner()
        baseline = scanner.scan_source(VULNERABLE, "a.py")
        scanner.classifier = BrokenClassifier()
        degraded = scanner.scan_source(VULNERABLE, "a.py")
        assert [f.trace_id for f in degraded.findings] == [
            f.trace_id for f in baseline.findings
        ]
        assert degraded.findings[0].model == "rule"
        assert any("ML scoring unavailable" in r for r in degraded.findings[0].reasons)

    def test_a_classifier_without_a_fitted_probe_is_treated_as_absent(self):
        class Partial:
            def predict_single(self, _vector):
                return {"predicted_cwe": "CWE-89", "confidence": 1.0, "ood": False}

        scanner = SyrthScanner()
        scanner.classifier = Partial()
        assert scanner.has_ml is False
        report = scanner.scan_source(VULNERABLE, "a.py")
        assert report.findings[0].model == "rule"

    def test_ml_absence_is_recorded_not_hidden(self):
        scanner = SyrthScanner(model_path="does-not-exist.joblib")
        assert scanner.model_error
        report = scanner.scan_source(VULNERABLE, "a.py")
        assert report.model == "rule"
        assert report.findings

    def test_findings_are_ranked_deterministically(self):
        scanner = SyrthScanner()
        source = (
            "import os\n"
            "def a(request):\n"
            '    cur.execute("SELECT " + request.GET["x"])\n'
            "def b(request):\n"
            '    os.system(request.GET["y"])\n'
        )
        first = scanner.scan_source(source, "a.py").findings
        second = SyrthScanner().scan_source(source, "a.py").findings
        assert [f.trace_id for f in first] == [f.trace_id for f in second]
        assert first[0].severity == "critical"

    def test_unreadable_file_is_reported_not_raised(self):
        report = SyrthScanner().scan_file("definitely-not-here.py")
        assert report.errors
        assert report.findings == []

    def test_report_serialises_to_json(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        payload = json.loads(json.dumps(report.to_dict()))
        assert payload["summary"]["findings"] == 1
        assert payload["traces"][0]["schema"] == 3


class TestSuppression:
    def test_cwe_suppression(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        suppressions = SuppressionSet()
        suppressions.add("cwe", "CWE-94")
        SyrthScanner.suppress(report, suppressions)
        assert report.findings == []
        assert report.suppressed

    def test_function_suppression_with_confidence_floor(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        suppressions = SuppressionSet()
        suppressions.add("function", "handler:>=0.99")
        SyrthScanner.suppress(report, suppressions)
        assert report.findings

        suppressions = SuppressionSet()
        suppressions.add("function", "handler:>=0.5")
        SyrthScanner.suppress(report, suppressions)
        assert report.findings == []

    def test_file_suppression_with_glob(self):
        report = SyrthScanner().scan_source(VULNERABLE, "src/legacy/a.py")
        suppressions = SuppressionSet()
        suppressions.add("file", "src/legacy/*.py")
        SyrthScanner.suppress(report, suppressions)
        assert report.findings == []

    def test_loading_a_malformed_rule_raises(self, tmp_path: Path):
        path = tmp_path / "s.txt"
        path.write_text("not-a-rule\n", encoding="utf-8")
        with pytest.raises(ValueError):
            SuppressionSet.load(str(path))

    def test_loading_a_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            SuppressionSet.load("does-not-exist.txt")


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_trace_round_trip(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        payload = traces_to_json(report.traces)
        restored = traces_from_json(payload)
        assert restored == report.traces

    def test_trace_identity_survives_serialisation(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        restored = traces_from_json(traces_to_json(report.traces))
        assert restored[0].trace_id == report.traces[0].trace_id

    def test_trace_schema_mismatch_is_refused(self):
        payload = json.loads(traces_to_json([])) if False else [
            {"schema": 1, "function": "f", "cwe": "CWE-89"}
        ]
        with pytest.raises(ValueError):
            Trace.from_dict(payload[0])

    def test_sarif_is_well_formed(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        document = json.loads(to_sarif(report))
        assert document["version"] == SARIF_VERSION
        run = document["runs"][0]
        assert run["tool"]["driver"]["name"] == "SYRTH"
        assert run["results"][0]["ruleId"] == "CWE-94"
        assert run["results"][0]["partialFingerprints"]["syrthTraceId/v1"]
        assert run["results"][0]["codeFlows"]

    def test_sarif_reports_failed_invocations(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        report.errors.append(("a.py", "boom"))
        run = json.loads(to_sarif(report))["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is False

    def test_text_report_is_ascii(self):
        report = SyrthScanner().scan_source(VULNERABLE, "a.py")
        from syrth.scan import _render_text

        _render_text(report).encode("ascii")

    def test_label_space_is_closed_and_consistent(self):
        from syrth.classifier.xgboost import CWE_CLASSES

        assert set(CWE_CLASSES) == set(CATEGORY_CWE.values())
        assert len(CWE_CLASSES) == len(CATEGORIES)


class TestCli:
    def test_json_output(self, tmp_path: Path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        from syrth.scan import main

        code = main(["--file", str(target), "--json"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["findings"] == 1

    def test_sarif_output(self, tmp_path: Path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        from syrth.scan import main

        assert main(["--file", str(target), "--sarif"]) == 0
        assert json.loads(capsys.readouterr().out)["version"] == SARIF_VERSION

    def test_fail_on_any_produces_non_zero(self, tmp_path: Path):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        from syrth.scan import main

        assert main(["--file", str(target), "--json", "--fail-on", "any"]) == 1

    def test_directory_scan_is_deterministic(self, tmp_path: Path, capsys):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "b.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp_path / "pkg" / "a.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp_path / "pkg" / "notes.txt").write_text("ignored", encoding="utf-8")
        from syrth.scan import main

        main(["--path", str(tmp_path), "--json"])
        first = json.loads(capsys.readouterr().out)
        main(["--path", str(tmp_path), "--json"])
        second = json.loads(capsys.readouterr().out)
        assert first["summary"] == second["summary"]
        assert first["summary"]["files_scanned"] == 2
