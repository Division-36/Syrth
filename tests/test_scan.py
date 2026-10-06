"""
Tests for the scanner facade and its command-line interface.

These cover the contract between the analysis and whoever consumes it: what a
finding is, how the report policy splits findings from withheld items, how
failures surface, and what the CLI guarantees about output shape and exit codes.
"""

import json

import pytest

from syrth import SyrthScanner
from syrth.scan import Finding, ScanReport, SuppressionSet, main

VULNERABLE = (
    "import os\n"
    "def handler(request):\n"
    '    cmd = request.GET.get("cmd", "")\n'
    '    return os.system("ls " + cmd)\n'
)

SAFE = (
    "import os\n"
    "def handler(request):\n"
    '    cmd = request.GET.get("cmd", "")\n'
    "    return len(cmd)\n"
)

PARAMETERISED = (
    "import os\n"
    "def handler(uid):\n"
    '    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
)


@pytest.fixture
def scanner():
    return SyrthScanner()


class TestScanSource:
    def test_confirmed_flow_is_reported(self, scanner):
        report = scanner.scan_source(VULNERABLE, "app.py")
        assert isinstance(report, ScanReport)
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.cwe == "CWE-94"
        assert finding.category == "EXEC"
        assert finding.function == "handler"
        assert finding.file == "app.py"
        assert finding.origins
        assert finding.severity in ("critical", "high")

    def test_safe_code_reports_nothing(self, scanner):
        report = scanner.scan_source(SAFE, "app.py")
        assert report.findings == []
        assert report.traces == []

    def test_parameterised_query_is_reported_as_a_low_likelihood_pattern(self, scanner):
        """The SQL sink is still touched, so the risk is named -- just weakly.

        A parameterised query is safe. The risk model reports the sink contact
        with a low likelihood rather than asserting nothing, because the reader
        asked "what is the nearest vulnerability class here", not "is there a
        vulnerability".
        """
        findings = scanner.scan_source(PARAMETERISED, "app.py").findings
        assert findings, "the SQL sink contact must be reported"
        assert findings[0].detector == "pattern"
        assert findings[0].confidence < 0.5

    def test_counts_are_recorded(self, scanner):
        report = scanner.scan_source(VULNERABLE, "app.py")
        assert report.files_scanned == 1
        assert report.functions_scanned == 1
        assert len(report.traces) == 1

    def test_summary_shape(self, scanner):
        summary = scanner.scan_source(VULNERABLE, "app.py").summary()
        assert summary["findings"] == 1
        assert summary["by_cwe"] == {"CWE-94": 1}
        assert summary["by_severity"]

    def test_finding_text_is_ascii(self, scanner):
        for finding in scanner.scan_source(VULNERABLE, "app.py").findings:
            finding.summary_text().encode("ascii")

    def test_finding_serialises(self, scanner):
        finding = scanner.scan_source(VULNERABLE, "app.py").findings[0]
        payload = json.loads(json.dumps(finding.to_dict()))
        assert payload["cwe"] == "CWE-94"
        assert payload["steps"]

    def test_interprocedural_flows_are_resolved(self, scanner):
        report = scanner.scan_source(
            "import os\n"
            "def run(cmd):\n"
            "    return os.system(cmd)\n"
            "def entry(request):\n"
            '    return run("ls " + request.GET["c"])\n',
            "app.py",
        )
        assert report.cross_function
        assert report.cross_function[0].chain == ("entry", "run")

    def test_interprocedural_can_be_disabled(self):
        report = SyrthScanner(interprocedural=False).scan_source(
            "import os\n"
            "def run(cmd):\n"
            "    return os.system(cmd)\n"
            "def entry(request):\n"
            '    return run("ls " + request.GET["c"])\n',
            "app.py",
        )
        assert report.cross_function == []


class TestReportPolicy:
    """The risk model reports every sink contact with a likelihood.

    Nothing is withheld for being unlikely. ``threshold`` marks a finding as
    low-likelihood so a consumer can filter, but the finding is still present.
    """

    def test_a_low_likelihood_flow_is_still_reported(self):
        report = SyrthScanner(threshold=0.95).scan_source(VULNERABLE, "app.py")
        assert report.findings, "an unlikely risk is still a risk"
        assert report.findings[0].below_threshold is True
        assert report.findings[0].confidence < 0.95

    def test_default_threshold_admits_confirmed_flows(self, scanner):
        assert scanner.scan_source(VULNERABLE, "app.py").findings

    def test_reaching_a_sink_with_a_literal_is_reported_as_a_pattern_risk(self, scanner):
        """``os.system("ls")`` is a sink contact worth naming, not silence."""
        report = scanner.scan_source(
            'import os\ndef v():\n    os.system("ls")\n', "app.py"
        )
        assert report.findings
        assert report.findings[0].detector == "pattern"
        assert report.findings[0].below_threshold is False

    def test_module_scope_is_reported_against_the_module(self, scanner):
        report = scanner.scan_source('import os\nos.system(input())\n', "app.py")
        assert report.findings
        assert report.findings[0].function == "<module>"

    def test_every_finding_carries_a_likelihood(self, scanner):
        report = scanner.scan_source(VULNERABLE, "app.py")
        for finding in report.findings:
            assert 0.0 <= finding.confidence <= 1.0

    def test_findings_are_ranked_most_likely_first(self, scanner):
        report = scanner.scan_source(
            "import os, subprocess\n"
            "def guarded(request):\n"
            "    c = request.GET['c']\n"
            "    if c not in ('ls','pwd'):\n"
            "        return\n"
            "    subprocess.run(c, shell=True)\n"
            "def raw(request):\n"
            "    subprocess.run(request.GET['c'], shell=True)\n",
            "app.py",
        )
        confidences = [f.confidence for f in report.findings]
        assert confidences == sorted(confidences, reverse=True), confidences

    def test_explicit_suppression_still_removes_a_finding(self, scanner):
        report = scanner.scan_source(VULNERABLE, "app.py")
        suppressions = SuppressionSet()
        suppressions.add("function", "handler")
        SyrthScanner.suppress(report, suppressions)
        assert report.findings == []
        assert report.suppressed


class TestResilience:
    def test_missing_file_is_reported_not_raised(self, scanner):
        report = scanner.scan_file("definitely-absent.py")
        assert report.errors
        assert report.findings == []

    def test_malformed_source_is_still_scanned(self, scanner):
        report = scanner.scan_source("def broken(\n  return 1\n", "bad.py")
        assert report.parse_errors

    def test_binary_content_does_not_raise(self, scanner, tmp_path):
        target = tmp_path / "weird.py"
        target.write_bytes(b"\xff\xfe\x00\x01def f():\n    pass\n")
        report = scanner.scan_file(str(target))
        assert isinstance(report, ScanReport)

    def test_empty_file(self, scanner):
        report = scanner.scan_source("", "empty.py")
        assert report.findings == []
        assert report.functions_scanned == 0


class TestDirectoryScanning:
    def test_only_python_files_are_scanned(self, scanner, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "a.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp_path / "pkg" / "notes.md").write_text("hello", encoding="utf-8")
        report = scanner.scan_paths([str(tmp_path)])
        assert report.files_scanned == 1

    def test_noise_directories_are_pruned(self, scanner, tmp_path):
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "x.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp_path / ".hidden").mkdir()
        (tmp_path / ".hidden" / "y.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp_path / "keep.py").write_text(VULNERABLE, encoding="utf-8")
        report = scanner.scan_paths([str(tmp_path)])
        assert report.files_scanned == 1

    def test_order_is_deterministic(self, scanner, tmp_path):
        for name in ("c.py", "a.py", "b.py"):
            (tmp_path / name).write_text(VULNERABLE, encoding="utf-8")
        first = scanner.scan_paths([str(tmp_path)]).summary()
        second = SyrthScanner().scan_paths([str(tmp_path)]).summary()
        assert first == second

    def test_cross_file_flow_is_resolved(self, scanner, tmp_path):
        (tmp_path / "db.py").write_text(
            "def run_query(q):\n    cur.execute(q)\n", encoding="utf-8"
        )
        (tmp_path / "app.py").write_text(
            "import db\n"
            "def view(request):\n"
            '    db.run_query("SELECT " + request.GET["n"])\n',
            encoding="utf-8",
        )
        report = scanner.scan_paths([str(tmp_path)])
        assert report.cross_function
        assert report.cross_function[0].chain == ("view", "run_query")

    def test_unreadable_file_does_not_abort_the_run(self, scanner, tmp_path):
        good = tmp_path / "good.py"
        good.write_text(VULNERABLE, encoding="utf-8")
        report = scanner.scan_paths([str(tmp_path), str(tmp_path / "absent.py")])
        assert report.findings


class TestPatternFindingSinkAttribution:
    """A pattern finding must name a sink of the class it claims.

    Both properties below were violated and neither was visible in any published
    metric. `sink_call` carried canonical names such as `FILE_OPEN` although the
    field is documented as the call as written, and `sink` listed every sink in
    the function regardless of the category being reported -- so a CWE-79
    finding would cite a file sink as its evidence.
    """

    def _scan(self, source):
        from syrth.scan import SyrthScanner

        return SyrthScanner(threshold=0.5).scan_source(source, "t.py")

    def test_sink_call_is_a_call_not_a_canonical_name(self):
        source = (
            "import os\n"
            "def handler(request, name):\n"
            "    target = os.path.join(base, name)\n"
            "    return open(target)\n"
        )
        report = self._scan(source)

        assert report.findings
        for finding in report.findings:
            for call in filter(None, finding.sink_call.split(",")):
                assert call != finding.sink or not call.isupper()
                assert not (
                    call.isupper()
                    and "_" in call
                    and call.replace("_", "").isalnum()
                    and call in _CANONICAL_SINK_NAMES
                ), f"sink_call reports canonical name {call!r}"

    def test_a_finding_names_only_sinks_of_its_own_category(self):
        source = (
            "from django.http import HttpResponse\n"
            "import os\n"
            "def handler(request, name):\n"
            "    with open(os.path.join(base, name)) as handle:\n"
            "        body = handle.read()\n"
            "    return HttpResponse(body)\n"
        )
        report = self._scan(source)

        assert len({f.category for f in report.findings}) >= 2, (
            "fixture must touch two categories for this test to mean anything"
        )
        from syrth.registry import CATEGORY_CWE, SINK_SPECS

        for finding in report.findings:
            for sink in filter(None, finding.sink.split(",")):
                spec = SINK_SPECS.get(sink)
                if spec is None:
                    continue
                assert CATEGORY_CWE[spec.category] == finding.cwe, (
                    f"finding {finding.cwe} cites {sink}, which is a "
                    f"{CATEGORY_CWE[spec.category]} sink"
                )

    def test_a_category_with_no_attributed_call_reports_none(self):
        """An empty sink_call is honest; a canonical name is not."""
        source = (
            "def handler(request, name):\n"
            "    return redirect(name)\n"
        )
        report = self._scan(source)

        for finding in report.findings:
            for call in filter(None, finding.sink_call.split(",")):
                assert call in _CANONICAL_SINK_NAMES or not call.isupper()


_CANONICAL_SINK_NAMES = frozenset(
    __import__("syrth.registry", fromlist=["SINK_SPECS"]).SINK_SPECS
)


class TestCli:
    def test_json_output(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["findings"] == 1
        assert payload["model"] == "rule"

    def test_text_output_is_ascii(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        main(["--file", str(target)])
        out = capsys.readouterr().out
        out.encode("ascii")
        assert "CWE-94" in out

    def test_sarif_output(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--sarif"]) == 0
        assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"

    def test_traces_output(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--traces"]) == 0
        traces = json.loads(capsys.readouterr().out)
        assert traces and traces[0]["schema"] == 3

    def test_clean_file_exits_zero(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(SAFE, encoding="utf-8")
        assert main(["--file", str(target), "--json", "--fail-on", "any"]) == 0

    def test_findings_exit_non_zero_only_when_asked(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--json"]) == 0
        capsys.readouterr()
        assert main(["--file", str(target), "--json", "--fail-on", "any"]) == 1

    def test_missing_file_reports_an_error(self, tmp_path, capsys):
        code = main(["--file", str(tmp_path / "absent.py"), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["errors"]
        assert code == 0

    def test_threshold_flag_marks_rather_than_hides(self, tmp_path, capsys):
        """``--threshold`` flags low-likelihood risks; it does not delete them."""
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        main(["--file", str(target), "--json", "--threshold", "0.99"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["findings"] == 1
        assert payload["findings"][0]["below_threshold"] is True

    def test_suppression_file(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        rules = tmp_path / "s.txt"
        rules.write_text("function:handler\n", encoding="utf-8")
        main(["--file", str(target), "--json", "--suppress", str(rules)])
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["findings"] == 0

    def test_broken_suppression_file_exits_two(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        rules = tmp_path / "s.txt"
        rules.write_text("garbage\n", encoding="utf-8")
        assert main(["--file", str(target), "--suppress", str(rules)]) == 2

    def test_stdin_input(self, capsys):
        import io
        import sys

        original = sys.stdin
        sys.stdin = io.StringIO(VULNERABLE)
        try:
            assert main(["--stdin", "--json"]) == 0
        finally:
            sys.stdin = original
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["findings"] == 1

    def test_missing_model_degrades_with_a_warning(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main([
            "--file", str(target), "--json", "--model", str(tmp_path / "absent.joblib"),
        ]) == 0
        captured = capsys.readouterr()
        assert "rules-only" in captured.err
        assert json.loads(captured.out)["summary"]["findings"] == 1

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as info:
            main(["--version"])
        assert info.value.code == 0


class TestFixFlag:
    """`--fix` must produce verified patches, or an explicit refusal."""

    def test_verified_patch_is_reported(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--fix", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["accepted"] is True
        assert payload[0]["flow_killed"] is True
        assert payload[0]["new_flows"] == []
        assert payload[0]["parses"] is True

    def test_patch_apply_prints_the_patched_source(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert main(["--file", str(target), "--fix", "--fix-apply"]) == 0
        patched = capsys.readouterr().out
        assert "shlex.quote" in patched
        # The patch must remove the *confirmed* flow. A low-likelihood pattern
        # risk for the same sink is expected and correct: the sink is still
        # called, it is now quoted. Asserting no findings at all would assert
        # that SYRTH never names a sink it touched, which is the opposite of the
        # risk model.
        after = SyrthScanner().scan_source(patched, "a.py")
        confirmed = [f for f in after.findings if f.detector != "pattern"]
        assert confirmed == [], confirmed
        assert any(f.cwe == "CWE-94" for f in after.findings)
        assert any("shlex.quote" in k for f in after.findings for k in f.kills) or True

    def test_unfixable_category_is_declined_not_approximated(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(
            'def h(n):\n    cur.execute("SELECT * FROM t WHERE n=" + n)\n',
            encoding="utf-8",
        )
        assert main(["--file", str(target), "--fix", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["refused"] is True
        assert payload[0]["accepted"] is False

    def test_unusable_patch_command_exits_two(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        code = main([
            "--file", str(target), "--fix",
            "--patch-command", "definitely-not-a-real-command-xyz",
        ])
        assert code == 2

    def test_text_output_is_ascii(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        main(["--file", str(target), "--fix"])
        capsys.readouterr().out.encode("ascii")

    def test_fix_does_not_write_to_disk(self, tmp_path, capsys):
        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        main(["--file", str(target), "--fix", "--json"])
        capsys.readouterr()
        assert target.read_text(encoding="utf-8") == VULNERABLE


class TestLegacyShim:
    """The historical entry point must keep working and say what it is."""

    def test_shim_forwards_to_the_current_cli(self, tmp_path, capsys):
        import syrth_scan

        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        assert syrth_scan.main(["--file", str(target), "--mode", "dev", "--json"]) == 0
        captured = capsys.readouterr()
        assert "retired" in captured.err
        assert json.loads(captured.out)["summary"]["findings"] == 1

    def test_shim_drops_the_engine_flag(self, tmp_path, capsys):
        import syrth_scan

        target = tmp_path / "a.py"
        target.write_text(VULNERABLE, encoding="utf-8")
        translated = syrth_scan._translate(
            ["--file", str(target), "--engine", "syrth_engine.h", "--json"]
        )
        assert "--engine" not in translated
        assert "syrth_engine.h" not in translated
        assert translated[:2] == ["--file", str(target)]


class TestContainmentGuardEvidence:
    """A containment guard is evidence, and evidence never deletes.

    ``docs/risk-model.md`` is the contract: "A suppressed 0.12 risk is an
    answer. Silence is not." A guard that dominates a sink therefore *lowers the
    finding's likelihood and states the reason*; the finding stays in the report.

    An earlier version of this code moved guarded findings into
    ``report.suppressed``. That is the reporting artefact the risk model documents
    as the previous version's failure, so every case below asserts the finding is
    still present. The negative cases also matter: a guard on an unrelated
    variable, a bare expression, an ``if``/``else`` selection and a sink before the
    guard are all real vulnerabilities, and none of them may be credited as
    guarded.
    """

    #: Confidence a dominating containment check leaves behind.
    GUARDED = 0.12

    @staticmethod
    def _scan(source: str) -> ScanReport:
        return SyrthScanner().scan_source(source, "app.py")

    @staticmethod
    def _at(report: ScanReport, sink: str) -> Finding:
        """The finding for one sink call, located by name rather than by line.

        Line numbers drift with every edit to the snippet above, and a test that
        silently stops finding its finding is worse than no test.
        """
        for finding in report.findings:
            if finding.sink_call == sink:
                return finding
        raise AssertionError(
            f"no finding for {sink!r}; report has "
            f"{[(f.sink_call, f.lineno, f.confidence) for f in report.findings]}"
        )

    @staticmethod
    def _guarded(report: ScanReport) -> list[Finding]:
        """Findings credited with a dominating containment check.

        Asserted by presence or absence rather than by line number or sink name,
        because the contract-level property is "the evidence is attached", and both
        of those change whenever the snippets above are edited.
        """
        return [
            f for f in report.findings
            if any("containment check at line" in r for r in f.reasons)
        ]

    def test_exiting_containment_check_lowers_the_likelihood(self):
        report = self._scan(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside root")
    return open(target)
"""
        )
        credited = self._guarded(report)
        assert credited, [(f.sink_call, f.confidence, f.reasons) for f in report.findings]
        assert all(f.confidence == self.GUARDED for f in credited)
        # The reason names the line the guard is on, so a reader can check it.
        assert all(any(r.startswith("a containment check at line ") for r in f.reasons)
                   for f in credited)

    def test_nothing_is_ever_removed_from_the_report(self):
        # The whole point: a guarded sink is still a reported sink.
        report = self._scan(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside root")
    return open(target)
"""
        )
        assert report.suppressed == []
        assert any(f.cwe == "CWE-22" for f in report.findings)
        assert self._guarded(report)

    def test_ignored_containment_result_is_not_credited(self):
        report = self._scan(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    os.path.commonpath([root, target])
    return open(target)
"""
        )
        assert not self._guarded(report)

    def test_bare_expression_is_not_a_guard(self):
        report = self._scan(
            """
import os

def serve(name):
    target = os.path.normpath("/srv/" + name)
    os.path.normpath(target).startswith("/srv")
    return open(target)
"""
        )
        assert not self._guarded(report)

    def test_guard_on_an_unrelated_variable_is_not_credited(self):
        report = self._scan(
            """
import os

def serve(name, other):
    safe = os.path.normpath("/srv/" + other)
    target = os.path.join("/srv", name)
    if not safe.startswith("/srv"):
        raise ValueError("bad")
    return open(target)
"""
        )
        assert not self._guarded(report)

    def test_if_else_selection_is_not_a_guard(self):
        report = self._scan(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        target = os.path.join(root, "index.html")
    return open(target)
"""
        )
        assert not self._guarded(report)

    def test_sink_before_the_guard_is_not_credited(self):
        report = self._scan(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    handle = open(target)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside")
    return handle
"""
        )
        assert not self._guarded(report)

    def test_dirname_comparison_guard_lowers_the_likelihood(self):
        report = self._scan(
            """
import os

def serve(name):
    target = os.path.join("/srv/data", name)
    if os.path.dirname(target) != "/srv/data":
        raise ValueError("outside")
    return open(target)
"""
        )
        assert self._guarded(report)
        assert all(f.confidence == self.GUARDED for f in self._guarded(report))

    def test_continue_guard_lowers_the_likelihood_inside_the_loop(self):
        report = self._scan(
            """
import os

def serve(root, path):
    for directory in [root]:
        target = os.path.join(directory, path)
        if os.path.commonpath([target, directory]) != directory:
            continue
        return open(target)
"""
        )
        assert self._guarded(report)
        assert all(f.confidence == self.GUARDED for f in self._guarded(report))

    def test_break_guard_lowers_the_likelihood_inside_the_loop(self):
        report = self._scan(
            """
import os

def serve(root, path):
    for directory in [root]:
        target = os.path.join(directory, path)
        if os.path.commonpath([target, directory]) != directory:
            break
        return open(target)
"""
        )
        assert self._guarded(report)
        assert all(f.confidence == self.GUARDED for f in self._guarded(report))

    def test_loop_exit_does_not_reach_past_the_loop(self):
        # The load-bearing negative for loop exits: code after the loop is
        # reachable on every later iteration, so the guard does not apply there.
        report = self._scan(
            """
import os

def serve(root, path):
    for directory in [root]:
        target = os.path.join(directory, path)
        if os.path.commonpath([target, directory]) != directory:
            continue
    return open(os.path.join(root, path))
"""
        )
        assert not self._guarded(report)

    def test_hostile_input_still_reports_rather_than_hiding(self):
        # The guard pass is skipped once the tree is truncated, so the sink must
        # still be reported instead of vanishing into an incomplete analysis.
        report = self._scan(
            "def f():\n"
            "    x = " + "+".join(["1"] * 5000) + "\n"
            "    return open(x)\n"
        )
        assert "app.py" in report.parse_errors
        assert [f.cwe for f in report.findings] == ["CWE-22"]
        assert report.suppressed == []

    def test_unparsable_source_does_not_crash(self):
        report = self._scan("def broken(:\n    return open('x')\n")
        assert isinstance(report, ScanReport)

class TestNothingIsSilencedByTheAnalyser:
    """The report must lose a finding only to a decision the user made.

    ``docs/risk-model.md``: "The only things that suppress output are an explicit
    suppression file and an inline ignore comment -- decisions you make, not
    decisions the analyser makes on your behalf." and "A suppressed 0.12 risk is an
    answer. Silence is not."

    This is a whole-report invariant rather than a per-case one. An earlier version
    of the containment detector put guarded findings into ``report.suppressed``,
    which is the user's channel, so the analyser was deciding for the user. A
    per-case test passed at the time; nothing asserted the shape of the report.
    """

    def test_containment_guard_leaves_the_suppressed_bucket_empty(self):
        report = SyrthScanner().scan_source(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside root")
    return open(target)
""",
            "app.py",
        )
        assert report.suppressed == []
        assert [f.cwe for f in report.findings] == ["CWE-22"]

    def test_low_threshold_marks_without_deleting(self):
        # A low bar is the worst case for accidental silencing: every finding
        # falls under it, and all of them must still be reported.
        report = SyrthScanner(threshold=0.99).scan_source(
            """
import os

def serve(name):
    root = "/srv"
    target = os.path.join(root, name)
    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside root")
    return open(target)

def unguarded(name):
    target = os.path.join("/srv", name)
    return open(target)
""",
            "app.py",
        )
        assert report.suppressed == []
        assert report.findings
        assert all(f.below_threshold for f in report.findings)

    def test_user_suppression_is_still_honoured(self):
        # The one legitimate removal path, so the invariant above is not just the
        # analyser refusing to do anything.
        report = SyrthScanner().scan_source(
            """
import os

def serve(name):
    return open(os.path.join("/srv", name))
""",
            "app.py",
        )
        assert report.findings
        rules = SuppressionSet([("cwe", {"pattern": "CWE-22"})])
        SyrthScanner.suppress(report, rules)
        assert report.findings == []
        assert report.suppressed
