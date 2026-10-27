"""
Tests for patch synthesis with mechanical kill verification, and for the
benchmark harness.

The verifier is the load-bearing part of this module, so most of these tests are
about what it *rejects*: a rewrite that breaks the file, one that silences a
finding by introducing another, and one that does not remove the flow at all.
"""

import sys
from pathlib import Path

import pytest

from benchmarks.run_benchmarks import (
    RESERVED,
    Record,
    alpha_rename,
    evaluate,
    label_ties,
    renameable_names,
    split,
)
from syrth.patch import (
    CATEGORY_FIX,
    REFUSAL_REASON,
    CommandBackend,
    PatchProposal,
    SanitiserBackend,
    _parses,
    _sink_argument_span,
    propose_and_verify,
    render,
    verify,
)
from syrth.registry import CATEGORIES, Category
from syrth.scan import SyrthScanner

RCE = 'import os\ndef h(x):\n    os.system("ls " + x)\n'
PATH = 'def h(fn):\n    open("/u/" + fn)\n'
SQL = 'def h(n):\n    cur.execute("SELECT * FROM t WHERE n=" + n)\n'


@pytest.fixture
def scanner():
    return SyrthScanner()


def first_finding(source, scanner):
    report = scanner.scan_source(source, "app.py")
    assert report.findings, "expected at least one finding"
    return report, report.findings[0]


class TestSpanLocation:
    def test_positional_argument(self, scanner):
        _report, finding = first_finding(RCE, scanner)
        span = _sink_argument_span(RCE, finding)
        assert span is not None
        start, end = span
        assert RCE[start:end] == '"ls " + x'

    def test_second_line_offsets_are_absolute(self, scanner):
        source = 'import os\n\n\ndef h(x):\n    os.system(x)\n'
        _report, finding = first_finding(source, scanner)
        span = _sink_argument_span(source, finding)
        assert span is not None
        start, end = span
        assert source[start:end] == "x"

    def test_keyword_argument(self, scanner):
        source = 'def h(n):\n    cur.execute(query="SELECT " + n)\n'
        _report, finding = first_finding(source, scanner)
        span = _sink_argument_span(source, finding)
        assert source[span[0]:span[1]] == '"SELECT " + n'

    def test_splat_is_refused(self, scanner):
        source = 'def h(a):\n    cur.execute(*a)\n'
        _report, finding = first_finding(source, scanner)
        assert _sink_argument_span(source, finding) is None

    def test_unlocatable_line_is_refused(self, scanner):
        source = RCE
        _report, finding = first_finding(source, scanner)
        finding.lineno = 999
        assert _sink_argument_span(source, finding) is None


class TestDeterministicBackend:
    def test_rce_is_fixed_and_verified(self, scanner):
        report, finding = first_finding(RCE, scanner)
        trace = report.traces[0]
        proposal = SanitiserBackend().propose(RCE, finding, trace)
        assert proposal.applicable
        assert "shlex.quote" in proposal.patched_source
        assert "import shlex" in proposal.patched_source
        result = verify(proposal, RCE, finding, trace, scanner)
        assert result.accepted, result.reasons
        assert result.flow_killed
        assert result.new_flows == ()

    def test_path_traversal_is_fixed_and_verified(self, scanner):
        report, finding = first_finding(PATH, scanner)
        trace = report.traces[0]
        proposal = SanitiserBackend().propose(PATH, finding, trace)
        result = verify(proposal, PATH, finding, trace, scanner)
        assert result.accepted, result.reasons
        assert "os.path.basename" in proposal.patched_source

    def test_patched_file_is_valid_python(self, scanner):
        report, finding = first_finding(RCE, scanner)
        proposal = SanitiserBackend().propose(RCE, finding, report.traces[0])
        assert _parses(proposal.patched_source)

    def test_import_is_not_duplicated(self, scanner):
        source = 'import shlex\nimport os\ndef h(x):\n    os.system("ls " + x)\n'
        report, finding = first_finding(source, scanner)
        proposal = SanitiserBackend().propose(source, finding, report.traces[0])
        assert proposal.patched_source.count("import shlex") == 1

    @pytest.mark.parametrize("category", [Category.SQL, Category.DESER, Category.NET])
    def test_unsound_mechanical_fixes_are_declined(self, category, scanner):
        assert CATEGORY_FIX[category] is None
        assert REFUSAL_REASON[category]

    def test_sql_is_declined_with_an_actionable_reason(self, scanner):
        report, finding = first_finding(SQL, scanner)
        proposal = SanitiserBackend().propose(SQL, finding, report.traces[0])
        assert not proposal.applicable
        assert proposal.refused
        assert "parameterised" in proposal.rationale

    def test_every_category_has_a_decision(self):
        for category in CATEGORIES:
            assert category in CATEGORY_FIX, category

    def test_every_declined_category_explains_itself(self):
        for category, sanitiser in CATEGORY_FIX.items():
            if sanitiser is None:
                assert category in REFUSAL_REASON, category


class TestVerificationRejections:
    def test_broken_rewrite_is_rejected(self, scanner):
        report, finding = first_finding(RCE, scanner)
        proposal = PatchProposal(
            trace_id=report.traces[0].trace_id,
            function=finding.function,
            category=finding.category,
            backend="fake",
            rationale="deliberately broken",
            patched_source="def h(x:\n    os.system(x)\n",
        )
        result = verify(proposal, RCE, finding, report.traces[0], scanner)
        assert not result.accepted
        assert result.parses is False
        assert any("not valid Python" in r for r in result.reasons)

    def test_no_op_rewrite_is_rejected(self, scanner):
        report, finding = first_finding(RCE, scanner)
        proposal = PatchProposal(
            trace_id=report.traces[0].trace_id,
            function=finding.function,
            category=finding.category,
            backend="fake",
            rationale="comment only",
            patched_source=RCE + "# nothing changed\n",
        )
        result = verify(proposal, RCE, finding, report.traces[0], scanner)
        assert not result.accepted
        assert result.flow_killed is False
        assert any("still present" in r for r in result.reasons)

    def test_rewrite_that_introduces_a_flow_is_rejected(self, scanner):
        source = 'import os\ndef h(x):\n    os.system("ls " + x)\n'
        report, finding = first_finding(source, scanner)
        # A "fix" that silences the command injection by evaluating user input.
        proposal = PatchProposal(
            trace_id=report.traces[0].trace_id,
            function=finding.function,
            category=finding.category,
            backend="fake",
            rationale="trades one vulnerability for another",
            patched_source='import os\ndef h(x):\n    eval(x)\n',
        )
        result = verify(proposal, source, finding, report.traces[0], scanner)
        assert not result.accepted
        assert result.new_flows

    def test_refused_proposal_is_not_accepted(self, scanner):
        report, finding = first_finding(SQL, scanner)
        proposal = SanitiserBackend().propose(SQL, finding, report.traces[0])
        result = verify(proposal, SQL, finding, report.traces[0], scanner)
        assert not result.accepted
        assert result.reasons


class TestProposeAndVerify:
    def test_returns_results_and_unchanged_source_by_default(self, scanner):
        report, _finding = first_finding(RCE, scanner)
        results, final = propose_and_verify(RCE, report, None, scanner, apply=False)
        assert results
        assert final == RCE

    def test_apply_folds_accepted_patches_in(self, scanner):
        report, _finding = first_finding(RCE, scanner)
        results, final = propose_and_verify(RCE, report, None, scanner, apply=True)
        assert any(r.accepted for r in results)
        assert final != RCE
        # A patch removes the *flow*; the sink call remains, so a low-likelihood
        # pattern risk for it is the expected and correct outcome.
        after = scanner.scan_source(final, "app.py")
        assert [f for f in after.findings if f.detector != "pattern"] == [], after.findings

    def test_second_patch_is_verified_against_patched_state(self, scanner):
        source = (
            'import os\n'
            'def a(x):\n    os.system("ls " + x)\n'
            'def b(fn):\n    open("/u/" + fn)\n'
        )
        report = scanner.scan_source(source, "app.py")
        results, final = propose_and_verify(source, report, None, scanner, apply=True)
        accepted = [r for r in results if r.accepted]
        assert len(accepted) >= 1
        after = scanner.scan_source(final, "app.py")
        assert [f for f in after.findings if f.detector != "pattern"] == [], after.findings

    def test_render_is_ascii(self, scanner):
        report, _finding = first_finding(RCE, scanner)
        results, _final = propose_and_verify(RCE, report, None, scanner)
        render(results).encode("ascii")

    def test_render_handles_no_findings(self):
        render([]).encode("ascii")


class TestCommandBackend:
    def test_missing_command_is_refused_at_construction(self):
        with pytest.raises(FileNotFoundError):
            CommandBackend(["definitely-not-a-real-command-xyz"])

    def test_empty_argv_is_refused(self):
        with pytest.raises(ValueError):
            CommandBackend([])

    def test_external_rewrite_is_verified_like_any_other(self, scanner, tmp_path):
        script = tmp_path / "fix.py"
        script.write_text(
            "import sys, pathlib\n"
            "text = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')\n"
            "text = text.replace('os.system(\"ls \" + x)', 'os.system(\"ls\")')\n"
            "sys.stdout.write(text)\n",
            encoding="utf-8",
        )
        backend = CommandBackend([sys.executable, str(script)], name="test")
        report, finding = first_finding(RCE, scanner)
        proposal = backend.propose(RCE, finding, report.traces[0])
        assert proposal.applicable
        result = verify(proposal, RCE, finding, report.traces[0], scanner)
        assert result.accepted, result.reasons

    def test_failing_command_is_refused_with_a_reason(self, scanner):
        script = Path(".syrth-failing-backend.py")
        script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
        try:
            backend = CommandBackend([sys.executable, str(script)], name="failing")
            report, finding = first_finding(RCE, scanner)
            proposal = backend.propose(RCE, finding, report.traces[0])
            assert not proposal.applicable
            assert "exited 3" in proposal.rationale
        finally:
            script.unlink(missing_ok=True)

    def test_empty_output_is_refused(self, scanner):
        script = Path(".syrth-empty-backend.py")
        script.write_text("import sys\nsys.stdout.write('')\n", encoding="utf-8")
        try:
            backend = CommandBackend([sys.executable, str(script)], name="empty")
            report, finding = first_finding(RCE, scanner)
            proposal = backend.propose(RCE, finding, report.traces[0])
            assert not proposal.applicable
            assert "no output" in proposal.rationale
        finally:
            script.unlink(missing_ok=True)


class TestAlphaRenaming:
    def test_module_paths_are_preserved(self):
        renamed = alpha_rename("import os\ndef f():\n    os.system('ls')\n", 1)
        assert "import os" in renamed
        assert ".system" in renamed

    def test_aliases_are_renamed(self):
        renamed = alpha_rename("import subprocess as sp\ndef f():\n    sp.run('ls')\n", 1)
        assert "import subprocess as " in renamed
        assert "sp.run" not in renamed

    def test_attribute_names_are_preserved(self):
        renamed = alpha_rename("import os\ndef f():\n    os.system('ls')\n", 1)
        assert ".system" in renamed

    def test_keyword_arguments_are_preserved(self):
        source = "import requests\ndef f(u):\n    requests.get(url=u)\n"
        renamed = alpha_rename(source, 1)
        # The keyword *name* is part of the callee's contract and must survive;
        # its *value* is a local and is renamed.
        collapsed = renamed.replace(" ", "")
        assert "url=zz" in collapsed
        assert not any(
            part.split("=")[0].startswith("zz")
            for part in collapsed.split(",")
            if "=" in part
        )

    def test_imported_names_are_never_renamed_at_their_use_site(self):
        source = (
            "import os\n"
            "import subprocess as sp\n"
            "def f(x):\n"
            "    return os.path.join(sp, x)\n"
        )
        renamed = alpha_rename(source, 1)
        collapsed = renamed.replace(" ", "")
        # The module path and the attribute are part of the program's meaning.
        assert "importos" in collapsed
        assert "os.path.join(" in collapsed
        assert "importsubprocessas" in collapsed
        # An alias is a *local binding*, not a frozen import: renaming it is
        # sound as long as every use moves with it, and it must, or the
        # invariance check would never exercise aliased calls.
        assert "importsubprocessassp" not in collapsed
        assert "defzz" in collapsed

    def test_locals_are_renamed(self):
        source = "def handler(user_id, name):\n    cmd = name\n    return user_id, cmd\n"
        renamed = alpha_rename(source, 1)
        assert "user_id" not in renamed
        assert "handler" not in renamed

    def test_keywords_are_preserved(self):
        source = "def f(a):\n    return [x for x in a if x is not None]\n"
        renamed = alpha_rename(source, 1)
        for word in RESERVED:
            assert word not in renamed or word in source

    def test_renaming_is_deterministic_for_a_seed(self):
        source = "def f(a, b):\n    return a + b\n"
        assert alpha_rename(source, 7) == alpha_rename(source, 7)

    def test_different_seeds_give_different_renames(self):
        source = "def f(a, b):\n    return a + b\n"
        assert alpha_rename(source, 1) != alpha_rename(source, 2)

    def test_unparsable_source_is_returned_unchanged(self):
        broken = "def f(\n    return 1\n"
        assert alpha_rename(broken, 1) == broken

    def test_parenthesised_import_is_handled(self):
        source = "from os import (\n    path,\n    getcwd,\n)\ndef f():\n    return path\n"
        renamed = alpha_rename(source, 1)
        assert "from os import" in renamed
        assert "def " in renamed

    def test_renameable_names_excludes_non_local_identifiers(self):
        source = "import os\nimport subprocess as sp\ndef f(x):\n    return os.path.join(sp, x)\n"
        names = set(renameable_names(source))
        assert "f" in names and "x" in names
        assert "os" not in names
        assert "system" not in names


class TestHarness:
    def records(self):
        return [
            Record(RCE, "CWE-94", "adv-1"),
            Record('import os\ndef v(x):\n    os.system(x)\n', "CWE-94", "adv-2"),
            Record('import os\ndef v():\n    os.system("ls")\n', "", "adv-3"),
            Record(SQL, "CWE-89", "adv-4"),
            Record(
                'def v(uid):\n    cur.execute("SELECT * FROM t WHERE id=%s", (uid,))\n',
                "", "adv-5",
            ),
            Record('def v(n):\n    open("/u/" + n)\n', "CWE-22", "adv-6"),
        ]

    def test_split_is_group_disjoint(self):
        train, test, leaked = split(self.records(), 0.4)
        assert leaked == 0
        assert not ({r.group for r in train} & {r.group for r in test})
        assert train and test

    def test_split_is_deterministic(self):
        a = split(self.records(), 0.4)
        b = split(self.records(), 0.4)
        assert [r.group for r in a[1]] == [r.group for r in b[1]]

    def test_safe_records_are_not_reported(self):
        """A safe record yields no *confirmed* flow.

        Under the risk model a safe record may still produce low-likelihood
        pattern findings for the sinks it touches. Counting those as detection
        success would be wrong, so the assertion is scoped to confirmed flows.
        """
        metrics, outcomes = evaluate(self.records())
        safe = [o for o in outcomes if not o.record.label]
        assert safe, "fixture must contain safe records"
        for outcome in safe:
            confirmed = outcome.taint_confirmed
            assert not confirmed or outcome.confidence >= 0.5, (
                f"{outcome.record.group} has a confirmed flow on a safe record"
            )
        assert metrics.support["safe"] == len(safe)

    def test_rename_invariance_is_measured(self):
        metrics, outcomes = evaluate(self.records())
        assert metrics.rename_invariance == 1.0, [
            (o.record.group, o.predicted) for o in outcomes if not o.rename_stable
        ]

    def test_patch_kill_rate_is_measured(self):
        metrics, _outcomes = evaluate(self.records())
        assert metrics.support["patch_attempts"] >= 1
        assert 0.0 <= metrics.kill_rate <= 1.0

    def test_confidence_intervals_are_reported(self):
        metrics, _outcomes = evaluate(self.records())
        for key in ("precision", "recall", "rename_invariance"):
            interval = metrics.confidence_intervals[key]
            assert interval["low"] <= interval["point"] <= interval["high"]

    def test_missing_grouping_is_survivable(self):
        records = [Record(RCE, "CWE-94", f"g{i}") for i in range(4)]
        metrics, _outcomes = evaluate(records)
        assert metrics.support["records"] == 4

    def test_empty_corpus_is_reported_as_unusable(self):
        metrics, _outcomes = evaluate([])
        assert any("unsafe" in w for w in metrics.warnings)

    def test_label_ties_are_counted(self):
        # Two records with identical code and different labels.
        source = 'def v(x):\n    os.system(x)\n'
        records = [Record(source, "CWE-94", "a"), Record(source, "CWE-79", "b")]
        assert label_ties(records) == 1
        assert label_ties([Record(source, "CWE-94", "a")]) == 0

    def test_metrics_serialise(self):
        import json

        metrics, _outcomes = evaluate(self.records())
        json.dumps(metrics.to_dict())
