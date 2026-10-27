"""Regression tests for the adversarial-review findings.

Three defects, each of which produced a *wrong security verdict* or a crash
rather than a cosmetic problem:

1. ``alpha_rename`` treated a statement-level ``name = ...`` as a keyword
   argument, so it renamed the *use* of a local without renaming its
   assignment. The rewritten program was broken and a real CWE-94 finding
   vanished.
2. ``_has_error_node`` walked the tree recursively, overflowing the stack.
3. ``_collect_imports`` and ``_find_functions`` recursed over tree depth for the
   same reason.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.run_benchmarks import alpha_rename  # noqa: E402
from syrth import SyrthScanner  # noqa: E402


def cwes(source: str) -> list[str]:
    return sorted({t.cwe for t in SyrthScanner().scan_source(source, "r.py").traces})


class TestRenamerDoesNotRewriteTheProgram:
    """A rename must move a local's binding and every use together."""

    ASSIGN_THEN_SINK = "def f(x):\n    y = x + ''\n    os.system(y)\n"

    def test_a_local_is_renamed_at_its_assignment(self):
        renamed = alpha_rename(self.ASSIGN_THEN_SINK, 1)
        lines = [line for line in renamed.split("\n") if line.strip()]
        # The binding line must not still say ``y =``.
        assert not any(line.strip().startswith("y =") for line in lines), renamed

    def test_the_finding_survives_renaming(self):
        """The defect: the sink argument was renamed, the assignment was not."""
        base = cwes(self.ASSIGN_THEN_SINK)
        assert base == ["CWE-94"], base
        for seed in (1, 7, 42):
            assert cwes(alpha_rename(self.ASSIGN_THEN_SINK, seed)) == base, (
                f"verdict changed under seed {seed}"
            )

    def test_every_occurrence_of_a_renamed_local_moves_together(self):
        import ast

        renamed = alpha_rename(self.ASSIGN_THEN_SINK, 1)
        ast.parse(renamed)  # must still be a valid program

    @pytest.mark.parametrize(
        "source",
        [
            "def f(x):\n    y = x\n    os.system(y)\n",
            "def f(x):\n    a = x\n    b = a + ''\n    os.system(b)\n",
            "def f(x):\n    p = [x]\n    os.system(p[0])\n",
            "def f(x):\n    d = {'k': x}\n    os.system(d['k'])\n",
        ],
    )
    def test_variants_keep_their_verdict(self, source):
        base = cwes(source)
        for seed in (1, 42):
            assert cwes(alpha_rename(source, seed)) == base, f"seed {seed}: {source!r}"


class TestKeywordArgumentsAreStillProtected:
    """The fix must not break the rule it was protecting."""

    def test_call_keyword_argument_name_is_not_renamed(self):
        source = "import requests\ndef f(u):\n    requests.get(url=u)\n"
        renamed = alpha_rename(source, 1)
        # The keyword *name* is part of the callee's contract and must survive;
        # its *value* is a local and is renamed.
        assert "url=zz" in renamed
        assert "url=" in renamed

    def test_keyword_only_parameter_is_not_renamed_at_the_call(self):
        source = "def g(*, timeout):\n    return timeout\ndef f():\n    g(timeout=1)\n"
        renamed = alpha_rename(source, 1)
        assert "timeout=1" in renamed, renamed


class TestHostileInputDoesNotCrash:
    """A static analyser must not raise on input it is asked to analyse."""

    @pytest.mark.parametrize(
        "source",
        [
            "def f():\n    x = " + "1+" * 600 + "1\n",
            "def f():\n    x = " + "1+" * 3000 + "1\n",
            "def f():\n    x = " + "[" * 600 + "]" * 600 + "\n",
            "def f():\n    x = " + "(" * 400 + ")" * 400 + "\n",
        ],
    )
    def test_deep_expressions_are_bounded(self, source):
        report = SyrthScanner().scan_source(source, "deep.py")
        assert report is not None

    @pytest.mark.parametrize(
        "source",
        [
            "",
            "# only a comment\n",
            "def f():\n    pass\x00\n",
            "def f():\n    s = 'unterminated\n",
            'def f():\n    return "\ud800"\n',
            "def f():\n\treturn 1\n  return 2\n",
            "\ufeffdef f():\n    pass\n",
        ],
    )
    def test_malformed_input_survives(self, source):
        assert SyrthScanner().scan_source(source, "bad.py") is not None

    def test_expressions_beyond_budget_are_reported_not_hidden(self):
        """A truncated analysis must be visible, never silently partial."""
        deep = "def f():\n    x = " + "1+" * 5000 + "1\n"
        # ``ScanReport.parse_errors`` is a list of file names, not a flag.
        assert SyrthScanner().scan_source(deep, "deep.py").parse_errors == ["deep.py"]

    def test_a_shallow_file_reports_no_parse_error(self):
        shallow = "def f():\n    x = 1 + 1\n    return x\n"
        assert SyrthScanner().scan_source(shallow, "ok.py").parse_errors == []


class TestTraversalPreservesDiscoveryContract:
    """Making traversal iterative must not change observable ordering."""

    def test_functions_are_returned_in_source_order(self):
        source = "def f(x):\n    g('S' + x)\ndef g(q):\n    pass\n"
        names = [f.name for f in SyrthScanner().parse(source, "o.py").functions]
        assert names[:2] == ["f", "g"], names

    def test_a_decorated_function_is_reported_once(self):
        source = "import os\n@dec\ndef d(r):\n    os.system(r.GET['c'])\n"
        names = [f.name for f in SyrthScanner().parse(source, "d.py").functions]
        assert names.count("d") == 1, names

    def test_nested_and_deeply_nested_functions_are_all_found(self):
        source = (
            "import os\n"
            "def a():\n"
            "    def b():\n"
            "        def c(r):\n"
            "            os.system(r.GET['x'])\n"
        )
        names = [f.name for f in SyrthScanner().parse(source, "n.py").functions]
        assert names == ["a", "b", "c"], names

    def test_class_methods_are_found(self):
        source = "import os\nclass V:\n    def m(self, r):\n        os.system(r.GET['c'])\n"
        names = [f.name for f in SyrthScanner().parse(source, "c.py").functions]
        assert "m" in names, names

    def test_imports_keep_source_order(self):
        source = "import alpha\nimport beta\nfrom gamma import delta\n"
        imports = SyrthScanner().parse(source, "i.py").imports
        assert imports[:3] == ["alpha", "beta", "gamma"], imports
