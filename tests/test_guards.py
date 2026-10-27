"""Guard recognition: the fixes that removed the false alarms.

Before these changes a guard was recorded but could not affect the verdict,
because ``MIN_TAINT_CONFIDENCE`` (0.55) sat above the reporting threshold (0.5),
so ``PARTIAL_MITIGATION_FACTOR`` could never demote a finding. Guard
classification also had ``in`` and ``not in`` the wrong way round, the strength
was written to one ``TraceStep`` field and read from another, and the pattern
extractor left the opening quote attached to every regex literal.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.run_benchmarks import alpha_rename, renameable_names  # noqa: E402
from syrth import SyrthScanner  # noqa: E402
from syrth.parser.guards import (  # noqa: E402
    _regex_is_path_safe,
)

REPORTING_THRESHOLD = 0.5


def analyse(source: str):
    return SyrthScanner().scan_source(source, "guard.py")


def confirmed(source: str) -> list[tuple[str, float, tuple]]:
    return [
        (f.cwe, f.confidence, tuple(f.origins))
        for f in analyse(source).findings
        if f.confidence >= REPORTING_THRESHOLD
    ]


class TestGuardDemotion:
    """A terminating guard must push a flow below the reporting threshold."""

    def test_allowlist_guard_demotes_below_threshold(self):
        source = (
            "import subprocess\n"
            "def view(request):\n"
            "    cmd = request.GET['c']\n"
            "    if cmd not in ('ls', 'pwd'):\n"
            "        return 'no'\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        assert not confirmed(source), "an allowlist guard must not stay a finding"

    def test_unguarded_flow_stays_a_finding(self):
        source = (
            "import subprocess\n"
            "def view(request):\n"
            "    subprocess.run(request.GET['c'], shell=True)\n"
        )
        found = confirmed(source)
        assert found, "an unguarded flow must still be reported"
        assert found[0][1] >= 0.8

    def test_denylist_is_weaker_than_allowlist(self):
        allow = (
            "import subprocess\n"
            "def view(request):\n"
            "    c = request.GET['c']\n"
            "    if c not in ('ls', 'pwd'):\n"
            "        return\n"
            "    subprocess.run(c, shell=True)\n"
        )
        deny = (
            "import subprocess\n"
            "def view(request):\n"
            "    c = request.GET['c']\n"
            "    if c in ('rm -rf /',):\n"
            "        return\n"
            "    subprocess.run(c, shell=True)\n"
        )
        scores = {}
        for label, source in (("allow", allow), ("deny", deny)):
            traces = analyse(source).traces
            scores[label] = max(t.confidence for t in traces)
        assert scores["allow"] < scores["deny"] < 0.5

    def test_equality_guard_is_recognised(self):
        source = (
            "import subprocess\n"
            "def view(request):\n"
            "    c = request.GET['c']\n"
            "    if c != 'ls':\n"
            "        return\n"
            "    subprocess.run(c, shell=True)\n"
        )
        assert not confirmed(source)


class TestRegexGuard:
    """``if not re.match(r"^[a-z0-9_]+\\.log$", name): return``."""

    def test_charset_regex_demotes_path_traversal(self):
        source = (
            "import os, re\n"
            "def view(request):\n"
            "    name = request.GET.get('f')\n"
            "    if not re.match(r'^[a-z0-9_]+\\.log$', name):\n"
            "        return 'bad'\n"
            "    open(os.path.join('/var/log', name))\n"
        )
        assert not confirmed(source)

    @pytest.mark.parametrize(
        "pattern, expected",
        [
            (r"^[a-z0-9_]+$", True),
            (r"^[a-z0-9_]+\.log$", True),
            (r"^[\w-]+$", True),
            (r"^[0-9]{1,10}$", True),
            (r"^.*$", False),
            (r"^.+$", False),
            (r"^[a-z]+/[a-z]+$", False),
            (r"^[^/]+$", False),
            (r"^\D+$", False),
        ],
    )
    def test_path_safety_of_patterns(self, pattern, expected):
        assert _regex_is_path_safe(pattern) is expected

    def test_non_literal_pattern_is_not_a_guard(self):
        source = (
            "import os, re\n"
            "def view(request, pattern):\n"
            "    name = request.GET.get('f')\n"
            "    if not re.match(pattern, name):\n"
            "        return 'bad'\n"
            "    open(os.path.join('/var/log', name))\n"
        )
        # A pattern supplied at runtime proves nothing about the value, so the
        # flow must still be reported. Recognising it would be unsound.
        assert confirmed(source)


class TestRenamerSoundness:
    """The invariance metric is only meaningful if renaming is sound."""

    def test_free_names_are_not_renamed(self):
        source = (
            "def view(request):\n"
            "    return render_to_response('x.html', {'a': request.POST})\n"
        )
        assert "render_to_response" not in renameable_names(source)
        assert "render_to_response" in alpha_rename(source, 42)

    def test_locals_are_renamed(self):
        source = "def view(request):\n    payload = request.POST\n    return payload\n"
        assert "request" in renameable_names(source)
        assert "payload" in renameable_names(source)

    def test_imported_names_are_never_renamed(self):
        source = (
            "from django.shortcuts import render_to_response\n"
            "def view(request):\n"
            "    return render_to_response('x.html', {'a': request.POST})\n"
        )
        renamed = alpha_rename(source, 42)
        assert "render_to_response" in renamed
        assert "shortcuts" in renamed

    def test_backslash_continuation_is_preserved(self):
        source = (
            "def view(a, b, c):\n"
            "    if a or b \\\n"
            "            or c:\n"
            "        return 1\n"
            "    return 2\n"
        )
        renamed = alpha_rename(source, 42)
        compile(renamed, "<renamed>", "exec")
        assert "\\\n" in renamed
        assert renamed.count("\n") == source.count("\n")
