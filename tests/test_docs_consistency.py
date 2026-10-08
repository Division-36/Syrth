"""Documentation must agree with the repository.

Documentation drifts silently: a flag is renamed, a number changes, a file
moves, and the prose keeps asserting the old fact. This test makes that loud.

Checks:
  * every internal markdown link resolves;
  * every ``--flag`` named in the docs exists in ``--help``;
  * the test count quoted in the docs equals the collected count;
  * the measurement tables in the docs match a live run of the harness.

The harness run is the expensive part, so it is skipped unless the corpus is
present. Without it, the other three checks still run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
FLAG = re.compile(r"`(--[a-z][a-z-]*)`")
TESTS_CLAIM = re.compile(r"(\d+)\s+tests\b")
PASSED_CLAIM = re.compile(r"(\d+)\s+passed")

#: Docs whose numeric tables must match a live harness run.
MEASUREMENT_DOCS = ("benchmark.md",)


def markdown_files() -> list[Path]:
    return sorted([ROOT / "README.md", *DOCS.rglob("*.md")])


class TestInternalLinks:
    @pytest.mark.parametrize(
        "path", markdown_files(), ids=lambda p: p.name
    )
    def test_every_link_resolves(self, path: Path):
        text = path.read_text(encoding="utf-8", errors="replace")
        broken = []
        for _label, target in LINK.findall(text):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            clean = target.split("#", 1)[0]
            if not clean:
                continue
            if not (path.parent / clean).resolve().exists():
                broken.append(target)
        assert not broken, f"{path.relative_to(ROOT)} links to {broken}"


class TestDocumentedFlagsExist:
    @pytest.fixture(scope="class")
    def help_text(self) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "syrth.scan", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        return result.stdout + result.stderr

    @pytest.mark.parametrize("name", ("configuration.md", "usage.md"))
    def test_flags_in_docs_exist_in_help(self, name: str, help_text: str):
        path = DOCS / name
        text = path.read_text(encoding="utf-8", errors="replace")
        missing = sorted({m for m in FLAG.findall(text) if m not in help_text})
        assert not missing, f"{name} documents flags that do not exist: {missing}"


class TestTestCountClaims:
    """Current docs must quote the live count.

    The changelog is exempt: a historical entry describing what was true when it
    was written is correct history, not a stale claim. Editing those numbers
    would destroy the record.
    """

    #: Files whose counts must match today.
    CURRENT = ("README.md", "CONTRIBUTING.md", "usage.md", "benchmark.md",
               "risk-model.md", "limitations.md")

    def test_claimed_count_matches_collection(self):
        collected = _collected_count()
        checked = 0
        for name in self.CURRENT:
            path = ROOT / name if name == "README.md" else DOCS / name
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in TESTS_CLAIM.finditer(text):
                checked += 1
                assert int(match.group(1)) == collected, (
                    f"{name} claims {match.group(1)} tests, "
                    f"pytest collects {collected}"
                )
            for match in PASSED_CLAIM.finditer(text):
                # "N passed" is legitimately total or total - 1 when one skips.
                checked += 1
                assert int(match.group(1)) in (collected, collected - 1), (
                    f"{name} claims {match.group(1)} passed, "
                    f"pytest collects {collected}"
                )
        assert checked, "no test-count claim was found to check"


class TestMeasurementTables:
    """The published numbers must match a live run, not a remembered one."""

    def test_tables_match_a_live_harness_run(self):
        corpus = ROOT / "data" / "cve_pairs.jsonl"
        if not corpus.exists():
            pytest.skip("benchmark corpus is not generated in this checkout")

        sys.path.insert(0, str(ROOT))
        from benchmarks.risk_metrics import evaluate
        from benchmarks.run_benchmarks import load_records

        metrics, _ = evaluate(load_records(str(corpus)))
        live = {
            "coverage": f"{metrics.category_coverage:.1%}",
            "covered": f"{metrics.covered_classes}/{metrics.expected_classes}",
            "rank": f"{metrics.rank_agreements}/{metrics.rank_pairs}",
            "invariance": f"{metrics.rename_invariance:.1%}",
            "invariance_n": f"{metrics.rename_stable}/{metrics.rename_checked}",
            "kill_n": f"{metrics.patch_kills}/{metrics.patch_attempts}",
        }
        for name in MEASUREMENT_DOCS:
            text = (DOCS / name).read_text(encoding="utf-8", errors="replace")
            for key in ("covered", "invariance_n", "kill_n"):
                assert live[key] in text, (
                    f"{name} does not show the current {key} ({live[key]})"
                )
            for key in ("coverage", "invariance"):
                assert live[key] in text, (
                    f"{name} does not show the current {key} ({live[key]})"
                )


def _collected_count() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--co", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    total = 0
    for line in result.stdout.splitlines():
        match = re.match(r"tests/[\w.]+\.py:\s*(\d+)", line)
        if match:
            total += int(match.group(1))
    assert total, f"could not parse collection output:\n{result.stdout[-500:]}"
    return total


def test_json_is_valid():
    """Machine-readable artefacts must parse; a broken one is worse than none."""
    for name in ("risk_benchmark.json", "benchmark.json"):
        path = ROOT / "data" / name
        if path.exists():
            json.loads(path.read_text(encoding="utf-8"))


class TestPublishedMeasurementsMatchTheDocs:
    """A published measurement must not contradict the documentation beside it.

    ``data/risk_benchmark.json`` was stale when it was first added: it held 0.905
    category coverage and a 0.855 kill rate from before the guard-as-evidence
    change, while ``docs/benchmark.md`` said 0.957 and 0.89. Nothing caught it,
    because nothing read the file.

    These assertions are deliberately narrow -- coverage and kill rate, the two
    figures the docs quote in prose -- so that regenerating a measurement after an
    unrelated code change does not fail the suite, but a measurement that is
    *wrong* does.
    """

    @staticmethod
    def _load(name: str) -> dict:
        import json

        path = ROOT / "data" / name
        assert path.exists(), f"{path} is documented as published but is missing"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_risk_benchmark_is_not_stale(self):
        report = self._load("risk_benchmark.json")
        assert report["category_coverage"] == pytest.approx(111 / 116, abs=0.001), (
            "data/risk_benchmark.json disagrees with docs/benchmark.md; regenerate "
            "it with benchmarks/risk_metrics.py --json before quoting either"
        )
        assert report["kill_rate"] == pytest.approx(89 / 100, abs=0.001)

    def test_competitor_benchmark_covers_the_whole_corpus(self):
        report = self._load("competitor_benchmark.json")
        assert report["records"] == 350
        assert report["pairs"] == 175
        assert set(report["tools"]) == {
            "syrth", "bandit", "semgrep", "semgrep-owasp",
        }

    def test_every_published_tool_reports_its_own_population(self):
        # A mitigation rate without its denominator reads as a perfect score when
        # the tool never fired, which is the bug assert_pairs_are_distinct exists
        # to prevent. The denominator has to be in the published file, and the two
        # columns have to partition it.
        report = self._load("competitor_benchmark.json")
        for name, tool in report["tools"].items():
            assert "measurable_pairs" in tool, f"{name} published without a population"
            assert (
                tool["fix_noticed"] + tool["still_flagged_after_fix"]
                == tool["measurable_pairs"]
            ), f"{name}: the mitigation columns do not partition its population"
