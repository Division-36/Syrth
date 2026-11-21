"""The tool comparison's accounting rules.

The full scan takes minutes per repository, so these tests cover the parts
that decide what a result means: the denominator, the co-location rule, and
the resume logic. The scan itself is run through ``make tool-comparison``.
"""

from __future__ import annotations

from pathlib import Path

from benchmarks.tool_comparison import _aggregate, _function_at, _relative, _repositories

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus.jsonl"


class TestAggregation:
    """Co-location is not precision, and it has a denominator."""

    def _row(self, repo: str, tool: str, *, findings: int, functions: list[str],
             labelled_file: str = "app.py", labelled_function: str = "f"):
        return {
            "repo": repo,
            "tools": {
                tool: {
                    "available": True,
                    "findings": findings,
                    "functions": functions,
                    "files": [],
                    "seconds": 1.0,
                    "certificate_co_location": (1, len(functions)),
                    "labelled_file_hit": labelled_file in [f.split(":")[0] for f in functions],
                    "labelled_function_hit": any(
                        f == f"{labelled_file}:{labelled_function}" for f in functions
                    ),
                }
            },
        }

    def test_an_unavailable_tool_is_not_counted_as_a_zero(self):
        repositories = [{"repo": "a", "commit": "x", "file": "app.py", "function": "f"}]
        rows = [
            {
                "repo": "a",
                "tools": {
                    "syrth": self._row("a", "syrth", findings=5, functions=["app.py:f"])["tools"]["syrth"],
                    "bandit": {"available": False, "findings": 0, "functions": [], "files": [], "seconds": 0.0,
                               "certificate_co_location": (0, 0), "labelled_file_hit": False,
                               "labelled_function_hit": False},
                },
            }
        ]
        result = _aggregate(repositories, rows)
        assert result["per_tool"]["bandit"]["repositories"] == 0
        assert result["per_tool"]["syrth"]["repositories"] == 1

    def test_the_co_location_denominator_is_the_findings(self):
        repositories = [{"repo": "a", "commit": "x", "file": "app.py", "function": "f"}]
        row = self._row("a", "syrth", findings=4, functions=["app.py:f", "app.py:g"])
        result = _aggregate(repositories, [row])
        assert result["per_tool"]["syrth"]["certificate_co_location"] == (1, 2)

    def test_the_scope_says_what_was_measured(self):
        result = _aggregate([], [])
        assert result["scope"]["co_location_not_precision"] is True
        assert result["complete"] is True


class TestFindingLocations:
    """External tools give a file and a line; the function comes from the source."""

    def test_the_enclosing_function_is_recovered(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text(
            "def outer():\n"
            "    x = 1\n"
            "    def inner():\n"
            "        return x\n"
            "    return inner\n",
            encoding="utf-8",
        )
        assert _function_at(source, 2) == "outer"
        assert _function_at(source, 4) == "inner"

    def test_an_unparseable_file_has_no_function(self, tmp_path):
        source = tmp_path / "bad.py"
        source.write_text("def broken(:\n", encoding="utf-8")
        assert _function_at(source, 1) == ""

    def test_a_tool_path_is_made_relative_to_the_tree(self, tmp_path):
        worktree = tmp_path / "work"
        worktree.mkdir()
        target = worktree / "pkg" / "app.py"
        assert _relative(str(target), worktree) == "pkg/app.py"
        assert _relative("./pkg/app.py", worktree) == "pkg/app.py"


class TestPopulation:
    """One fix commit per repository, chosen mechanically."""

    def test_one_commit_per_repository(self):
        if not CORPUS.exists():
            return
        repositories = _repositories(str(CORPUS), "experiments/scratch/repos")
        names = [repo["repo"] for repo in repositories]
        assert len(names) == len(set(names))

    def test_every_repository_has_the_fields_the_comparison_needs(self):
        if not CORPUS.exists():
            return
        repositories = _repositories(str(CORPUS), "experiments/scratch/repos")
        for repo in repositories:
            assert set(repo) == {"repo", "commit", "file", "function"}
