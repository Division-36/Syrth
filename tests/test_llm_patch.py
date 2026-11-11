"""The repair experiment must not show the model the answer.

The experiment asks a model to fix a vulnerability. The corpus holds the real
upstream fix next to the vulnerable code, so a prompt that leaks any part of
the patched side -- or the advisory, the commit or the repository name in its
instructions -- turns the measurement into a lookup.

These tests cover the guard that enforces this, and the arithmetic the
results depend on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.llm_patch import (
    LeakageError,
    _metadata,
    assert_no_leakage,
    strip_fences,
    wilson,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus.jsonl"

VULNERABLE = (
    "import os\n"
    "\n"
    "def join(root, name):\n"
    "    return os.path.join(root, name)\n"
)

PATCHED = (
    "import os\n"
    "\n"
    "def join(root, name):\n"
    "    safe = os.path.basename(name)\n"
    "    return os.path.join(root, safe)\n"
)

META = {
    "advisory_id": "GHSA-test-0000-0000",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "repo": "exampleproject",
    "source": VULNERABLE,
}


def _prompt(source: str = VULNERABLE, instructions: str = "Fix it.\n") -> str:
    return f"{instructions}\n--- file ---\n{source}\n--- end of file ---\n"


class TestLeakageGuard:
    """The prompt must not carry the answer."""

    def test_a_clean_prompt_is_accepted(self):
        assert_no_leakage(_prompt(), "Fix it.\n", META, PATCHED)

    def test_a_new_line_of_the_patched_source_is_refused(self):
        meta = dict(META, source=VULNERABLE)
        with pytest.raises(LeakageError):
            assert_no_leakage(_prompt(PATCHED), "Fix it.\n", meta, PATCHED)

    def test_a_shared_line_is_not_a_leak(self):
        """A line the patched source shares with the vulnerable one is not the fix."""
        meta = dict(META, source=PATCHED)
        assert_no_leakage(_prompt(PATCHED), "Fix it.\n", meta, PATCHED)

    def test_the_advisory_identifier_is_refused(self):
        with pytest.raises(LeakageError):
            assert_no_leakage(
                _prompt(instructions="Fix GHSA-test-0000-0000 now.\n"), "x", META, PATCHED
            )

    def test_the_commit_is_refused(self):
        with pytest.raises(LeakageError):
            assert_no_leakage(
                _prompt(instructions="Fix 0123456789abcdef0123456789abcdef01234567.\n"),
                "x",
                META,
                PATCHED,
            )

    def test_the_repository_name_is_refused_in_the_instructions(self):
        instructions = "This is an exampleproject bug.\n"
        with pytest.raises(LeakageError):
            assert_no_leakage(_prompt(instructions=instructions), instructions, META, PATCHED)

    def test_the_repository_name_is_allowed_inside_the_source(self):
        """The source is the code under repair; it names its own project."""
        source = "import exampleproject\n\ndef f(x):\n    return exampleproject.run(x)\n"
        meta = dict(META, source=source)
        assert_no_leakage(_prompt(source), "Fix it.\n", meta, source)

    def test_a_prompt_without_the_source_is_refused(self):
        with pytest.raises(LeakageError):
            assert_no_leakage("Fix it.\n", "Fix it.\n", META, PATCHED)


class TestArithmetic:
    """The reported intervals."""

    def test_a_zero_count_has_an_interval_that_contains_zero(self):
        low, high = wilson(0, 57)
        assert low == 0.0
        assert 0 < high < 0.1

    def test_the_interval_brackets_the_estimate(self):
        low, high = wilson(30, 57)
        assert low < 30 / 57 < high

    def test_a_larger_sample_gives_a_narrower_interval(self):
        narrow = wilson(30, 570)
        wide = wilson(30, 57)
        assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])

    def test_no_attempts_is_not_a_division_by_zero(self):
        assert wilson(0, 0) == (0.0, 0.0)


class TestResponses:
    """A response arrives in whatever shape the model chose."""

    def test_plain_text_is_kept(self):
        assert strip_fences("print(1)\n") == "print(1)"

    def test_a_fenced_block_is_unwrapped(self):
        assert strip_fences("```python\nprint(1)\n```") == "print(1)"

    def test_a_fence_without_a_language_is_unwrapped(self):
        assert strip_fences("```\nprint(1)\n```") == "print(1)"


@pytest.mark.skipif(not CORPUS.exists(), reason="the corpus is not present")
class TestThePreparedPrompts:
    """The prompts the experiment actually uses."""

    def test_every_prepared_prompt_is_clean(self):
        """Re-check the prepared prompts against the patched sides.

        The harness refuses to write a leaky prompt, so this asserts that
        the file on disk is clean too, not only that the guard fired.
        """
        from benchmarks.llm_patch import _pairs
        from benchmarks.run_benchmarks import load_records

        prompts = ROOT / "data" / "llm_patch_prompts.jsonl"
        if not prompts.exists():
            pytest.skip("the prompts have not been prepared")
        metadata = _metadata(str(CORPUS))
        records = load_records(str(CORPUS))
        patched_sources = {v.pair_id: p.source for v, p in _pairs(records)}
        checked = 0
        with prompts.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                source = patched_sources[row["pair_id"]]
                assert_no_leakage(
                    row["prompt"],
                    row.get("instructions", ""),
                    metadata[row["pair_id"]],
                    source,
                )
                checked += 1
        assert checked > 0
