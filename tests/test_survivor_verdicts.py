"""The survivor classifier must not credit a guard it has not verified.

Two defects motivated this file, both of which moved a published number:

* scoring shapes by set overlap made an exact signature lose to a half match, so
  ``{"escape"}`` was filed under ``{"escape", "join"}``'s verdict;
* a sanitiser found *anywhere* in the added lines was treated as covering the
  value the assertion emits, so ``escape(m.run_id)`` was read as protecting a
  format placeholder fed by an unescaped ``url_for`` result.

Both fail in the direction of claiming more safety than exists, which is the one
direction this tool must not fail in.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from benchmarks.survivor_verdicts import classify, injected_names, signature, uncovered_names


def _case(vulnerable: str, patched: str) -> dict:
    return {"vulnerable_source": vulnerable, "source": patched, "label": "CWE-79"}


class TestSignatureMatch:
    def test_exact_signature_wins_over_a_partial_overlap(self):
        case = _case(
            "def render(x):\n    return x\n",
            "def render(x):\n    title = escape(x)\n    return Markup(title)\n",
        )
        assert signature(case) == frozenset({"escape"})
        verdict, _, _ = classify(case)
        # {"escape"} is its own shape; it must not be captured by {"escape","join"}.
        assert verdict == "fixed"


class TestClaimCoverage:
    AIRFLOW = (
        "def dag_run_link(v, c, m, p):\n"
        "    url = url_for('airflow.graph', dag_id=m.dag_id)\n"
        "    title = escape(m.run_id)\n"
        "    return Markup('<a href=\"{url}\">{title}</a>'.format(**locals()))\n"
    )

    def test_injected_names_come_from_the_assertion_not_the_function(self):
        assert injected_names(_case("def f():\n    pass\n", self.AIRFLOW)) == {"url", "title"}

    def test_escaping_one_placeholder_does_not_close_the_claim(self):
        # title is escaped; url is not. The verdict has to be uncertainty,
        # because url still reaches the href attribute.
        verdict, _, why = classify(_case("def f():\n    pass\n", self.AIRFLOW))
        assert verdict == "uncertain"
        assert "url" in why

    def test_escaping_every_placeholder_does_close_the_claim(self):
        patched = (
            "def link(m):\n"
            "    url = escape(m.dag_id)\n"
            "    title = escape(m.run_id)\n"
            "    return Markup('<a href=\"{url}\">{title}</a>'.format(**locals()))\n"
        )
        verdict, _, _ = classify(_case("def f():\n    pass\n", patched))
        assert verdict == "fixed"

    def test_plain_assignment_is_not_sanitisation(self):
        # url_for is not a sanitiser, so assigning through it leaves url exposed.
        case = _case("def f():\n    pass\n", self.AIRFLOW)
        assert "url" in uncovered_names({"url", "title"}, case, {"escape"})


class TestNonMarkupClaimsAreUnaffected:
    def test_containment_shape_still_classifies_as_unmodelled_guard(self):
        case = _case(
            "def f():\n    return open(p)\n",
            "def f():\n    if os.path.commonpath([r, p]) != r:\n        raise ValueError()\n"
            "    return open(p)\n",
        )
        verdict, _, _ = classify(case)
        assert verdict == "unmodelled_guard"
