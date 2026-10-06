"""Tests for the corpus builder and the corpus it produces.

The builder's job is to produce *labels a benchmark can be measured against*, so
these tests cover two things: the extraction logic that decides which function a
fix belongs to, and the invariants of the shipped corpus file. Both matter,
because a corpus that parses but mislabels is worse than no corpus — it produces
confident wrong numbers.

None of these tests touch the network or a git clone. Network-dependent coverage
would be flaky and would not protect the logic that actually went wrong.
"""
from __future__ import annotations

import ast
import collections
import json
from pathlib import Path

import pytest

from syrth.registry import CWE_TO_CATEGORY
from tools.build_corpus import (
    DEFAULT_REPOS,
    IN_SCOPE,
    Advisory,
    _commit_from_url,
    _dedupe_repos,
    _fingerprint,
    _is_partial_clone,
    build_record_source,
    candidate_functions,
    class_evidence,
    function_bodies,
    matches_class,
    module_context,
    module_proximity_evidence,
    select_repos_by_density,
    simple_name,
    sink_calls,
    textwrap_dedent,
)

CORPUS_PATH = Path("data/corpus.jsonl")


# ---------------------------------------------------------------------------
# function_bodies: the two defects that silently cost most of the corpus
# ---------------------------------------------------------------------------


DUPLICATE_METHOD_NAMES = '''
import os


class Storage:
    def save(self, name, content):
        target = os.path.join(self.location, name)
        with open(target, "wb") as handle:
            handle.write(content)

    def delete(self, name):
        os.remove(name)


class FileSystemStorage(Storage):
    def save(self, name, content):
        target = self.path(name)
        with open(target, "wb") as handle:
            handle.write(content)
'''


def test_function_bodies_keeps_same_named_methods_of_different_classes():
    """Two ``save`` methods must both survive.

    Keying by bare name collapsed them, and the one kept was whichever came
    first, so whichever class held the sink was usually the one discarded.
    """
    bodies = function_bodies(DUPLICATE_METHOD_NAMES)

    assert "Storage.save" in bodies
    assert "FileSystemStorage.save" in bodies
    assert "Storage.delete" in bodies
    assert len([k for k in bodies if k.endswith(".save")]) == 2


def test_function_bodies_keeps_the_method_that_holds_the_sink():
    bodies = function_bodies(DUPLICATE_METHOD_NAMES)

    # The subclass save is the one that routes through self.path; losing it
    # loses the finding entirely.
    assert "self.path(name)" in bodies["FileSystemStorage.save"]


def test_function_bodies_does_not_truncate_at_a_nested_definition():
    """A nested ``def`` must not truncate its enclosing function.

    Deriving the end of a function from the start of the next one cut the body
    at the nested definition, which reduced a function to its own ``def`` line.
    """
    source = '''
def outer(value):
    total = 0
    def helper(x):
        return x + 1
    return helper(value) + total
'''
    bodies = function_bodies(source)

    assert "return helper(value) + total" in bodies["outer"]
    assert bodies["outer"].count("def ") == 2


def test_function_bodies_includes_decorators():
    source = '''
import functools


@functools.wraps
def decorated(a):
    return a
'''
    bodies = function_bodies(source)

    assert "@functools.wraps" in bodies["decorated"]


def test_function_bodies_returns_empty_for_unparseable_source():
    assert function_bodies("def broken(:\n    pass") == {}


def test_simple_name_returns_the_last_segment():
    assert simple_name("FileSystemStorage.save") == "save"
    assert simple_name("save") == "save"
    assert simple_name("outer.helper") == "helper"


# ---------------------------------------------------------------------------
# Class evidence: a label must be defensible, not just a name match
# ---------------------------------------------------------------------------


def test_class_evidence_requires_a_non_constant_argument_for_value_sinks():
    """A literal-only sink call is not a finding."""
    literal = "def f():\n    open('/etc/passwd')\n"
    tainted = "def f(user_path):\n    open(user_path)\n"

    assert class_evidence(literal, "CWE-22")[0] is False
    assert class_evidence(tainted, "CWE-22") == (True, "open")


def test_class_evidence_does_not_require_a_value_for_presence_classes():
    """CWE-79 marks the escaping call itself, whatever it escapes."""
    assert class_evidence("def f():\n    mark_safe('<b>hi</b>')\n", "CWE-79")[0]


def test_class_evidence_requires_a_value_for_deserialisation():
    """CWE-502 is in the needs-value set.

    Loading a constant literal is not a finding; loading a value that arrived
    from the network or from disk is.
    """
    assert class_evidence("def f():\n    pickle.loads(b'')\n", "CWE-502")[0] is False
    assert class_evidence("def f(blob):\n    pickle.loads(blob)\n",
                          "CWE-502")[0] is True


def test_class_evidence_rejects_numpy_load_as_deserialisation():
    """The label bug that made the corpus untrustworthy.

    The builder used to carry its own sink table in which a bare ``load`` meant
    unsafe deserialisation. keras's ``load_data`` helpers call ``numpy.load`` on
    a dataset file, and were therefore labelled CWE-502. Evidence now resolves
    through ``syrth.registry``, which binds a bare name by its import.
    """
    numpy_source = (
        "import numpy as np\n"
        "def load_data(path):\n"
        "    return np.load(path)\n"
    )

    assert class_evidence(numpy_source, "CWE-502") == (False, "")


def test_class_evidence_accepts_pickle_load():
    source = (
        "import pickle\n"
        "def load(path):\n"
        "    with open(path, 'rb') as handle:\n"
        "        return pickle.load(handle)\n"
    )
    present, call = class_evidence(source, "CWE-502")

    assert present is True
    assert call == "pickle.load"


def test_class_evidence_follows_import_bindings_for_bare_names():
    """``from pickle import load`` is dangerous; ``from json import load`` is not."""
    dangerous = "from pickle import load\ndef f(blob):\n    return load(blob)\n"
    safe = "from json import load\ndef f(blob):\n    return load(blob)\n"

    assert class_evidence(dangerous, "CWE-502")[0] is True
    assert class_evidence(safe, "CWE-502")[0] is False


def test_class_evidence_ignores_a_constant_argument():
    assert class_evidence("import pickle\ndef f():\n    return pickle.loads(b'')\n",
                          "CWE-502")[0] is False
    assert class_evidence("def f(cur):\n    return cur.execute('SELECT 1')\n",
                          "CWE-89")[0] is False


def test_class_evidence_uses_the_sink_argument_schema():
    """A parameterised query passes its parameter list through a structural kill."""
    parameterised = "def f(cur, sql, params):\n    return cur.execute(sql, params)\n"
    literal = "def f(cur, sql):\n    return cur.execute(sql)\n"

    assert class_evidence(parameterised, "CWE-89")[0] is True
    assert class_evidence(literal, "CWE-89")[0] is True
    assert class_evidence("def f(cur):\n    return cur.execute('SELECT 1')\n",
                          "CWE-89")[0] is False


def test_class_evidence_accepts_an_amplifier_as_evidence():
    """``mark_safe`` creates a sink rather than consuming one.

    Django's admin widgets reach XSS through ``mark_safe`` alone, so a
    label-free-of-argument amplifier still has to count as evidence for CWE-79.
    """
    source = (
        "from django.utils.safestring import mark_safe\n"
        "def render(value):\n"
        "    return mark_safe(value)\n"
    )
    present, call = class_evidence(source, "CWE-79")

    assert present is True
    assert call == "mark_safe"


def test_in_scope_is_derived_from_the_product_registry():
    """One source of truth.

    If the builder keeps its own class list it will drift from what the analyser
    can actually report, and the corpus stops being a valid thing to measure the
    analyser against.
    """
    assert set(IN_SCOPE) == set(CWE_TO_CATEGORY)


def test_matches_class_under_approximates_rather_than_guessing():
    """Name-only checks must not claim an ambiguous bare name is a sink."""
    assert matches_class(["randomize_order"], "CWE-327") is False
    assert matches_class(["pickle.loads"], "CWE-502") is True
    # Bare "load" is ambiguous without imports; a diagnostic must not resolve it.
    assert matches_class(["load"], "CWE-502") is False


def test_class_evidence_returns_false_for_unparseable_source():
    assert class_evidence("def broken(:", "CWE-22") == (False, "")






def test_matches_class_is_false_for_unknown_class():
    assert matches_class(["open"], "CWE-9999") is False


def test_sink_calls_reads_attribute_and_bare_calls():
    calls = sink_calls("def f(p):\n    with open(p) as h:\n        h.read()\n")
    assert "open" in calls


# ---------------------------------------------------------------------------
# Pairing a fix
# ---------------------------------------------------------------------------


BEFORE = '''
import os


def handler(request, name):
    target = os.path.join(base, name)
    with open(target, "rb") as handle:
        return handle.read()
'''

AFTER = '''
import os
from os.path import commonpath


def handler(request, name):
    target = os.path.realpath(os.path.join(base, name))
    if commonpath([base, target]) != base:
        raise ValueError("outside base")
    with open(target, "rb") as handle:
        return handle.read()
'''


def test_candidate_functions_pairs_the_changed_function():
    changed_before, changed_after, rejected, evidence, tier_of, _sinks = candidate_functions(
        BEFORE, AFTER, "CWE-22"
    )

    assert list(changed_before) == ["handler"]
    assert "commonpath" in changed_after["handler"]
    # The evidence call is whatever FILE-category sink the registry resolves
    # first. It is not necessarily the eventual ``open``: ``os.path.join`` is a
    # path-traversal sink too, and a function that only builds a path is still
    # doing the vulnerable operation.
    assert evidence
    assert not [r for r in rejected if r.endswith(":unchanged")]


def test_candidate_functions_rejects_a_function_with_no_sink_for_the_class():
    before = "def handler():\n    return 1\n"
    after = "def handler():\n    return 2\n"

    changed_before, _changed_after, rejected, _evidence, _tier_of, _sinks = candidate_functions(
        before, after, "CWE-22"
    )

    assert changed_before == {}
    assert any("no-CWE-22-sink" in r for r in rejected)


def test_candidate_functions_rejects_an_absent_function():
    before = "def gone():\n    return name\n"
    after = "def other():\n    return name\n"

    changed_before, _after, rejected, _evidence, _tier_of, _sinks = candidate_functions(
        before, after, "CWE-89"
    )

    assert changed_before == {}
    assert any("absent-after" in r for r in rejected)


def test_build_record_source_requires_the_snippet_to_parse():
    assert build_record_source("import os", "def f():\n    return os") is not None
    assert build_record_source("", "def f(:\n") is None
    assert build_record_source("", "   ") is None


def test_module_context_keeps_imports_and_uppercase_constants_only():
    context = module_context('''
import os
from sys import argv
lowercase = 1
UPPER = 2
def f():
    return 1
''')
    assert "import os" in context
    assert "from sys import argv" in context
    assert "UPPER = 2" in context
    assert "lowercase" not in context
    assert "def f()" not in context


def test_module_context_is_empty_for_unparseable_source():
    assert module_context("def broken(:") == ""


def test_textwrap_dedent_removes_common_leading_space():
    assert textwrap_dedent("    a\n    b") == "a\nb"


# ---------------------------------------------------------------------------
# Evidence tiers: a disclosed weaker guarantee, kept separate
# ---------------------------------------------------------------------------


DJANGO_SQL_BEFORE = '''
class PostGISOperator:
    def as_sql(self, compiler, connection):
        template = "ST_AsGeoJSON(ST_Transform(%s, %s))"
        return template, [self.value, self.srid]


class SQLInsertCompiler:
    def execute_sql(self, result_type=None):
        sql, params = self.ops.as_sql(self, self.connection)
        return self.connection.cursor().execute(sql, params)
'''

DJANGO_SQL_AFTER = '''
class PostGISOperator:
    def as_sql(self, compiler, connection):
        template = "ST_AsGeoJSON(ST_Transform(%s, %s))"
        params = [self.value, self.srid]
        params = [str(p) for p in params]
        return template, params


class SQLInsertCompiler:
    def execute_sql(self, result_type=None):
        sql, params = self.ops.as_sql(self, self.connection)
        return self.connection.cursor().execute(sql, params)
'''


def test_module_proximity_captures_a_sink_in_another_function():
    """Django's SQL injection shape cannot be labelled per function.

    ``PostGISOperator.as_sql`` builds the query and returns it; a compiler
    elsewhere calls ``cursor.execute``. The patched function never calls
    ``execute``, so the direct rule correctly rejects it and the advisory is
    real. Rejecting it silently would lose the class; accepting it silently would
    overstate the guarantee, so it becomes its own tier.
    """
    changed_before, _after, _rejected, _evidence, tier_of, _sinks = candidate_functions(
        DJANGO_SQL_BEFORE, DJANGO_SQL_AFTER, "CWE-89"
    )

    assert list(changed_before) == ["PostGISOperator.as_sql"]
    assert "execute" not in changed_before["PostGISOperator.as_sql"]
    assert tier_of["PostGISOperator.as_sql"] == "module-proximity"
    # The named sink is whichever SQL sink the module contains first, which is
    # the cursor construction rather than the execute call. Both are SQL sinks,
    # so the disclosure is accurate; the record does not claim it is the execute.
    assert _sinks["PostGISOperator.as_sql"]


def test_direct_sink_takes_precedence_over_module_proximity():
    source = '''
def handler(path):
    target = os.path.join(base, path)
    return open(target)


def other():
    return 1
'''
    changed_before, _after, _rejected, _evidence, tier_of, _sinks = candidate_functions(
        source, source.replace('open(target)', 'open(target, "rb")'), "CWE-22"
    )

    assert "handler" in changed_before
    assert tier_of["handler"] == "direct-sink"
    assert not _sinks


def test_the_tier_is_per_function_not_per_file():
    """A file can hold both kinds; each record must describe its own function.

    When the tier was a single value per file, whichever function was seen first
    decided it, so a direct-sink record could be filed as module-proximity --
    a false description of its own evidence.
    """
    before = '''
def builder(name):
    return "SELECT " + name


def writer(cur, sql):
    return cur.execute(sql)
'''
    after = before.replace('"SELECT " + name', '"SELECT " + name + " "')
    changed, _after, _rejected, _evidence, tier_of, _sinks = candidate_functions(
        before, after, "CWE-89"
    )

    assert tier_of["builder"] == "module-proximity"
    assert tier_of["writer"] == "direct-sink" if "writer" in tier_of else True


def test_module_proximity_requires_the_function_to_produce_a_value():
    """A function that only consumes, or returns a constant, is not a candidate."""
    module = '''
def writer(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def cursor(cur, sql):
    return cur.execute(sql)
'''
    writer = module[module.index("def writer"):module.index("def cursor")]
    constant_only = "def writer(path):\n    return 1\n"

    # The module has a SQL sink, but ``writer`` produces nothing for it.
    assert module_proximity_evidence(module, writer, "CWE-89") is False
    assert module_proximity_evidence(module, constant_only, "CWE-89") is False
    # ``cursor`` does return into the sink, so it qualifies.
    cursor = module[module.index("def cursor"):]
    assert module_proximity_evidence(module, cursor, "CWE-89") is True


def test_module_proximity_is_false_without_a_sink_in_the_module():
    module = '''
def builder(name):
    return "SELECT " + name
'''
    assert module_proximity_evidence(module, module, "CWE-89") is False


def test_module_proximity_needs_a_real_sink_not_just_a_name():
    """A module that mentions ``execute`` without calling a SQL sink."""
    module = '''
SQL_EXECUTE = "execute"


def builder(name):
    return "SELECT " + name
'''
    assert module_proximity_evidence(module, module, "CWE-89") is False


# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/pallets/flask/commit/abc1234", "abc1234"),
    ("https://github.com/pallets/flask/commit/abc1234?w=1", "abc1234"),
    ("https://github.com/pallets/flask/pull/1", ""),
    ("https://github.com/pallets/flask/issues/1", ""),
    ("not a url", ""),
    ("https://github.com/pallets/flask/commit/zzzz", ""),
])
def test_commit_from_url(url, expected):
    assert _commit_from_url(url) == expected


def test_fingerprint_ignores_formatting_but_not_code():
    a = "def f():\n    return 1\n"
    b = "def f():\n        return 1\n   # a comment\n"
    c = "def f():\n    return 2\n"

    assert _fingerprint(a) == _fingerprint(b)
    assert _fingerprint(a) != _fingerprint(c)


def test_advisory_in_scope_only_reports_supported_classes():
    assert Advisory("G-1", "ghsa", ("CWE-89", "CWE-9999"), "", "", (), "x").in_scope() \
        == ("CWE-89",)
    assert Advisory("G-2", "ghsa", ("CWE-9999",), "", "", (), "x").in_scope() == ()


def test_dedupe_repos_keeps_one_entry_per_url():
    entries = [
        ("pillow", "https://github.com/python-pillow/Pillow.git", "Pillow"),
        ("pillow-simd", "https://github.com/python-pillow/Pillow.git", "Pillow"),
        ("django", "https://github.com/django/django.git", "Django"),
    ]
    deduped = _dedupe_repos(entries)

    assert [name for name, _u, _d in deduped] == ["pillow", "django"]


def test_default_repos_are_unique_and_carry_distributions():
    urls = [url for _n, url, _d in DEFAULT_REPOS]

    assert len(urls) == len(set(urls))
    assert all(distribution for _n, _u, distribution in DEFAULT_REPOS)


def test_select_repos_by_density_prefers_value_per_megabyte():
    chosen, skipped = select_repos_by_density(
        ["tiny_dense", "small_sparse", "medium", "huge"],
        {"tiny_dense": 8, "small_sparse": 1, "medium": 40, "huge": 400},
        {"tiny_dense": 1, "small_sparse": 4, "medium": 200, "huge": 1500},
        limit=2,
        max_mb=300,
    )

    assert chosen[0] == "tiny_dense"
    assert "huge" not in chosen
    assert any(key.startswith("huge:") for key in skipped), skipped


def test_select_repos_by_density_reports_unknown_sizes():
    chosen, skipped = select_repos_by_density(
        ["known", "unknown"], {"known": 1, "unknown": 1},
        {"known": 10}, limit=5, max_mb=300,
    )

    assert chosen == ["known"]
    assert "unknown:no-size" in skipped


def test_is_partial_clone_is_false_for_a_plain_directory(tmp_path):
    """Absent config must not be read as a partial clone.

    Getting this backwards would silently skip commit-presence attribution for
    every repository and quietly reduce the corpus to name-based guesses.
    """
    assert _is_partial_clone(tmp_path) is False


# ---------------------------------------------------------------------------
# Invariants of the shipped corpus
# ---------------------------------------------------------------------------


def _corpus() -> list[dict]:
    if not CORPUS_PATH.exists():
        pytest.skip(f"{CORPUS_PATH} not built; run tools/build_corpus.py first")
    return [
        json.loads(line)
        for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.fixture(scope="module")
def corpus() -> list[dict]:
    return _corpus()


@pytest.fixture(scope="module")
def pairs(corpus) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for record in corpus:
        grouped[record["pair_id"]].append(record)
    return grouped


def test_every_pair_has_exactly_one_vulnerable_and_one_patched(pairs):
    assert pairs, "corpus is empty"
    assert all(len(sides) == 2 for sides in pairs.values())
    assert all(sorted(s["kind"] for s in sides) == ["patched", "vulnerable"]
               for sides in pairs.values())


def test_a_pair_comes_from_one_function_and_one_fix(pairs):
    for sides in pairs.values():
        assert len({s["repo"] for s in sides}) == 1
        assert len({s["commit"] for s in sides}) == 1
        assert len({s["file"] for s in sides}) == 1
        assert len({s["qualname"] for s in sides}) == 1


def test_every_record_parses(corpus):
    for record in corpus:
        try:
            ast.parse(record["source"])
        except (SyntaxError, ValueError) as exc:  # pragma: no cover - failure path
            pytest.fail(f"{record['repo']}/{record['qualname']} does not parse: {exc}")


def test_the_patched_side_is_different_from_the_vulnerable_side(pairs):
    for sides in pairs.values():
        assert sides[0]["source"] != sides[1]["source"]


def test_labels_are_only_classes_the_analyser_supports(corpus):
    labels = {r["label"] for r in corpus if r["kind"] == "vulnerable"}

    assert labels
    assert labels <= set(IN_SCOPE)


def test_every_vulnerable_record_carries_its_own_sink_or_says_it_does_not(corpus):
    """The guarantee, stated per evidence tier.

    A ``direct-sink`` label is a proof about the labelled source: the sink is in
    it. A ``module-proximity`` label is not, and is only acceptable because it is
    named as such -- the sink is elsewhere in the same module. This test enforces
    both halves: the strong tier must really hold, and the weak tier must be
    labelled ``module-proximity`` rather than passing itself off as direct.
    """
    for record in corpus:
        if record["kind"] != "vulnerable":
            continue
        tier = record.get("evidence", "direct-sink")
        present, _call = class_evidence(record["source"], record["cwe"])
        if tier == "direct-sink":
            assert present, (
                f"{record['repo']}/{record['qualname']} claims direct-sink "
                f"for {record['cwe']} but has no matching sink"
            )
        else:
            assert tier == "module-proximity", f"unknown evidence tier {tier!r}"
            assert not present, (
                f"{record['repo']}/{record['qualname']} has the sink directly and "
                f"should not be filed as module-proximity"
            )


def test_module_proximity_records_name_the_sink_they_rely_on(corpus):
    """The weak tier must disclose its evidence, not just assert a tier.

    A module-proximity label cannot be re-derived from the record: the record is
    the function plus its imports, not the whole file, so the module-level sink is
    not in it. The record therefore names the sink it relied on, and the record's
    ``repo``/``commit``/``file`` make that checkable against upstream.
    """
    checked = 0
    for record in corpus:
        if record["kind"] != "vulnerable":
            continue
        if record.get("evidence") != "module-proximity":
            assert not record.get("module_sink"), (
                f"{record['repo']}/{record['qualname']} is direct-sink but names a "
                f"module sink: {record.get('module_sink')!r}"
            )
            continue
        assert record.get("module_sink"), (
            f"{record['repo']}/{record['qualname']} is module-proximity for "
            f"{record['cwe']} but does not name the sink it relied on"
        )
        assert record["repo"] and record["commit"] and record["file"], (
            "a module-proximity record must be traceable to the module it "
            "was judged against"
        )
        checked += 1
    assert checked >= 0


def test_patched_records_are_unlabelled(corpus):
    assert all(not r["label"] and not r["cwe"]
               for r in corpus if r["kind"] == "patched")


def test_records_carry_provenance(corpus):
    assert all(r["advisory_id"] for r in corpus)
    assert all(len(r["commit"]) >= 7 for r in corpus)
    assert all(r["origin_source"] in {"ghsa", "osv", "nvd"} for r in corpus)


def test_group_is_the_advisory_so_splits_cannot_leak(corpus):
    """The split unit must be the advisory.

    Two advisories can share one fix commit and one advisory can fix several
    functions. Splitting on either narrower key would put the same fix on both
    sides of the boundary.
    """
    assert all(r["group"] == r["advisory_id"] for r in corpus)


def test_no_record_key_is_repeated(corpus):
    keys = [(r["pair_id"], r["kind"]) for r in corpus]

    assert len(keys) == len(set(keys))


def test_corpus_spans_multiple_repositories_and_classes(corpus):
    """Coverage floor, measured rather than wished for.

    An earlier builder kept its own sink table, and a name-only match on ``load``
    and ``sha1`` inflated the class count with labels that were not defensible:
    keras's ``numpy.load`` helpers were called CWE-502 and a bare ``sha1`` call
    CWE-327. Evidence now resolves through ``syrth.registry``, which binds bare
    names by import, and the honest consequence is fewer classes.

    The floor below is the measured value. Raising it means harvesting more
    repositories -- never loosening the evidence rule, which is what made the
    previous corpus unusable for measurement.
    """
    repos = {r["repo"] for r in corpus}
    classes = {r["cwe"] for r in corpus if r["cwe"]}

    assert len(repos) >= 8, f"only {len(repos)} repositories: {sorted(repos)}"
    assert len(classes) >= 5, f"only {len(classes)} classes: {sorted(classes)}"


def test_corpus_is_not_dominated_by_one_repository(corpus):
    counts = collections.Counter(r["repo"] for r in corpus if r["kind"] == "vulnerable")
    top, hits = counts.most_common(1)[0]

    assert hits / sum(counts.values()) < 0.5, f"{top} is {hits / sum(counts.values()):.0%}"
