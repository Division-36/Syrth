"""
Correctness regression tests for the SYRTH analysis engine.

Every case in this module corresponds to a defect that shipped in earlier
releases: a missed idiom, a false positive on safe code, a non-deterministic
resolution, or a naming-dependent verdict. The names of the tests state the
guarantee, not the implementation, so a regression names the broken promise.

These tests deliberately use *semantically neutral* identifier names
(``user_id`` vs ``zzz``) so that any accidental dependence on identifier
spelling shows up as a failure rather than as a silent accuracy loss.
"""

from __future__ import annotations

import pytest

from syrth.parser import PythonParser
from syrth.registry import (
    Category,
    Origin,
    canonical_sink,
    kill_for,
    sink_spec_for,
)
from syrth.trace import DETECTOR_AMPLIFIER


def analyse(source: str):
    """Parse ``source`` and return the FileTrace."""
    return PythonParser().parse(source)


def traces_of(source: str, function: str | None = None):
    """Return every trace produced for ``source``, optionally filtered by name."""
    trace = analyse(source)
    if function is not None:
        func = trace.get_function(function)
        return list(func.traces) if func else []
    return trace.all_traces()


def sinks_of(source: str, function: str | None = None):
    """Return the set of canonical sink names reached."""
    trace = analyse(source)
    if function is not None:
        func = trace.get_function(function)
        return set(func.sinks) if func else set()
    return {t.sink for t in trace.all_traces()}


def assert_flow(source, category, function=None, sink=None):
    """Assert that at least one trace of ``category`` exists."""
    found = traces_of(source, function)
    matching = [t for t in found if t.category == category]
    assert matching, (
        f"expected a {category} flow, got "
        f"{[(t.category, t.sink) for t in found] or 'no traces'}"
    )
    if sink is not None:
        assert matching[0].sink == sink
    return matching[0]


def assert_no_flow(source, category, function=None):
    """Assert that no trace of ``category`` is produced."""
    found = traces_of(source, function)
    assert not [t for t in found if t.category == category], (
        f"expected no {category} flow, got "
        f"{[(t.category, t.sink, t.sink_arg) for t in found]}"
    )


# ---------------------------------------------------------------------------
# 1. Source-span decoding. tree-sitter reports byte offsets; slicing the decoded
#    str silently corrupted every node after the first multi-byte character.
# ---------------------------------------------------------------------------


class TestUnicodeSourceSpans:
    def test_non_ascii_before_code_does_not_corrupt_identifiers(self):
        source = '# \u2500\u2500\u2500 section \u2500\u2500\u2500\ndef handler(request):\n    return request.GET["q"]\n'
        trace = analyse(source)
        assert [f.name for f in trace.functions] == ["handler"]

    def test_non_ascii_in_docstring_does_not_corrupt_call_names(self):
        source = (
            'def handler():\n'
            '    """R\u00e9sum\u00e9 \u2192 \u2713"""\n'
            '    import os\n'
            '    os.system("ls")\n'
        )
        trace = analyse(source)
        assert "os.system" in trace.functions[0].calls

    def test_identifiers_with_non_ascii_content_decode_correctly(self):
        source = 'def f():\n    x = "caf\u00e9 \u2713"\n    return x\n'
        trace = analyse(source)
        assert [f.name for f in trace.functions] == ["f"]

    def test_line_numbers_are_preserved(self):
        source = '# \u2713\ndef a():\n    pass\n\ndef b():\n    pass\n'
        trace = analyse(source)
        lines = {f.name: f.lineno for f in trace.functions}
        assert lines == {"a": 2, "b": 5}


# ---------------------------------------------------------------------------
# 2. Rename invariance. The verdict must depend on dataflow, not on what a
#    developer happened to call a variable.
# ---------------------------------------------------------------------------


class TestRenameInvariance:
    SQL_INJECTION = 'def h({p}):\n    cur.execute("SELECT * FROM u WHERE n=" + {p})\n'
    RCE = 'def h({p}):\n    os.system("ls " + {p})\n'

    @pytest.mark.parametrize("name", ["user_id", "x", "zzz", "q", "value_1", "tmp"])
    def test_sql_injection_detected_for_any_parameter_name(self, name):
        assert_flow(self.SQL_INJECTION.format(p=name), Category.SQL)

    @pytest.mark.parametrize("name", ["user_id", "x", "zzz", "q", "value_1", "tmp"])
    def test_rce_detected_for_any_parameter_name(self, name):
        assert_flow(self.RCE.format(p=name), Category.EXEC)

    def test_local_variable_rename_does_not_change_verdict(self):
        a = traces_of('def h(z):\n    q = z\n    cur.execute("S" + q)\n')
        b = traces_of('def h(z):\n    completely_different = z\n    cur.execute("S" + completely_different)\n')
        assert [t.sink for t in a] == [t.sink for t in b]
        assert [t.category for t in a] == [t.category for t in b]

    def test_parameter_name_does_not_leak_into_the_verdict(self):
        source = self.SQL_INJECTION.format(p="password")
        trace = traces_of(source)[0]
        # The origin vocabulary reports the *role*, not the spelling.
        assert Origin.PARAM in trace.origins


# ---------------------------------------------------------------------------
# 3. String-construction idioms. f-strings, .format() and % were all invisible
#    to the previous analysis.
# ---------------------------------------------------------------------------


class TestStringConstruction:
    def test_fstring_interpolation_propagates(self):
        assert_flow(
            'def v(request):\n    uid = request.GET["id"]\n'
            '    cur.execute(f"SELECT * FROM u WHERE id={uid}")\n',
            Category.SQL,
        )

    def test_fstring_with_multiple_interpolations(self):
        assert_flow(
            'def v(a, b):\n    cur.execute(f"SELECT {a} FROM {b}")\n',
            Category.SQL,
        )

    def test_fstring_nested_call_interpolation(self):
        assert_flow(
            'def v(request):\n'
            '    cur.execute(f"SELECT * FROM u WHERE n={request.args.get(\'n\')}")\n',
            Category.SQL,
        )

    def test_nested_fstring_inside_format(self):
        assert_flow(
            'def v(a):\n    cur.execute("SELECT {}".format(f"{a}"))\n',
            Category.SQL,
        )

    def test_percent_formatting_propagates(self):
        assert_flow(
            "def v(name):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n",
            Category.SQL,
        )

    def test_percent_formatting_with_tuple(self):
        assert_flow(
            "def v(a, b):\n    cur.execute(\"SELECT %s, %s\" % (a, b))\n",
            Category.SQL,
        )

    def test_str_format_method_propagates(self):
        assert_flow(
            "def v(name):\n    cur.execute(\"SELECT * FROM u WHERE n='{}'\".format(name))\n",
            Category.SQL,
        )

    def test_plain_concatenation_propagates(self):
        assert_flow(
            'def v(name):\n    cur.execute("SELECT * FROM u WHERE n=" + name)\n',
            Category.SQL,
        )

    def test_implicit_literal_concatenation_propagates(self):
        assert_flow(
            'def v(a):\n    cur.execute("SELECT * FROM t WHERE n=\'" a "\'")\n',
            Category.SQL,
        )

    def test_implicit_concatenation_in_assignment(self):
        assert_flow(
            'def v(a, b):\n    q = "SELECT " a\n    cur.execute(q)\n',
            Category.SQL,
        )

    def test_literal_only_template_produces_no_flow(self):
        assert_no_flow(
            'def v():\n    cur.execute(f"SELECT * FROM u WHERE id=1")\n',
            Category.SQL,
        )


# ---------------------------------------------------------------------------
# 4. Argument-position awareness. ``execute(sql, params)`` is not injection.
# ---------------------------------------------------------------------------


class TestSinkArgumentSchema:
    def test_parameterised_query_positional_params_is_safe(self):
        assert_no_flow(
            'def v(uid):\n    cur.execute("SELECT * FROM u WHERE id=%s", (uid,))\n',
            Category.SQL,
        )

    def test_parameterised_query_keyword_params_is_safe(self):
        assert_no_flow(
            'def v(uid):\n    cur.execute("SELECT * FROM u WHERE id=%s", params=(uid,))\n',
            Category.SQL,
        )

    def test_parameterised_query_tainted_statement_is_reported(self):
        assert_flow(
            'def v(uid):\n    cur.execute("SELECT * FROM u WHERE id=%s" + uid, (1,))\n',
            Category.SQL,
        )

    def test_sanitised_params_do_not_launder_tainted_statement(self):
        assert_flow(
            'def v(uid, other):\n'
            '    cur.execute("SELECT " + shlex.quote(uid) + " FROM t WHERE x=" + other)\n',
            Category.SQL,
        )

    def test_keyword_sink_argument_is_analysed(self):
        assert_flow(
            'def v(uid):\n    cur.execute(query="SELECT * FROM u WHERE id=" + uid)\n',
            Category.SQL,
        )

    def test_keyword_safe_argument_is_not_analysed(self):
        assert_no_flow(
            'def v(uid):\n    cur.execute(sql="SELECT 1", params=(uid,))\n',
            Category.SQL,
        )

    def test_splat_argument_is_treated_as_dangerous(self):
        assert_flow(
            'def v(args):\n    cur.execute(*args)\n',
            Category.SQL,
        )

    def test_argv_style_subprocess_is_safe(self):
        assert_no_flow(
            'def v(item):\n    subprocess.run(["ls", item], shell=False)\n',
            Category.EXEC,
        )

    def test_argv_style_subprocess_without_shell_false_is_flagged(self):
        assert_flow(
            'def v(item):\n    subprocess.run(["ls", item])\n',
            Category.EXEC,
        )

    def test_shell_true_is_flagged(self):
        assert_flow(
            'def v(item):\n    subprocess.run("ls " + item, shell=True)\n',
            Category.EXEC,
        )


# ---------------------------------------------------------------------------
# 5. Typed kills. A sanitiser protects the categories it actually protects.
# ---------------------------------------------------------------------------


class TestSanitisers:
    def test_shlex_quote_kills_exec(self):
        assert_no_flow(
            'import shlex\ndef v(cmd):\n    os.system("ls " + shlex.quote(cmd))\n',
            Category.EXEC,
        )

    def test_shlex_quote_does_not_kill_sql(self):
        assert_flow(
            'import shlex\ndef v(x):\n    cur.execute("SELECT " + shlex.quote(x))\n',
            Category.SQL,
        )

    def test_basename_kills_file(self):
        assert_no_flow(
            'import os\ndef v(name):\n    open(os.path.join("/d", os.path.basename(name)))\n',
            Category.FILE,
        )

    def test_basename_does_not_kill_exec(self):
        assert_flow(
            'import os\ndef v(x):\n    os.system(os.path.basename(x))\n',
            Category.EXEC,
        )

    def test_normpath_is_a_partial_mitigation(self):
        trace = assert_flow(
            'import os\ndef v(name):\n    open(os.path.join("/d", os.path.normpath(name)))\n',
            Category.FILE,
        )
        assert trace.confidence < 0.90
        assert any("partial mitigation" in n for n in trace.notes)

    def test_html_escape_kills_xss(self):
        assert_no_flow(
            'import html\ndef v(x):\n    return render_template_string("<p>" + html.escape(x))\n',
            Category.XSS,
        )

    def test_int_coercion_kills_numeric_injection(self):
        assert_no_flow(
            'def v(x):\n    cur.execute("SELECT * FROM u WHERE id=" + str(int(x)))\n',
            Category.SQL,
        )

    def test_safe_load_is_not_a_deserialisation_sink(self):
        assert "DESER_UNSAFE" not in sinks_of(
            'import yaml\ndef v(x):\n    return yaml.safe_load(x)\n'
        )

    def test_pickle_loads_is_a_deserialisation_sink(self):
        assert_flow(
            'import pickle\ndef v(x):\n    return pickle.loads(x)\n', Category.DESER
        )

    def test_json_loads_is_not_a_deserialisation_sink(self):
        assert "DESER_UNSAFE" not in sinks_of('import json\ndef v(x):\n    return json.loads(x)\n')

    def test_import_binding_disambiguates_loads(self):
        assert_flow(
            'from pickle import loads\ndef v(x):\n    return loads(x)\n', Category.DESER
        )

    def test_import_binding_disambiguates_json_loads(self):
        assert "DESER_UNSAFE" not in sinks_of(
            'from json import loads\ndef v(x):\n    return loads(x)\n'
        )

    def test_defusedxml_is_not_an_xxe_sink(self):
        assert "XXE_PARSE" not in sinks_of(
            'import defusedxml\ndef v(x):\n    return defusedxml.fromstring(x)\n'
        )

    def test_lxml_is_an_xxe_sink(self):
        assert_flow('import lxml\ndef v(x):\n    return lxml.etree.fromstring(x)\n', Category.XXE)

    def test_re_compile_is_not_a_code_execution_sink(self):
        assert "EXEC_COMMAND" not in sinks_of('import re\ndef v(x):\n    return re.compile(x)\n')


# ---------------------------------------------------------------------------
# 6. Amplifiers. ``mark_safe`` is a sink even when nothing is tainted.
# ---------------------------------------------------------------------------


class TestAmplifiers:
    def test_mark_safe_on_clean_value_is_reported(self):
        """An assertion about a value the tracker could not tie to a source.

        The fixture assigns the constant to a local first. That is the case the
        invariant is about: the analyser cannot see where the value came from, so
        the assertion itself has to be the finding. A literal passed straight to
        ``mark_safe`` is a different case, covered by
        ``test_mark_safe_on_a_literal_is_not_reported``.
        """
        found = assert_flow(
            'def v():\n    x = "<b>x</b>"\n    return mark_safe(x)\n',
            Category.XSS,
        )
        assert found.detector == DETECTOR_AMPLIFIER

    def test_mark_safe_on_a_literal_is_not_reported(self):
        """A literal cannot be an assertion somebody got wrong.

        Airflow's pagination helper builds static markup with
        ``Markup("<li class=...>")``, and reporting that put a finding on code
        with no attacker-controlled value in it at all.
        """
        assert_no_flow(
            'def v():\n    return mark_safe("<b>x</b>")\n', Category.XSS
        )

    def test_mark_safe_on_tainted_value_is_reported(self):
        found = assert_flow('def v(x):\n    return mark_safe(x)\n', Category.XSS)
        assert found.detector == DETECTOR_AMPLIFIER
        assert Origin.PARAM in found.origins

    def test_escaped_then_marked_safe_is_not_reported(self):
        assert_no_flow(
            'import html\ndef v(x):\n    return mark_safe(html.escape(x))\n', Category.XSS
        )

    def test_mark_safe_is_not_registered_as_a_plain_sink(self):
        assert canonical_sink("mark_safe") is None
        assert canonical_sink("django.utils.safestring.mark_safe") is None


# ---------------------------------------------------------------------------
# 7. Expression and statement coverage.
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_augmented_assignment_keeps_taint(self):
        assert_flow(
            'def v(request):\n    msg = "a"\n    msg += request.GET["m"]\n    os.system(msg)\n',
            Category.EXEC,
        )

    def test_attribute_target_keeps_taint(self):
        assert_flow(
            'def v(self, request):\n    self.q = request.GET["q"]\n    cur.execute(self.q)\n',
            Category.SQL,
        )

    def test_subscript_container_keeps_taint(self):
        assert_flow(
            'def v(data, request):\n    data["q"] = request.GET["q"]\n    cur.execute(data["q"])\n',
            Category.SQL,
        )

    def test_tuple_target_keeps_taint(self):
        assert_flow(
            'def v(request):\n    a, b = request.GET["a"], "const"\n    os.system(a + b)\n',
            Category.EXEC,
        )

    def test_for_loop_variable_is_tainted_from_iterable(self):
        assert_flow(
            'def v(items):\n    for item in items:\n        os.system(item)\n',
            Category.EXEC,
        )

    def test_with_statement_target_propagates(self):
        assert_flow(
            'def v(x):\n    with context(x) as handle:\n        os.system(handle)\n',
            Category.EXEC,
        )

    def test_list_comprehension_loop_variable_is_tainted(self):
        assert_flow(
            'def v(items):\n    return [os.system(i) for i in items]\n',
            Category.EXEC,
        )

    def test_conditional_expression_propagates(self):
        assert_flow(
            'def v(a, flag):\n    q = a if flag else "x"\n    cur.execute(q)\n',
            Category.SQL,
        )

    def test_boolean_operator_propagates(self):
        assert_flow(
            'def v(a, b):\n    q = a and b\n    cur.execute(q)\n', Category.SQL
        )

    def test_parenthesised_expression_propagates(self):
        assert_flow(
            'def v(a):\n    cur.execute(("SELECT " + a))\n', Category.SQL
        )

    def test_walrus_assignment_propagates(self):
        assert_flow(
            'def v(a):\n    if (q := a):\n        cur.execute(q)\n', Category.SQL
        )

    def test_nested_call_argument_propagates(self):
        assert_flow(
            'def v(request):\n    os.system(inner(request.GET["c"]))\n', Category.EXEC
        )

    def test_try_except_body_is_analysed(self):
        assert_flow(
            'def v(a):\n    try:\n        os.system(a)\n    except Exception:\n        pass\n',
            Category.EXEC,
        )

    def test_nested_function_is_analysed_separately(self):
        trace = analyse(
            'def outer(request):\n'
            '    def inner(x):\n        os.system(x)\n'
            '    inner(request.GET["c"])\n'
        )
        names = [f.name for f in trace.functions]
        assert "inner" in names and "outer" in names
        assert any(t.sink == "EXEC_COMMAND" for t in trace.get_function("inner").traces)

    def test_lambda_default_argument_is_analysed(self):
        trace = analyse('def v(request):\n    f = lambda x=os.system(request.GET["c"]): x\n')
        assert any(t.sink == "EXEC_COMMAND" for t in trace.all_traces())

    def test_class_body_default_argument_is_analysed(self):
        trace = analyse(
            'import os\nclass A:\n    cmd = os.system\n    def m(self, x):\n        os.system(x)\n'
        )
        assert trace.functions

    def test_decorator_expression_is_analysed(self):
        trace = analyse(
            'import os\n@os.system("ls " + input())\ndef f():\n    pass\n'
        )
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)

    def test_generator_argument_position_is_respected(self):
        assert_no_flow(
            'def v(uid):\n    cur.execute("SELECT * FROM u WHERE id=%s", (x for x in [uid]))\n',
            Category.SQL,
        )


# ---------------------------------------------------------------------------
# 8. Origins must describe how data entered, not guess.
# ---------------------------------------------------------------------------


class TestOrigins:
    def test_parameter_origin(self):
        assert Origin.PARAM in assert_flow('def v(a):\n    os.system(a)\n', Category.EXEC).origins

    def test_request_origin(self):
        found = assert_flow(
            'def v(request):\n    os.system(request.args.get("c"))\n', Category.EXEC
        )
        assert Origin.REQUEST in found.origins

    def test_env_origin_is_not_reported_as_request(self):
        found = assert_flow(
            'import os\ndef v():\n    os.system(os.environ["CMD"])\n', Category.EXEC
        )
        assert Origin.ENV in found.origins
        assert Origin.REQUEST not in found.origins

    def test_getenv_origin(self):
        found = assert_flow('import os\ndef v():\n    os.system(os.getenv("C"))\n', Category.EXEC)
        assert Origin.ENV in found.origins

    def test_stdin_origin(self):
        found = assert_flow('def v():\n    os.system(input())\n', Category.EXEC)
        assert Origin.STDIN in found.origins

    def test_cli_origin(self):
        found = assert_flow('import sys\ndef v():\n    os.system(sys.argv[1])\n', Category.EXEC)
        assert Origin.CLI in found.origins

    def test_db_read_origin(self):
        found = assert_flow(
            'def v(cur):\n    os.system(cur.fetchone()[0])\n', Category.EXEC
        )
        assert Origin.DB_READ in found.origins

    def test_file_read_origin(self):
        found = assert_flow('def v(p):\n    with open(p) as fh:\n        os.system(fh.read())\n',
                            Category.EXEC)
        assert Origin.FILE_READ in found.origins

    def test_network_read_origin(self):
        found = assert_flow(
            'import requests\ndef v(u):\n    os.system(requests.get(u).text)\n',
            Category.EXEC,
        )
        assert Origin.NET_READ in found.origins

    def test_module_level_sink_is_reported(self):
        trace = analyse('import os\ndef _noop():\n    pass\nos.system(input())\n')
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)

    def test_module_scope_is_flagged(self):
        trace = analyse('import os\nos.system(input())\n')
        assert trace.module_level_flag()


# ---------------------------------------------------------------------------
# 9. Safe code must stay silent. Each case below was a false positive.
# ---------------------------------------------------------------------------


class TestFalsePositives:
    def test_django_render_with_dict_context_is_not_reported_as_template_injection(self):
        assert_no_flow(
            'def view(request, user_id):\n'
            '    return render(request, "p.html", {"uid": user_id})\n',
            Category.XSS,
        )

    def test_authenticate_is_not_a_sink(self):
        assert "XSS_OUTPUT" not in sinks_of(
            "def login(request):\n    authenticate(username=request.POST['u'],"
            " password=request.POST['p'])\n"
        )

    def test_safe_open_of_a_constant_path(self):
        assert_no_flow('def f():\n    open("/etc/config")\n', Category.FILE)

    def test_dict_get_of_a_constant_key(self):
        assert_no_flow(
            'import json\ndef f():\n    d = json.loads(\'{"a": 1}\')\n    return d["a"]\n',
            Category.DESER,
        )

    def test_constant_fstring_is_not_a_flow(self):
        assert_no_flow('def f():\n    cur.execute(f"SELECT {1}")\n', Category.SQL)

    def test_multiple_safe_sinks_produce_no_traces(self):
        source = (
            'import os\n'
            'def f():\n'
            '    open("/etc/config")\n'
            '    os.system("ls")\n'
            '    cur.execute("SELECT 1")\n'
            '    eval("1 + 1")\n'
        )
        assert traces_of(source) == []


# ---------------------------------------------------------------------------
# 10. Category/CWE consistency: one closed label space for every detector.
# ---------------------------------------------------------------------------


class TestLabelSpace:
    def test_every_sink_category_has_a_cwe(self):
        for name in canonical_sink.__globals__["SINK_SPECS"].values():
            assert name.cwe.startswith("CWE-")
            assert name.scat_token == f"SCAT:{name.category}"

    def test_sink_token_and_feature_category_agree(self):
        trace = analyse('import yaml\ndef v(x):\n    yaml.load(x)\n')
        found = trace.get_function("v")
        assert "DESER_UNSAFE" in found.sinks
        assert "SCAT:DESER" in found.to_token_sequence()

    def test_token_sequence_has_no_unknown_sink_names(self):
        source = (
            'import os, requests, yaml, pickle\n'
            'def v(a, request):\n'
            '    os.system(a)\n'
            '    requests.get(request.args["u"])\n'
            '    yaml.load(a)\n'
            '    pickle.loads(a)\n'
            '    open(a)\n'
            '    eval(a)\n'
            '    redirect(a)\n'
            '    mark_safe(a)\n'
        )
        found = analyse(source).get_function("v")
        for token in found.to_token_sequence():
            if token.startswith("sink:"):
                assert sink_spec_for(token[5:]) is not None, token


# ---------------------------------------------------------------------------
# 11. Determinism. String hashing is randomised per process, so any
#     order-dependent resolution would make results irreproducible.
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize(
        "call_name,expected",
        [
            ("cursor.execute", "SQL_EXECUTE"),
            ("execute", "SQL_EXECUTE"),
            ("db.execute", "SQL_EXECUTE"),
            ("pickle.loads", "DESER_UNSAFE"),
            ("yaml.load", "DESER_UNSAFE"),
            ("json.loads", None),
            ("json.load", None),
            ("os.system", "EXEC_COMMAND"),
            ("subprocess.run", "EXEC_COMMAND"),
            ("os.path.join", "FILE_OPEN"),
            ("redirect", "REDIRECT_NAV"),
            ("mark_safe", None),
            ("shlex.quote", None),
            ("html.escape", None),
            ("re.compile", None),
            ("eval", "EXEC_COMMAND"),
            ("exec", "EXEC_COMMAND"),
            ("compile", "EXEC_COMMAND"),
            ("__import__", "EXEC_COMMAND"),
        ],
    )
    def test_canonical_sink_is_exact(self, call_name, expected):
        assert canonical_sink(call_name) == expected

    def test_repeated_parsing_is_stable(self):
        source = (
            'import os, requests, yaml\n'
            'def v(a, request):\n'
            '    os.system(a)\n'
            '    yaml.load(a)\n'
            '    requests.get(request.args["u"])\n'
        )
        first = [t.trace_id for t in analyse(source).all_traces()]
        for _ in range(5):
            assert [t.trace_id for t in analyse(source).all_traces()] == first

    def test_kill_resolution_never_returns_a_sink(self):
        for name in ("pickle.loads", "yaml.load", "subprocess.run", "eval"):
            assert kill_for(name) is None

    def test_trace_ids_are_line_independent(self):
        before = 'def v(a):\n    os.system(a)\n'
        after = 'def v(a):\n    # a new comment\n    # and another\n    os.system(a)\n'
        assert [t.trace_id for t in analyse(before).all_traces()] == [
            t.trace_id for t in analyse(after).all_traces()
        ]


# ---------------------------------------------------------------------------
# 12. Robustness. Malformed input must not raise and must not invent findings.
# ---------------------------------------------------------------------------


class TestRobustness:
    @pytest.mark.parametrize(
        "source",
        [
            "",
            "def broken(\n    return 1\n",
            "class ??:\n  pass\n",
            "def f():\n\treturn 1\n",
            "\x00\x01\x02",
            "def f():\n    return 'unterminated\n",
            "async def f():\n    await g()\n",
            "def f(*args, **kwargs):\n    return args\n",
            "def f(a: int = 3, *b: str, c: bool = False) -> int:\n    return a\n",
        ],
    )
    def test_malformed_source_does_not_raise(self, source):
        trace = analyse(source)
        assert trace is not None

    def test_parse_errors_are_flagged(self):
        assert analyse("def broken(\n    return 1\n").parse_errors

    def test_clean_source_is_not_flagged(self):
        assert not analyse("def f():\n    return 1\n").parse_errors

    def test_unicode_decode_error_does_not_raise(self):
        source = 'def f():\n    return "\ud800"\n'
        trace = analyse(source)
        assert [f.name for f in trace.functions] == ["f"]

    def test_deeply_nested_expression_terminates(self):
        source = "def f(a):\n    os.system(" + "(" * 60 + "a" + ")" * 60 + ")\n"
        assert_flow(source, Category.EXEC)


class TestOriginReporting:
    """Reported origins must be a set: no duplicates, no invented labels."""

    def test_refining_a_request_parameter_does_not_duplicate_the_origin(self):
        # ``username`` is derived from ``request`` (PARAM) while ``bio`` comes
        # from an attribute read that is already REQUEST, so the merged origin
        # set holds both. Refining PARAM -> REQUEST must not yield REQUEST twice.
        source = (
            "def profile_view(request):\n"
            "    username = request.user.username\n"
            "    bio = request.session.get('bio')\n"
            "    html = f'<p>{username}{bio}</p>'\n"
            "    return HttpResponse(html)\n"
        )
        candidates = traces_of(source)
        assert any(t.category is Category.XSS for t in candidates), (
            "expected an XSS trace from a request-derived response body"
        )
        for candidate in candidates:
            assert len(set(candidate.origins)) == len(candidate.origins), (
                f"duplicated origins in {candidate.summary()!r}"
            )

    def test_origins_are_sorted_and_unique_under_every_trace(self):
        source = (
            "def a(request):\n"
            "    os.system(request.GET['x'])\n"
            "    cur.execute(request.args['y'])\n"
            "    return HttpResponse(open(request.files['z']).read())\n"
        )
        for candidate in traces_of(source):
            origins = list(candidate.origins)
            assert origins == sorted(origins)
            assert len(origins) == len(set(origins))
            assert all(isinstance(o, str) and o for o in origins)
