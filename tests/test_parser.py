"""
Tests for the Python front end.

Covers the parsing surface a consumer depends on: function extraction, parameter
resolution, decorator and import handling, framework detection, sink
canonicalisation, module-scope analysis, the token sequence, and fault tolerance
on malformed input.
"""

import pytest

from syrth.parser import FileTrace, FunctionTrace, PythonParser, Token
from syrth.registry import Category, sink_spec_for


@pytest.fixture
def parser():
    return PythonParser()


def parse(parser, code):
    return parser.parse(code)


class TestToken:
    def test_construction_and_round_trip(self):
        token = Token(
            type="function_definition",
            name="test_func",
            line=10,
            column=5,
            language="python",
        )
        assert token.children == []
        assert token.metadata == {}
        payload = token.to_dict()
        assert payload["name"] == "test_func"
        assert payload["children"] == []

    def test_children_are_serialised_recursively(self):
        parent = Token(type="call", name="execute", line=15, column=0)
        parent.children.append(Token(type="identifier", name="query", line=15, column=7))
        payload = parent.to_dict()
        assert payload["children"][0]["name"] == "query"


class TestFunctionTrace:
    def test_fields(self):
        trace = FunctionTrace(
            name="test_function",
            decorators=["login_required"],
            args=["request", "user_id"],
            calls=["execute"],
            sinks=["SQL_EXECUTE"],
            lineno=20,
        )
        assert trace.has_auth_decorator is False
        assert trace.has_csrf_exempt is False
        assert trace.sink_categories() == [Category.SQL]
        assert trace.confirmed() == []

    def test_token_sequence_shape(self):
        trace = FunctionTrace(
            name="sql_query",
            decorators=["login_required"],
            args=["user_id", "query"],
            calls=["cursor.execute", "render_template_string"],
            sinks=["SQL_EXECUTE", "XSS_TEMPLATE_BODY"],
            has_auth_decorator=True,
            has_sql_string=True,
            flows=["flow:PARAM->SQL_EXECUTE"],
        )
        tokens = trace.to_token_sequence()
        assert "@login_required" in tokens
        assert "def:sql_query" in tokens
        assert "arg:user_id" in tokens
        assert "sink:SQL_EXECUTE" in tokens
        assert "sink:XSS_TEMPLATE_BODY" in tokens
        assert "SCAT:SQL" in tokens
        assert "SCAT:XSS" in tokens
        assert "tainted:SQL_EXECUTE" in tokens
        # An auth decorator suppresses the no-auth marker, but never suppresses
        # a confirmed flow.
        assert "meta:no_auth" not in tokens
        assert "tainted:SQL_EXECUTE" in tokens

    def test_every_sink_token_is_a_known_sink(self):
        trace = FunctionTrace(
            name="f", sinks=["SQL_EXECUTE", "EXEC_COMMAND", "FILE_OPEN"],
        )
        for token in trace.to_token_sequence():
            if token.startswith("sink:"):
                assert sink_spec_for(token[len("sink:"):]) is not None

    def test_name_hints_are_separate_from_the_token_stream(self):
        trace = FunctionTrace(name="f", args=["user_id", "zzz"])
        hints = trace.name_hint_tokens()
        tokens = trace.to_token_sequence()
        assert hints and all(h.startswith("nh:") for h in hints)
        assert not any(t.startswith("nh:") for t in tokens)


class TestFileTrace:
    def test_lookup_helpers_tolerate_unknown_names(self):
        trace = FileTrace(path="a.py")
        assert trace.get_function("nope") is None
        assert trace.get_function_sinks("nope") == []
        assert trace.get_function_flows("nope") == []
        assert trace.all_traces() == []
        assert trace.module_level_flag() is False


class TestStructureExtraction:
    def test_simple_function(self, parser):
        trace = parse(parser, 'def simple():\n    return "hello"\n')
        assert [f.name for f in trace.functions] == ["simple"]
        assert trace.functions[0].lineno == 1
        assert trace.functions[0].args == []
        assert trace.functions[0].calls == []
        assert trace.functions[0].sinks == []

    def test_parameters_keep_their_positions(self, parser):
        trace = parse(parser, "def f(a, b, c):\n    return a\n")
        func = trace.functions[0]
        assert func.args == ["a", "b", "c"]
        assert func.arg_positions == [(0, "a"), (1, "b"), (2, "c")]

    def test_self_and_cls_are_kept_but_not_tainted_as_parameters(self, parser):
        trace = parse(parser, "def f(self, x):\n    return x\n")
        assert trace.functions[0].args == ["self", "x"]

    def test_star_args_keep_their_positions(self, parser):
        trace = parse(parser, "def f(a, *args, **kwargs):\n    return a\n")
        func = trace.functions[0]
        assert func.arg_positions[0] == (0, "a")
        assert func.arg_positions[1][1].startswith("*")
        assert func.arg_positions[2][1].startswith("**")

    def test_typed_and_defaulted_parameters(self, parser):
        trace = parse(parser, "def f(a: int = 3, b: str = 'x') -> int:\n    return a\n")
        assert [name for _index, name in trace.functions[0].arg_positions] == ["a", "b"]

    def test_decorators(self, parser):
        trace = parse(
            parser,
            '@login_required\n@require_POST\ndef admin(request):\n    return request\n',
        )
        func = trace.functions[0]
        assert set(func.decorators) == {"login_required", "require_POST"}
        assert func.has_auth_decorator is True

    def test_csrf_exempt_is_detected_and_separate(self, parser):
        trace = parse(parser, "@csrf_exempt\ndef v(request):\n    return request\n")
        assert trace.functions[0].has_csrf_exempt is True

    def test_nested_functions_are_separate_traces(self, parser):
        trace = parse(
            parser,
            "def outer(request):\n"
            "    def inner(x):\n"
            "        os.system(x)\n"
            "    inner(request.GET['c'])\n",
        )
        names = [f.name for f in trace.functions]
        assert "inner" in names and "outer" in names

    def test_class_methods_are_analysed(self, parser):
        trace = parse(
            parser,
            "class A:\n"
            "    def m(self, x):\n"
            "        os.system(x)\n",
        )
        assert [f.name for f in trace.functions] == ["m"]
        assert any(t.sink == "EXEC_COMMAND" for t in trace.functions[0].traces)

    def test_async_functions(self, parser):
        trace = parse(parser, "async def f(request):\n    os.system(request.GET['c'])\n")
        assert [f.name for f in trace.functions] == ["f"]
        assert trace.functions[0].traces


class TestImportsAndFrameworks:
    def test_plain_import(self, parser):
        trace = parse(parser, "import os\nimport os.path\n")
        assert "os" in trace.imports

    def test_from_import_records_the_module(self, parser):
        trace = parse(parser, "from django.http import JsonResponse\n")
        assert "django.http" in trace.imports

    def test_framework_detection(self, parser):
        trace = parse(
            parser,
            "from django.http import HttpResponse\nfrom flask import Flask\n",
        )
        assert "framework:django" in trace.framework_tokens
        assert "framework:flask" in trace.framework_tokens

    def test_import_bindings_disambiguate_bare_names(self, parser):
        from syrth.registry import Bindings

        bindings = Bindings()
        bindings.bind_import("pickle", "loads")
        assert bindings.sink_for("loads") == "DESER_UNSAFE"
        safe = Bindings()
        safe.bind_import("json", "loads")
        assert safe.sink_for("loads") is None

    def test_imports_only_file_has_no_functions(self, parser):
        trace = parse(parser, "import os\nfrom sys import argv\nimport pathlib\n")
        # ``from sys import argv`` records the module, not the imported name, so
        # framework detection keys on modules rather than on symbols.
        assert trace.imports == ["os", "pathlib", "sys"]
        assert trace.functions == []

    def test_from_import_binds_the_symbol(self, parser):
        from syrth.registry import Bindings

        trace = parse(parser, "from pickle import loads\ndef f(x):\n    loads(x)\n")
        bindings = trace.bindings
        assert isinstance(bindings, Bindings)
        assert bindings.sink_for("loads") == "DESER_UNSAFE"


class TestSinkCanonicalisation:
    @pytest.mark.parametrize(
        "code,expected",
        [
            ("def f():\n    cursor.execute('SELECT 1')\n", "SQL_EXECUTE"),
            ("def f():\n    os.system('ls')\n", "EXEC_COMMAND"),
            ("def f():\n    subprocess.run('ls')\n", "EXEC_COMMAND"),
            ("def f():\n    open('/etc/passwd')\n", "FILE_OPEN"),
            ("def f():\n    redirect('/x')\n", "REDIRECT_NAV"),
            ("def f():\n    requests.get('http://x')\n", "NET_REQUEST"),
            ("def f():\n    pickle.loads(b'')\n", "DESER_UNSAFE"),
            ("def f():\n    hashlib.md5(b'')\n", "CRYPTO_WEAK"),
        ],
    )
    def test_spellings_collapse_to_one_canonical_sink(self, parser, code, expected):
        trace = parse(parser, code)
        assert expected in trace.functions[0].sinks

    def test_two_spellings_of_one_operation_produce_one_sink(self, parser):
        trace = parse(
            parser,
            "def f():\n"
            "    cur.execute('SELECT 1')\n"
            "    conn.execute('SELECT 2')\n"
            "    cur.executemany('SELECT 3')\n",
        )
        assert trace.functions[0].sinks == ["SQL_EXECUTE"]

    def test_call_names_are_recorded_verbatim(self, parser):
        trace = parse(parser, "def f():\n    cur.execute('SELECT 1')\n")
        assert "cur.execute" in trace.functions[0].calls
        assert trace.functions[0].sinks == ["SQL_EXECUTE"]

    def test_sql_literal_is_recorded(self, parser):
        trace = parse(
            parser, "def f():\n    cur.execute('SELECT * FROM t WHERE a=1')\n"
        )
        assert trace.functions[0].has_sql_string is True


class TestModuleScope:
    def test_module_level_sink_is_analysed(self, parser):
        trace = parse(parser, "import os\ndef _noop():\n    pass\nos.system(input())\n")
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)
        assert trace.module_level_flag() is True

    def test_module_scope_records_calls(self, parser):
        trace = parse(parser, "import os\nos.getcwd()\n")
        assert "os.getcwd" in trace.module_calls

    def test_class_defaults_run_at_import_time(self, parser):
        trace = parse(parser, "import os\nclass A:\n    cmd = os.system(input())\n")
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)

    def test_decorator_expressions_run_at_import_time(self, parser):
        trace = parse(parser, "import os\n@os.system(input())\ndef f():\n    pass\n")
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)


class TestInterproceduralBookkeeping:
    def test_invocations_are_recorded_with_argument_origins(self, parser):
        trace = parse(parser, "def f(x):\n    g('S' + x)\ndef g(q):\n    pass\n")
        func = trace.functions[0]
        assert func.invocations
        callee, line, origins, slots = func.invocations[0]
        assert callee == "g"
        assert line == 2
        assert any("PARAM#0" in o for o in origins[0])
        assert slots[0][0] == 0

    def test_symbolic_origins_are_recorded(self, parser):
        trace = parse(parser, "def f(a):\n    q = a\n    r = 'x' + q\n")
        func = trace.functions[0]
        assert "q" in func.symbolic_origins
        assert "PARAM#0" in func.symbolic_origins["q"]

    def test_return_propagation_is_recorded(self, parser):
        trace = parse(parser, "def f(a):\n    return a\ndef g(b):\n    return b\n")
        assert trace.functions[0].returns_param_indices == [0]
        assert trace.functions[1].returns_param_indices == [0]

    def test_sanitisers_are_recorded_even_when_no_flow_survives(self, parser):
        trace = parse(parser, "import shlex\ndef f(x):\n    os.system(shlex.quote(x))\n")
        assert trace.functions[0].sanitisers == ["shlex.quote"]
        assert trace.functions[0].traces == []


class TestFaultTolerance:
    @pytest.mark.parametrize(
        "code",
        [
            "",
            "def broken(\n    return 1\n",
            "class ??:\n  pass\n",
            "def f():\n\treturn 1\n",
            "\x00\x01",
            "def f():\n    return 'unterminated\n",
            "def f(a, a, a):\n    return a\n",
            "async for x in y:\n    pass\n",
        ],
    )
    def test_malformed_input_does_not_raise(self, parser, code):
        trace = parse(parser, code)
        assert isinstance(trace, FileTrace)

    def test_parse_errors_are_reported(self, parser):
        assert parse(parser, "def broken(\n    return 1\n").parse_errors is True

    def test_clean_source_is_not_flagged(self, parser):
        assert parse(parser, "def f():\n    return 1\n").parse_errors is False

    def test_non_ascii_does_not_corrupt_later_nodes(self, parser):
        source = '# \u2500\u2500 section \u2500\u2500\ndef v(request):\n    os.system(request.GET["c"])\n'
        trace = parse(parser, source)
        assert [f.name for f in trace.functions] == ["v"]
        assert trace.functions[0].traces[0].sink == "EXEC_COMMAND"

    def test_reparsing_is_stable(self, parser):
        source = 'def f(a):\n    os.system("ls " + a)\n'
        first = [t.trace_id for t in parse(parser, source).all_traces()]
        for _ in range(3):
            assert [t.trace_id for t in parse(parser, source).all_traces()] == first
