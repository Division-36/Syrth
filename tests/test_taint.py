"""
Tests for the taint value model and its integration with the front end.

The value model carries three independent things -- which origins reached a
value, which sink categories a full sanitiser neutralised, and which a partial
one mitigated. These tests pin the semantics that make safe code and unsafe code
distinguishable: kills are category-typed, and a sanitised operand cannot
launder an unsanitised one.
"""

import pytest

from syrth.parser import PythonParser
from syrth.registry import Category, Origin
from syrth.taint import TaintEngine, TaintState, TaintValue
from syrth.trace import STEP_KIND_SANITIZE, STEP_KIND_SOURCE, TraceStep


@pytest.fixture
def engine():
    return TaintEngine()


def source_step(line=1):
    return TraceStep(line, 0, STEP_KIND_SOURCE, "param", "x")


class TestTaintValue:
    def test_default_is_clean(self):
        value = TaintValue()
        assert value.tainted is False
        assert value.external is False
        assert value.origins == frozenset()

    def test_parameter_origin_is_external(self):
        value = TaintValue(origins=frozenset({Origin.PARAM}))
        assert value.tainted is True
        assert value.external is True

    def test_global_origin_is_not_external(self):
        value = TaintValue(origins=frozenset({Origin.GLOBAL}))
        assert value.tainted is True
        assert value.external is False

    def test_full_kill_neutralises_only_its_categories(self):
        spec = _spec("shlex.quote", kills=[Category.EXEC])
        value = TaintValue(origins=frozenset({Origin.PARAM})).with_kill(spec)
        assert value.tainted is True
        assert value.sanitised_for(Category.EXEC)
        assert not value.sanitised_for(Category.SQL)
        assert not value.partially_mitigated(Category.EXEC)

    def test_partial_kill_does_not_neutralise(self):
        spec = _spec("os.path.normpath", kills=[Category.FILE], full=False)
        value = TaintValue(origins=frozenset({Origin.PARAM})).with_kill(spec)
        assert not value.sanitised_for(Category.FILE)
        assert value.partially_mitigated(Category.FILE)

    def test_kill_records_its_name(self):
        spec = _spec("os.path.basename", kills=[Category.FILE])
        value = TaintValue(origins=frozenset({Origin.PARAM})).with_kill(spec)
        assert "os.path.basename" in value.kills

    def test_with_origin_keeps_the_path(self):
        value = TaintValue().with_origin(Origin.REQUEST, source_step())
        assert value.origins == frozenset({Origin.REQUEST})
        assert len(value.path) == 1

    def test_append_ignores_a_repeat_of_the_same_line(self):
        value = TaintValue(origins=frozenset({Origin.PARAM}), path=(source_step(3),))
        same = TraceStep(3, 9, STEP_KIND_SANITIZE, "kill:int")
        assert value.append(same).path == value.path

    def test_to_dict_is_serialisable(self):
        import json

        value = TaintValue(origins=frozenset({Origin.PARAM}), path=(source_step(),))
        json.dumps(value.to_dict())


def _spec(name, kills=(), produces=(), full=True):
    from syrth.registry import KillSpec

    return KillSpec(name=name, kills=frozenset(kills), produces=frozenset(produces),
                    full=full)


class TestTaintEngineResolution:
    def test_origin_classification(self, engine):
        assert engine.origin_of("input") == Origin.STDIN
        assert engine.origin_of("os.environ") == Origin.ENV
        assert engine.origin_of("sys.argv") == Origin.CLI
        assert engine.origin_of("request.args") == Origin.REQUEST
        assert engine.origin_of("cur.fetchone") == Origin.DB_READ
        assert engine.origin_of("plain_name") is None
        assert engine.origin_of("") is None

    def test_reader_disambiguation_by_receiver(self, engine):
        assert engine.origin_of("fh.read") == Origin.FILE_READ
        assert engine.origin_of("response.text") == Origin.NET_READ
        assert engine.origin_of("requests.get") is None  # a call, not a reader

    def test_canonical_sink_resolution(self, engine):
        assert engine.canonical_sink("cursor.execute") == "SQL_EXECUTE"
        assert engine.canonical_sink("json.loads") is None
        assert engine.canonical_sink("pickle.loads") == "DESER_UNSAFE"
        assert engine.canonical_sink("nope") is None

    def test_sink_category(self, engine):
        assert engine.sink_category("SQL_EXECUTE") == "SCAT:SQL"
        assert engine.sink_category("EXEC_COMMAND") == "SCAT:EXEC"
        assert engine.sink_category("nope") is None

    def test_high_risk_classification(self, engine):
        assert engine.is_high_risk_sink("EXEC_COMMAND") is True
        assert engine.is_high_risk_sink("DESER_UNSAFE") is True
        assert engine.is_high_risk_sink("REDIRECT_NAV") is False

    def test_kill_never_resolves_for_a_sink(self, engine):
        assert engine.kill_for("pickle.loads") is None
        assert engine.kill_for("json.loads").name == "json.loads"


class TestTaintEnginePropagation:
    def test_parameter_source_is_position_based(self, engine):
        value = engine.parameter_source("anything", 4)
        assert value.origins == frozenset({Origin.PARAM})
        assert value.path[0].line == 4

    def test_merge_unions_origins(self, engine):
        left = TaintValue(origins=frozenset({Origin.PARAM}))
        right = TaintValue(origins=frozenset({Origin.ENV}))
        merged = engine.merge([left, right])
        assert merged.origins == frozenset({Origin.PARAM, Origin.ENV})

    def test_merge_of_clean_values_stays_clean(self, engine):
        assert engine.merge([TaintValue(), TaintValue()]).origins == frozenset()

    def test_merge_picks_the_shorter_explaining_path(self, engine):
        long_path = tuple(source_step(i) for i in range(1, 6))
        short_path = tuple(source_step(i) for i in range(1, 3))
        left = TaintValue(origins=frozenset({Origin.PARAM}), path=long_path)
        right = TaintValue(origins=frozenset({Origin.ENV}), path=short_path)
        assert len(engine.merge([left, right]).path) == 2

    def test_merge_intersects_neutralisation(self, engine):
        safe = TaintValue(origins=frozenset({Origin.PARAM}),
                          neutralised=frozenset({Category.EXEC}))
        unsafe = TaintValue(origins=frozenset({Origin.ENV}))
        merged = engine.merge([safe, unsafe])
        assert not merged.sanitised_for(Category.EXEC)

    def test_merge_ignores_clean_operands_when_intersecting(self, engine):
        """A literal beside a sanitised value must not launder the sanitiser."""
        safe = TaintValue(origins=frozenset({Origin.PARAM}),
                          neutralised=frozenset({Category.EXEC}))
        literal = TaintValue(constant=True)
        assert engine.merge([literal, safe]).sanitised_for(Category.EXEC)

    def test_assignment_binding(self, engine):
        state = TaintState()
        engine.propagate_through_assignment("cmd", TaintValue(
            origins=frozenset({Origin.PARAM})), state)
        assert state.value("cmd").tainted

    def test_call_result_inherits_argument_taint(self, engine):
        args = [TaintValue(origins=frozenset({Origin.PARAM}))]
        assert engine.propagate_through_call("os.system", args).tainted

    def test_call_result_of_a_reader_gains_its_origin(self, engine):
        result = engine.propagate_through_call("cur.fetchone", [TaintValue()])
        assert Origin.DB_READ in result.origins

    def test_is_dangerous_argument(self, engine):
        assert engine.is_dangerous_argument("SQL_EXECUTE", 0, None)
        assert not engine.is_dangerous_argument("SQL_EXECUTE", 1, None)
        assert not engine.is_dangerous_argument("SQL_EXECUTE", 0, "params")
        assert engine.is_dangerous_argument("SQL_EXECUTE", None, None)


class TestCheckSink:
    def test_reports_an_unmitigated_flow(self, engine):
        assert engine.check_sink("SQL_EXECUTE", [Origin.PARAM], Category.SQL) == "report"

    def test_suppresses_a_fully_neutralised_flow(self, engine):
        assert engine.check_sink(
            "SQL_EXECUTE", [Origin.PARAM], Category.SQL,
            neutralised=[Category.SQL],
        ) == "suppressed"

    def test_downgrades_a_partially_mitigated_flow(self, engine):
        assert engine.check_sink(
            "SQL_EXECUTE", [Origin.PARAM], Category.SQL, partial=[Category.SQL],
        ) == "partial"

    def test_no_origins_means_no_flow(self, engine):
        assert engine.check_sink("SQL_EXECUTE", [], Category.SQL) == "suppressed"

    def test_flow_tokens(self, engine):
        assert engine.flows_for([Origin.ENV, Origin.PARAM], "EXEC_COMMAND") == [
            "flow:ENV->EXEC_COMMAND", "flow:PARAM->EXEC_COMMAND",
        ]

    def test_tainted_tokens_are_sorted(self, engine):
        assert engine.tainted_tokens(["os.system", "EXEC_COMMAND"]) == [
            "tainted:EXEC_COMMAND", "tainted:os.system"
        ]


class TestParserIntegration:
    def setup_method(self):
        self.parser = PythonParser()

    def traces(self, code, function=None):
        trace = self.parser.parse(code)
        if function:
            return trace.get_function(function).traces
        return trace.all_traces()

    def test_request_to_sink(self):
        found = self.traces(
            'def v(request):\n'
            '    uid = request.GET.get("id")\n'
            '    cur.execute("SELECT * FROM t WHERE id=" + uid)\n'
        )
        assert found and found[0].category == Category.SQL
        assert Origin.REQUEST in found[0].origins

    def test_parameter_to_sink(self):
        found = self.traces('def v(cmd):\n    os.system(cmd)\n')
        assert Origin.PARAM in found[0].origins

    def test_no_source_means_no_flow(self):
        assert self.traces('def v():\n    os.system("ls")\n') == []

    def test_flow_tokens_are_derived_from_traces(self):
        trace = self.parser.parse('def v(a):\n    os.system(a)\n')
        assert trace.functions[0].flows == ["flow:PARAM->EXEC_COMMAND"]

    def test_sanitised_flow_produces_no_token(self):
        trace = self.parser.parse(
            'import shlex\ndef v(cmd):\n    os.system("ls " + shlex.quote(cmd))\n'
        )
        assert trace.functions[0].flows == []
        assert trace.functions[0].sanitisers == ["shlex.quote"]

    def test_amplifier_is_reported_without_taint(self):
        """No origin, but the value's provenance is not observable.

        A local holding a constant is the honest fixture: the analyser cannot
        see where the value came from, so the assertion is the finding. A literal
        handed straight to ``mark_safe`` is a constant at runtime and is
        suppressed separately.
        """
        found = self.traces(
            'def v():\n    x = "<b>x</b>"\n    return mark_safe(x)\n'
        )
        assert found and found[0].detector == "amplifier"
        assert found[0].origins == ()

    def test_amplifier_on_a_literal_is_not_reported(self):
        assert not [
            t for t in self.traces('def v():\n    return mark_safe("<b>x</b>")\n')
            if t.detector == "amplifier"
        ]

    def test_module_scope_flow(self):
        trace = self.parser.parse('import os\nos.system(input())\n')
        assert any(t.sink == "EXEC_COMMAND" for t in trace.module_traces)
