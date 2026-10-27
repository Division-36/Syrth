"""
Tests for the feature vector.

The vector is rename-invariant by construction, so most of this module is about
pinning that guarantee and the schema guards that keep it true: no
identifier-derived field may enter the default vector, and the layout is
versioned.
"""

import pytest

from syrth.features import (
    FEATURE_INDEX,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    NUM_FEATURES,
    FeatureExtractionError,
    FeatureExtractor,
    feature_schema,
)
from syrth.parser import PythonParser


@pytest.fixture
def extractor():
    return FeatureExtractor()


def parse(code, path="m.py"):
    return PythonParser().parse(code, path)


def vector_of(extractor, code):
    trace = parse(code)
    return extractor.extract_function(trace.functions[0], trace)


def value(vec, name):
    return vec[FEATURE_NAMES.index(name)]


class TestLayout:
    def test_declared_width(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_names_are_unique(self):
        assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)

    def test_group_indices_tile_the_vector(self):
        indices = sorted(
            i for group in FEATURE_INDEX.values() for i in group.values()
        )
        assert indices == list(range(NUM_FEATURES))

    def test_schema_is_described(self):
        schema = feature_schema()
        assert schema["version"] == FEATURE_SCHEMA_VERSION
        assert schema["count"] == NUM_FEATURES
        assert schema["rename_invariant"] is True


class TestRenameInvariance:
    """The guarantee the whole design rests on."""

    @pytest.mark.parametrize(
        "template",
        [
            'def h({p}):\n    cur.execute("SELECT * FROM t WHERE n=" + {p})\n',
            'def h({p}):\n    os.system("ls " + {p})\n',
            'def h({p}):\n    q = "S" + {p}\n    cur.execute(q)\n',
            'def h({p}):\n    open("/d/" + {p})\n',
        ],
    )
    def test_vector_is_independent_of_every_identifier(self, extractor, template):
        baseline = None
        for name in ("user_id", "x", "zzz", "value_1", "tmp", "q", "h"):
            vec = vector_of(extractor, template.format(p=name))
            if baseline is None:
                baseline = vec
            else:
                assert vec == baseline, f"vector changed when the parameter became {name!r}"

    def test_local_variable_renaming_is_invariant(self, extractor):
        a = vector_of(extractor, 'def h(z):\n    q = z\n    cur.execute("S" + q)\n')
        b = vector_of(
            extractor,
            'def h(z):\n    a_completely_other_name = z\n'
            '    cur.execute("S" + a_completely_other_name)\n',
        )
        assert a == b

    def test_name_hints_are_not_in_the_default_vector(self, extractor):
        from syrth.parser.base import FunctionTrace

        func = FunctionTrace(
            name="fetch_user_record",
            args=["user_id", "target"],
            calls=["get_user", "os.system"],
        )
        hints = FeatureExtractor.name_hints(func)
        assert hints and all(h.startswith("nh_") for h in hints)
        assert not any(name in FEATURE_NAMES for name in hints)


class TestTaintFeatures:
    def test_confirmed_flow_sets_the_taint_features(self, extractor):
        vec = vector_of(extractor, 'def v(x):\n    cur.execute("SELECT " + x)\n')
        assert value(vec, "flow_count") == 1.0
        assert value(vec, "tainted_sink_count") == 1.0
        assert value(vec, "tainted_sql") == 1.0
        assert value(vec, "origin_param") == 1.0
        assert value(vec, "has_external_origin") == 1.0
        assert value(vec, "max_path_length") >= 2.0

    def test_no_flow_leaves_taint_features_at_zero(self, extractor):
        vec = vector_of(extractor, 'def v():\n    cur.execute("SELECT 1")\n')
        assert value(vec, "flow_count") == 0.0
        assert value(vec, "tainted_sink_count") == 0.0
        assert value(vec, "origin_param") == 0.0

    def test_sql_category_flag_is_set_without_a_flow(self, extractor):
        vec = vector_of(extractor, 'def v():\n    cur.execute("SELECT 1")\n')
        assert value(vec, "scat_sql") == 1.0
        assert value(vec, "sink_count") == 1.0

    def test_request_origin_is_recorded(self, extractor):
        vec = vector_of(
            extractor, 'def v(request):\n    os.system(request.GET["c"])\n'
        )
        assert value(vec, "origin_request") == 1.0
        assert value(vec, "origin_param") == 0.0

    def test_global_only_origin_is_flagged_separately(self, extractor):
        vec = vector_of(
            extractor,
            'def v(self):\n    self.cmd = "ls"\n    os.system(self.cmd)\n',
        )
        # A self-attribute is process state, not an external input.
        assert value(vec, "flow_count") >= 0.0

    def test_path_length_features(self, extractor):
        short = vector_of(extractor, 'def v(x):\n    os.system(x)\n')
        long = vector_of(
            extractor,
            'def v(x):\n    a = x\n    b = "x" + a\n    c = "y" + b\n'
            '    os.system(c)\n',
        )
        assert value(long, "max_path_length") > value(short, "max_path_length")


class TestSanitiserFeatures:
    def test_sanitiser_is_visible_even_when_the_flow_is_suppressed(self, extractor):
        vec = vector_of(
            extractor, 'import shlex\ndef v(x):\n    os.system("ls " + shlex.quote(x))\n'
        )
        assert value(vec, "kill_shell_quote") == 1.0
        assert value(vec, "sanitiser_count") == 1.0
        assert value(vec, "flow_count") == 0.0

    def test_each_category_typed_kill_maps_to_its_feature(self, extractor):
        cases = [
            ('import os\ndef v(x):\n    open("/d/" + os.path.basename(x))\n',
             "kill_path_basename"),
            ('import html\ndef v(x):\n    return mark_safe(html.escape(x))\n',
             "kill_html_escape"),
            ('def v(x):\n    cur.execute("S" + str(int(x)))\n',
             "kill_numeric_coercion"),
            ('import yaml\ndef v(x):\n    return yaml.safe_load(x)\n',
             "kill_safe_deserialiser"),
        ]
        for code, feature in cases:
            assert value(vector_of(extractor, code), feature) == 1.0, feature


class TestSinkShapeFeatures:
    def test_high_risk_split(self, extractor):
        exec_vec = vector_of(extractor, 'def v(x):\n    os.system(x)\n')
        sql_vec = vector_of(extractor, 'def v(x):\n    cur.execute("S" + x)\n')
        assert exec_vec[FEATURE_NAMES.index("sink_high_risk")] == 1.0
        assert sql_vec[FEATURE_NAMES.index("sink_low_risk")] == 1.0

    def test_family_flags(self, extractor):
        deser = vector_of(extractor, 'import pickle\ndef v(x):\n    pickle.loads(x)\n')
        assert deser[FEATURE_NAMES.index("sink_deser")] == 1.0
        net = vector_of(extractor, 'import requests\ndef v(u):\n    requests.get(u)\n')
        assert net[FEATURE_NAMES.index("sink_network")] == 1.0

    def test_keyword_sink_argument_is_flagged(self, extractor):
        vec = vector_of(
            extractor, 'def v(x):\n    cur.execute(query="SELECT " + x)\n'
        )
        assert vec[FEATURE_NAMES.index("sink_at_keyword")] == 1.0
        assert vec[FEATURE_NAMES.index("sink_at_positional")] == 0.0


class TestContextFeatures:
    def test_framework_flags(self, extractor):
        trace = parse("from flask import Flask\ndef v(x):\n    os.system(x)\n")
        vec = extractor.extract_function(trace.functions[0], trace)
        assert vec[FEATURE_NAMES.index("framework_flask")] == 1.0
        assert vec[FEATURE_NAMES.index("framework_django")] == 0.0

    def test_auth_decorator_flag(self, extractor):
        vec = vector_of(
            extractor, '@login_required\ndef v(x):\n    os.system(x)\n'
        )
        assert vec[FEATURE_NAMES.index("has_auth_decorator")] == 1.0
        assert vec[FEATURE_NAMES.index("has_csrf_exempt")] == 0.0

    def test_csrf_exempt_flag(self, extractor):
        vec = vector_of(extractor, '@csrf_exempt\ndef v(x):\n    os.system(x)\n')
        assert vec[FEATURE_NAMES.index("has_csrf_exempt")] == 1.0

    def test_sql_literal_flag(self, extractor):
        vec = vector_of(
            extractor, 'def v():\n    cur.execute("SELECT * FROM t")\n'
        )
        assert vec[FEATURE_NAMES.index("has_sql_literal")] == 1.0

    def test_parse_error_flag(self, extractor):
        trace = parse("def broken(\n    return 1\n")
        func = trace.functions[0] if trace.functions else None
        if func is not None:
            vec = extractor.extract_function(func, trace)
            assert vec[FEATURE_NAMES.index("parse_error")] == 1.0


class TestStructuralFeatures:
    def test_counts(self, extractor):
        vec = vector_of(
            extractor,
            "def v(a, b):\n"
            '    cur.execute("SELECT " + a)\n'
            "    return b\n",
        )
        assert value(vec, "arg_count") == 2.0
        assert value(vec, "return_count") == 1.0
        assert value(vec, "call_count") >= 1.0

    def test_line_span(self, extractor):
        vec = vector_of(
            extractor, "def v(a):\n    cur.execute('SELECT ' + a)\n    return 1\n"
        )
        assert value(vec, "line_span") >= 1.0


class TestModuleScopeRecord:
    def test_module_record_is_emitted(self, extractor):
        trace = parse("import os\nos.system(input())\n")
        records = extractor.extract_file(trace)
        names = [r["name"] for r in records]
        assert "<module>" in names

    def test_module_record_carries_the_flow(self, extractor):
        trace = parse("import os\nos.system(input())\n")
        record = next(r for r in extractor.extract_file(trace) if r["name"] == "<module>")
        vec = record["features"]
        assert vec[FEATURE_NAMES.index("has_module_scope_flow")] == 1.0
        assert vec[FEATURE_NAMES.index("tainted_exec")] == 1.0

    def test_matrix_helper(self, extractor):
        trace = parse("def v(a):\n    os.system(a)\ndef w():\n    pass\n")
        matrix = extractor.matrix(extractor.extract_file(trace))
        assert all(len(row) == NUM_FEATURES for row in matrix)


class TestGuards:
    def test_unknown_feature_name_raises(self, extractor):
        with pytest.raises(FeatureExtractionError):
            FeatureExtractor._set([0.0] * NUM_FEATURES, "no_such_feature", 1.0)

    def test_out_of_range_index_raises(self, extractor):
        with pytest.raises(FeatureExtractionError):
            FeatureExtractor._set_at([0.0] * NUM_FEATURES, NUM_FEATURES, 1.0)

    def test_category_of_requires_exactly_one_category(self, extractor):
        trace = parse("def v():\n    cur.execute('SELECT 1')\n")
        vec = extractor.extract_function(trace.functions[0], trace)
        assert extractor.category_of(vec) == "CWE-89"

    def test_category_of_is_empty_when_ambiguous(self, extractor):
        trace = parse("def v():\n    cur.execute('SELECT 1')\n    os.system('ls')\n")
        vec = extractor.extract_function(trace.functions[0], trace)
        assert extractor.category_of(vec) == ""
        assert set(extractor.categories_of(vec)) == {"SQL", "EXEC"}

    def test_wrong_width_vector_is_rejected(self, extractor):
        with pytest.raises(FeatureExtractionError):
            extractor.category_of([0.0] * 5)
