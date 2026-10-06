"""
SYRTH Feature Extraction
=========================
Deterministic, rename-invariant feature vectors over a ``FunctionTrace``.

Rename invariance
-----------------
The default vector contains **no identifier-derived features**. Every field is a
function of the dataflow shape: which sink categories are reached, from which
origins, through which propagation edges, and which sanitisers were observed.
Two programs that differ only by a consistent renaming of identifiers produce
byte-identical vectors, which is a guarantee this project can make and measure
(``tests/test_analysis_correctness.py::TestRenameInvariance``).

Identifier hints remain available through :meth:`FeatureExtractor.name_hints`,
which is deliberately *not* part of :data:`FEATURE_NAMES`, so a downstream model
cannot acquire a dependence on naming conventions by accident.

Layout stability
----------------
The vector layout is fixed and versioned by :data:`FEATURE_SCHEMA_VERSION`. A
saved model records the version it was trained against and refuses to score a
vector built with a different layout, rather than silently mis-scoring it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from ..parser.base import FileTrace, FunctionTrace
from ..registry import (
    CATEGORIES,
    CATEGORY_CWE,
    EXTERNAL_ORIGINS,
    ORIGINS,
    normalise_token,
    sink_spec_for,
)
from ..trace import DETECTOR_AMPLIFIER

#: Version of the feature layout. Bump whenever a field is added, removed or
#: reordered. Stored in model bundles and checked at inference time.
FEATURE_SCHEMA_VERSION = 3

_FEATURE_GROUPS: list[tuple[str, list[str]]] = [
    (
        "structural",
        [
            "sink_count",
            "call_count",
            "arg_count",
            "decorator_count",
            "return_count",
            "unique_call_count",
            "loop_count",
            "branch_count",
            "nesting_depth",
            "statement_count",
            "has_try",
            "has_with",
            "has_comprehension",
            "has_lambda",
            "has_async",
            "line_span",
        ],
    ),
    (
        "taint",
        [
            "flow_count",
            "tainted_sink_count",
            "distinct_origins",
            "has_external_origin",
            "has_global_only_origin",
            "max_path_length",
            "avg_path_length",
            "sanitiser_count",
            "has_partial_mitigation",
            "has_full_mitigation_observed",
            "has_amplifier",
            "has_module_scope_flow",
        ],
    ),
]

# One flag per sink category, then one per tainted category.
_FEATURE_GROUPS.append(
    ("scat", [f"scat_{c.lower()}" for c in CATEGORIES])
)
_FEATURE_GROUPS.append(
    ("tainted", [f"tainted_{c.lower()}" for c in CATEGORIES])
)
_FEATURE_GROUPS.append(
    ("origin", [f"origin_{o.lower()}" for o in ORIGINS])
)

_FEATURE_GROUPS.extend(
    [
        (
            "sanitiser",
            [
                "kill_shell_quote",
                "kill_path_basename",
                "kill_path_normalise",
                "kill_html_escape",
                "kill_html_clean",
                "kill_numeric_coercion",
                "kill_structural_decoder",
                "kill_safe_deserialiser",
                "kill_defused_xml",
                "kill_regex_escape",
                "kill_url_encode",
            ],
        ),
        (
            "sink_shape",
            [
                "sink_at_positional",
                "sink_at_keyword",
                "sink_at_splat",
                "sink_high_risk",
                "sink_low_risk",
                "sink_deser",
                "sink_crypto",
                "sink_network",
                "sink_mail",
                "sink_template",
            ],
        ),
        (
            "context",
            [
                "framework_django",
                "framework_flask",
                "framework_fastapi",
                "framework_other",
                "has_auth_decorator",
                "has_csrf_exempt",
                "has_sql_literal",
                "parse_error",
            ],
        ),
    ]
)

FEATURE_NAMES: list[str] = [
    name for _group, names in _FEATURE_GROUPS for name in names
]

NUM_FEATURES: int = len(FEATURE_NAMES)

#: Per-group index ranges, for readable access in tests and reports.
FEATURE_INDEX: dict[str, dict[str, int]] = {}
_offset = 0
for _group, _names in _FEATURE_GROUPS:
    FEATURE_INDEX[_group] = {name: _offset + i for i, name in enumerate(_names)}
    _offset += len(_names)

assert NUM_FEATURES == _offset, "feature layout accounting mismatch"

#: Flat name -> index map, built once for O(1) writes.
_FEATURE_SLOT: dict[str, int] = {
    name: index for mapping in FEATURE_INDEX.values() for name, index in mapping.items()
}

#: Maps a sanitiser name to the feature that records its presence.
_KILL_FEATURE: dict[str, str] = {
    "shlex.quote": "kill_shell_quote",
    "os.path.basename": "kill_path_basename",
    "os.path.normpath": "kill_path_normalise",
    "os.path.realpath": "kill_path_normalise",
    "html.escape": "kill_html_escape",
    "markupsafe.escape": "kill_html_escape",
    "bleach.clean": "kill_html_clean",
    "nh3.clean": "kill_html_clean",
    "lxml.html.cleanup": "kill_html_clean",
    "int": "kill_numeric_coercion",
    "float": "kill_numeric_coercion",
    "bool": "kill_numeric_coercion",
    "ast.literal_eval": "kill_structural_decoder",
    "json.loads": "kill_structural_decoder",
    "json.load": "kill_structural_decoder",
    "yaml.safe_load": "kill_safe_deserialiser",
    "defusedxml": "kill_defused_xml",
    "re.escape": "kill_regex_escape",
    "urllib.parse.quote": "kill_url_encode",
    "urllib.parse.quote_plus": "kill_url_encode",
    "sqlalchemy.sql.text": "kill_regex_escape",
    "cursor.mogrify": "kill_structural_decoder",
}

_CATEGORY_INDEX: dict[str, int] = {
    category: FEATURE_INDEX["scat"][f"scat_{category.lower()}"] for category in CATEGORIES
}
_TAINTED_INDEX: dict[str, int] = {
    category: FEATURE_INDEX["tainted"][f"tainted_{category.lower()}"]
    for category in CATEGORIES
}
_ORIGIN_INDEX: dict[str, int] = {
    origin: FEATURE_INDEX["origin"][f"origin_{origin.lower()}"] for origin in ORIGINS
}

#: Sink families that get their own shape flag, because the mitigation strategy
#: differs for each and a single category flag cannot express it.
_SHAPE_FLAGS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("DESER_UNSAFE",), "sink_deser"),
    (("CRYPTO_WEAK",), "sink_crypto"),
    (("NET_REQUEST",), "sink_network"),
    (("XSS_MAIL_BODY",), "sink_mail"),
    (("XSS_TEMPLATE_BODY", "XSS_TEMPLATE_NAME", "XSS_TEMPLATE_PATH"), "sink_template"),
)


class FeatureExtractionError(RuntimeError):
    """Raised when a feature vector cannot be produced for a record."""


class FeatureExtractor:
    """Produces one fixed-length feature vector per function.

    The extractor is stateless and deterministic: the same ``FunctionTrace``
    always yields the same vector.
    """

    def extract_file(self, trace: FileTrace) -> list[dict[str, object]]:
        """Extract a record per function in ``trace``.

        Returns:
            A list of dicts with keys ``name``, ``lineno``, ``features``,
            ``tokens`` and ``traces``.
        """
        results: list[dict[str, object]] = []
        for func in trace.functions:
            results.append(
                {
                    "name": func.name,
                    "lineno": func.lineno,
                    "features": self.extract_function(func, trace),
                    "tokens": func.to_token_sequence(),
                    "traces": list(func.traces),
                }
            )
        if trace.module_traces:
            results.append(
                {
                    "name": "<module>",
                    "lineno": 1,
                    "features": self.extract_module(trace),
                    "tokens": [],
                    "traces": list(trace.module_traces),
                }
            )
        return results

    def extract_function(
        self, func: FunctionTrace, file_trace: FileTrace | None = None
    ) -> list[float]:
        """Extract the feature vector for one function.

        Args:
            func: Function trace to analyse.
            file_trace: Optional file trace, used only for framework flags.

        Returns:
            A list of ``NUM_FEATURES`` floats in :data:`FEATURE_NAMES` order.
        """
        vector = [0.0] * NUM_FEATURES
        traces = list(func.traces)
        origins = _union_origins(traces)

        # -- structural ---------------------------------------------------
        self._set(vector, "sink_count", float(len(func.sinks)))
        self._set(vector, "call_count", float(len(func.calls)))
        self._set(vector, "arg_count", float(len(func.args)))
        self._set(vector, "decorator_count", float(len(func.decorators)))
        self._set(vector, "return_count", float(len(func.returns)))
        self._set(vector, "unique_call_count", float(len(set(func.calls))))
        self._set(vector, "line_span", float(max(0, func.end_lineno - func.lineno)))

        # -- taint --------------------------------------------------------
        self._set(vector, "flow_count", float(len(traces)))
        tainted_sinks = {t.sink for t in traces if t.origins}
        self._set(vector, "tainted_sink_count", float(len(tainted_sinks)))
        self._set(vector, "distinct_origins", float(len(origins)))
        self._set(vector, "has_external_origin", float(bool(origins & EXTERNAL_ORIGINS)))
        self._set(
            vector,
            "has_global_only_origin",
            float(bool(origins) and origins <= {"GLOBAL"}),
        )
        lengths = [len(t.steps) for t in traces] or [0]
        self._set(vector, "max_path_length", float(max(lengths)))
        self._set(vector, "avg_path_length", round(sum(lengths) / len(lengths), 4))
        self._set(
            vector,
            "has_amplifier",
            float(any(t.detector == DETECTOR_AMPLIFIER for t in traces)),
        )
        self._set(
            vector,
            "has_partial_mitigation",
            float(any("partial mitigation" in n for t in traces for n in t.notes)),
        )
        kills = sorted(set(func.sanitisers) | {k for t in traces for k in t.kills})
        self._set(vector, "sanitiser_count", float(len(kills)))
        self._set(vector, "has_full_mitigation_observed", float(bool(kills)))
        for kill in kills:
            feature = _KILL_FEATURE.get(kill)
            if feature is not None:
                self._set(vector, feature, 1.0)

        # -- categories ---------------------------------------------------
        for sink in func.sinks:
            spec = sink_spec_for(sink)
            if spec is None:
                continue
            self._set_at(vector, _CATEGORY_INDEX[spec.category], 1.0)
        for item in traces:
            if not item.origins:
                continue
            self._set_at(vector, _TAINTED_INDEX[item.category], 1.0)
        for origin in origins:
            index = _ORIGIN_INDEX.get(origin)
            if index is not None:
                self._set_at(vector, index, 1.0)

        # -- sink shape ----------------------------------------------------
        self._set(
            vector, "sink_high_risk",
            float(sum(1 for s in func.sinks if (sink_spec_for(s) and sink_spec_for(s).high_risk))),
        )
        self._set(
            vector, "sink_low_risk",
            float(sum(1 for s in func.sinks if (sink_spec_for(s) and not sink_spec_for(s).high_risk))),
        )
        for sink in func.sinks:
            for family, flag in _SHAPE_FLAGS:
                if sink in family:
                    self._set(vector, flag, 1.0)
        for trace in traces:
            if trace.sink_arg.startswith("kw:"):
                self._set(vector, "sink_at_keyword", 1.0)
            elif trace.sink_arg == "splat":
                self._set(vector, "sink_at_splat", 1.0)
            else:
                self._set(vector, "sink_at_positional", 1.0)

        # -- context --------------------------------------------------------
        self._set(
            vector, "has_auth_decorator", float(bool(func.has_auth_decorator))
        )
        self._set(vector, "has_csrf_exempt", float(bool(func.has_csrf_exempt)))
        self._set(vector, "has_sql_literal", float(bool(func.has_sql_string)))
        if file_trace is not None:
            self._set_context_framework(vector, file_trace.framework_tokens)
            self._set(vector, "parse_error", float(bool(file_trace.parse_errors)))
        return vector

    def extract_module(self, trace: FileTrace) -> list[float]:
        """Feature vector for module scope.

        Module scope has no enclosing function, so the vector records the
        module's own sinks and flows. Keeping it as a separate record means a
        module-level injection is reported instead of being silently dropped.
        """
        vector = [0.0] * NUM_FEATURES
        traces = list(trace.module_traces)
        origins = _union_origins(traces)
        sinks = {t.sink for t in traces}
        self._set(vector, "sink_count", float(len(sinks)))
        self._set(vector, "call_count", float(len(trace.module_calls)))
        self._set(vector, "flow_count", float(len(traces)))
        self._set(vector, "tainted_sink_count", float(len(sinks)))
        self._set(vector, "distinct_origins", float(len(origins)))
        self._set(vector, "has_external_origin", float(bool(origins & EXTERNAL_ORIGINS)))
        self._set(vector, "has_module_scope_flow", 1.0)
        for kill in sorted(set(trace.sanitisers)):
            feature = _KILL_FEATURE.get(kill)
            if feature is not None:
                self._set_at(vector, _FEATURE_SLOT[feature], 1.0)
        self._set(
            vector, "sanitiser_count", float(len(set(trace.sanitisers)))
        )
        self._set(
            vector, "has_full_mitigation_observed", float(bool(trace.sanitisers))
        )
        for sink in sinks:
            spec = sink_spec_for(sink)
            if spec is not None:
                self._set_at(vector, _CATEGORY_INDEX[spec.category], 1.0)
        for item in traces:
            if item.origins:
                self._set_at(vector, _TAINTED_INDEX[item.category], 1.0)
        for origin in origins:
            index = _ORIGIN_INDEX.get(origin)
            if index is not None:
                self._set_at(vector, index, 1.0)
        self._set_context_framework(vector, trace.framework_tokens)
        self._set(vector, "parse_error", float(bool(trace.parse_errors)))
        return vector

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _set(vector: list[float], name: str, value: float) -> None:
        """Write ``value`` into ``vector`` at the index registered for ``name``."""
        index = _FEATURE_SLOT.get(name)
        if index is None:
            raise FeatureExtractionError(f"unknown feature {name!r}")
        vector[index] = float(value)

    @staticmethod
    def _set_at(vector: list[float], index: int, value: float) -> None:
        """Write ``value`` into ``vector`` at a pre-resolved index."""
        if not 0 <= index < NUM_FEATURES:
            raise FeatureExtractionError(f"feature index out of range: {index}")
        vector[index] = float(value)

    @staticmethod
    def _set_context_framework(
        vector: list[float], framework_tokens: Sequence[str]
    ) -> None:
        """Write framework flags from the file's framework tokens."""
        tokens = set(framework_tokens)
        context = FEATURE_INDEX["context"]
        for name, value in (
            ("framework_django", float("framework:django" in tokens)),
            ("framework_flask", float("framework:flask" in tokens)),
            ("framework_fastapi", float("framework:fastapi" in tokens)),
            (
                "framework_other",
                float(
                    bool(
                        tokens
                        - {"framework:django", "framework:flask", "framework:fastapi"}
                    )
                ),
            ),
        ):
            vector[context[name]] = value

    @staticmethod
    def name_hints(func: FunctionTrace) -> list[str]:
        """Identifier-normalisation hints for ``func``.

        Intentionally *outside* :data:`FEATURE_NAMES`. These tokens describe
        what the developer called things, not what the code does, so feeding
        them to a classifier would reintroduce exactly the naming dependence the
        default vector is designed to exclude.
        """
        hints = [f"nh_def:{normalise_token(func.name)}"]
        hints.extend(f"nh_arg:{normalise_token(a)}" for a in func.args)
        hints.extend(f"nh_call:{normalise_token(c)}" for c in sorted(set(func.calls)))
        return hints

    @staticmethod
    def matrix(records: Iterable[Mapping[str, object]]) -> list[list[float]]:
        """Stack ``records`` into a plain feature matrix."""
        return [list(record["features"]) for record in records]  # type: ignore[arg-type]

    def to_record(self, func: FunctionTrace) -> dict[str, object]:
        """Build the classifier input record for one function."""
        return {
            "name": func.name,
            "lineno": func.lineno,
            "features": self.extract_function(func),
            "tokens": func.to_token_sequence(),
            "category": func.tainted_categories()[:1] or func.sink_categories()[:1],
        }

    def category_of(self, vector: Sequence[float]) -> str:
        """Inverse of the category flags for a whole vector.

        Returns:
            The CWE identifier when exactly one sink-category flag is set,
            otherwise ``""``. Used to derive a weak, fully explainable label for
            functions with no confirmed taint flow.
        """
        if len(vector) != NUM_FEATURES:
            raise FeatureExtractionError(
                f"expected {NUM_FEATURES} features, got {len(vector)}"
            )
        hits = [
            category
            for category in CATEGORIES
            if vector[_CATEGORY_INDEX[category]] > 0.0
        ]
        return CATEGORY_CWE[hits[0]] if len(hits) == 1 else ""

    def categories_of(self, vector: Sequence[float]) -> list[str]:
        """All sink categories whose flag is set in ``vector``."""
        if len(vector) != NUM_FEATURES:
            raise FeatureExtractionError(
                f"expected {NUM_FEATURES} features, got {len(vector)}"
            )
        return [c for c in CATEGORIES if vector[_CATEGORY_INDEX[c]] > 0.0]


def _union_origins(traces: Sequence) -> set:
    """Union the reported origins of a trace sequence."""
    origins: set = set()
    for trace in traces:
        origins.update(trace.origins)
    return origins


def feature_schema() -> Mapping[str, object]:
    """Describe the vector layout, for embedding in model bundles."""
    return {
        "version": FEATURE_SCHEMA_VERSION,
        "count": NUM_FEATURES,
        "names": list(FEATURE_NAMES),
        "rename_invariant": True,
    }


__all__ = [
    "FEATURE_INDEX",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FeatureExtractionError",
    "FeatureExtractor",
    "NUM_FEATURES",
    "feature_schema",
]
