"""
SYRTH Parser Base
=================
Language-agnostic AST containers and the tree-sitter base parser.

Correctness note
----------------
tree-sitter reports node positions as **byte** offsets into the UTF-8 encoded
source. Slicing a Python ``str`` with those offsets silently corrupts every
node that follows the first multi-byte character in the file. The previous
release did exactly that, which silently renamed every function, sink, argument
and call in any file containing a non-ASCII character -- a file set that
includes essentially all real Python. This module keeps the encoded source
alongside the decoded text and decodes node spans from bytes, which is the only
correct way to read tree-sitter positions in Python.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import tree_sitter

from ..registry import (
    SECURITY_DECORATORS,
    SINK_SPECS,
    canonical_sink,
    normalise_token,
    sink_spec_for,
)
from ..trace import Trace


@dataclass
class Token:
    """Language-agnostic parsed token.

    Attributes:
        type: AST node type.
        name: Function/class/variable/call name.
        line: 1-indexed source line.
        column: 0-indexed source column.
        children: Child tokens.
        language: Source language tag.
        metadata: Language-specific extras.
    """

    type: str
    name: str
    line: int
    column: int
    children: list[Token] = field(default_factory=list)
    language: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dictionary."""
        return {
            "type": self.type,
            "name": self.name,
            "line": self.line,
            "column": self.column,
            "children": [child.to_dict() for child in self.children],
            "language": self.language,
            "metadata": self.metadata,
        }


@dataclass
class FunctionTrace:
    """Security-relevant summary of one function.

    Attributes:
        name: Function name.
        lineno: 1-indexed line of the ``def`` statement.
        end_lineno: 1-indexed line of the last statement in the body.
        decorators: Decorator names as written.
        args: Parameter names, in declaration order, minus ``self``/``cls``.
        arg_positions: ``(index, name)`` for every declared parameter, which is
            what sink argument schemas are matched against.
        calls: Call names as written, in source order.
        sinks: Canonical sink names reached, sorted and de-duplicated.
        returns: Returned expression names.
        flows: ``flow:<ORIGIN>-><SINK>`` tokens, for compatibility.
        traces: Full :class:`~syrth.trace.Trace` certificates.
        has_sql_string: A SQL keyword appears in a string literal.
        has_auth_decorator: A security decorator is present (auxiliary only).
        has_csrf_exempt: ``@csrf_exempt`` is present.
        call_sites: ``(canonical_sink, call_name, line, column)`` for each sink
            call, used for kill/amplifier bookkeeping and reporting.
        symbolic_origins: ``variable name -> sorted taint origins``. Origins are
            ``PARAM#<index>`` for parameters, which is what lets the
            interprocedural layer answer "which arguments actually reach this
            function's sinks".
        invocations: ``(callee, line, per-argument origins, per-argument
            keywords)`` for every call, used to build the call graph.
        returns_param_indices: Sorted parameter indices whose taint reaches the
            return value.
        sanitisers: Every sanitiser applied anywhere in the function, whether or
            not it suppressed a flow. Recorded separately from the traces
            because a successful kill produces no trace, and "this code uses
            ``shlex.quote``" is strong evidence about intent even when no
            finding survives.
    """

    name: str
    decorators: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    #: Containment guards in this function as ``(line, tested_names)``.
    #: ``syrth.containment`` recognises the shape; this records it so the scan
    #: layer can decide whether a sink is dominated by one without re-parsing.
    guards: list[tuple[int, frozenset[str], tuple[int, int] | None]] = field(default_factory=list)
    #: Identifiers read by each sink call's first argument, keyed by line. Used
    #: to decide whether a containment guard and a sink actually share state.
    sink_argument_names: dict[int, frozenset[str]] = field(default_factory=dict)
    #: True when every value this function returns is dominated by a
    #: containment guard, so the guard can reach a sink in the caller.
    guarded_returns: bool = False
    returns: list[str] = field(default_factory=list)
    flows: list[str] = field(default_factory=list)
    traces: list[Trace] = field(default_factory=list)
    has_sql_string: bool = False
    has_auth_decorator: bool = False
    has_csrf_exempt: bool = False
    lineno: int = 0
    end_lineno: int = 0
    arg_positions: list[tuple[int, str]] = field(default_factory=list)
    call_sites: list[tuple[str, str, int, int]] = field(default_factory=list)
    symbolic_origins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    invocations: list[tuple[str, int, tuple[tuple[str, ...], ...], tuple]] = field(
        default_factory=list
    )
    returns_param_indices: list[int] = field(default_factory=list)
    sanitisers: list[str] = field(default_factory=list)

    # ------------------------------------------------------------- helpers
    def sink_categories(self) -> list[str]:
        """Sorted unique sink categories present in this function."""
        cats = {spec.category for spec in SINK_SPECS.values() if spec.name in set(self.sinks)}
        return sorted(cats)

    def tainted_categories(self) -> list[str]:
        """Sorted unique categories reached by a confirmed taint flow."""
        return sorted({trace.category for trace in self.traces if trace.origins})

    def confirmed(self) -> list[Trace]:
        """Traces with at least one taint origin, i.e. confirmed flows."""
        return [trace for trace in self.traces if trace.origins]

    # ------------------------------------------------------- token sequence
    def to_token_sequence(self) -> list[str]:
        """Flatten into the normalised token sequence used for training.

        Token grammar::

            @decorator          security decorator
            def:<name>          function name (name hint normalised)
            arg:<name>          parameter, position preserved
            call:<name>         call as written (name hint normalised)
            sink:<canonical>    canonical sink name
            SCAT:<CAT>          sink category, one per distinct category
            ret:<name>          returned expression
            meta:no_auth        sinks present and no security decorator
            flow:<ORIGIN>-><SINK>        confirmed taint flow
            tainted:<SINK>      taint-confirmed canonical sink
            kill:<NAME>         sanitiser observed on a confirmed path
            amp:<NAME>          taint amplifier (sanitiser that creates a sink)

        Sink names and category tokens both come from
        :mod:`syrth.registry`, which is the only place they are defined, so the
        token stream and the numeric feature vector cannot disagree.
        """
        tokens: list[str] = []

        for dec in self.decorators:
            tokens.append(f"@{dec}")

        tokens.append(f"def:{self.name}")

        for arg in self.args:
            tokens.append(f"arg:{arg}")

        for call in self.calls:
            tokens.append(f"call:{call}")

        for sink in self.sinks:
            tokens.append(f"sink:{sink}")

        seen_cats: set[str] = set()
        for sink in self.sinks:
            spec = sink_spec_for(sink)
            if spec is not None and spec.scat_token not in seen_cats:
                seen_cats.add(spec.scat_token)
                tokens.append(spec.scat_token)

        if self.has_sql_string and "SQL_EXECUTE" not in self.sinks:
            tokens.append("sink:SQL_EXECUTE")
            tokens.append("SCAT:SQL")

        for ret in self.returns:
            tokens.append(f"ret:{ret}")

        if self.sinks and not self.has_auth_decorator:
            tokens.append("meta:no_auth")

        for flow in self.flows:
            tokens.append(flow)

        for flow in self.flows:
            _, _, sink = flow.partition("->")
            if sink:
                token = f"tainted:{sink}"
                if token not in tokens:
                    tokens.append(token)

        for kill in self._kill_names():
            token = f"kill:{kill}"
            if token not in tokens:
                tokens.append(token)

        for amp in self._amplifier_names():
            token = f"amp:{amp}"
            if token not in tokens:
                tokens.append(token)

        return tokens

    def _kill_names(self) -> list[str]:
        names: set[str] = set()
        for trace in self.traces:
            names.update(trace.kills)
        return sorted(names)

    def _amplifier_names(self) -> list[str]:
        return sorted(
            {trace.notes[0] for trace in self.traces
             if trace.notes and trace.notes[0].startswith("amp:")}
        )

    def name_hint_tokens(self) -> list[str]:
        """Auxiliary identifier-normalisation tokens.

        These are *advisory only*. They never reach the taint verdict; they are
        exposed separately so a downstream model can use them without being able
        to make the analyser non-rename-invariant.
        """
        hints: list[str] = []
        for arg in self.args:
            hints.append(f"nh:{normalise_token(arg)}")
        return hints


@dataclass
class FileTrace:
    """File-level trace: imports, frameworks and per-function traces.

    Attributes:
        path: Source path.
        imports: Imported module names.
        framework_tokens: Detected framework tokens.
        functions: Per-function traces.
        module_calls: Calls made at module scope. The previous release dropped
            these entirely, so a module-level ``os.system(user_input)`` was
            reported as a clean file.
        module_traces: Traces for sinks reached at module scope.
        bindings: Import bindings used to disambiguate bare call names.
        call_sites: ``(canonical_sink, call_name, line, column)`` for sinks
            reached at module scope.
        parse_errors: True when tree-sitter reported an ERROR/MISSING node.
    """

    path: str = ""
    imports: list[str] = field(default_factory=list)
    framework_tokens: list[str] = field(default_factory=list)
    functions: list[FunctionTrace] = field(default_factory=list)
    module_calls: list[str] = field(default_factory=list)
    module_traces: list[Trace] = field(default_factory=list)
    sanitisers: list[str] = field(default_factory=list)
    call_sites: list[tuple[str, str, int, int]] = field(default_factory=list)
    invocations: list[tuple[str, int, tuple[tuple[str, ...], ...], tuple]] = field(
        default_factory=list
    )
    parse_errors: bool = False
    bindings: Any = None

    def get_function(self, name: str) -> FunctionTrace | None:
        """Return the first function named ``name``, or ``None``."""
        for func in self.functions:
            if func.name == name:
                return func
        return None

    def get_function_sinks(self, name: str) -> list[str]:
        """Canonical sinks for a function, or an empty list if unknown."""
        func = self.get_function(name)
        return list(func.sinks) if func else []

    def get_function_flows(self, name: str) -> list[str]:
        """Taint-flow tokens for a function, or an empty list if unknown."""
        func = self.get_function(name)
        return list(func.flows) if func else []

    def all_traces(self) -> list[Trace]:
        """Every confirmed and pattern trace in the file, deterministically ordered."""
        traces: list[Trace] = list(self.module_traces)
        for func in self.functions:
            traces.extend(func.traces)
        return traces

    def module_level_flag(self) -> bool:
        """True when a sink was reached outside any function body."""
        return bool(self.module_traces)


class BaseParser(ABC):
    """Abstract multi-language parser built on tree-sitter.

    Attributes:
        language: Language tag, e.g. ``python``.
        language_code: Compiled tree-sitter language.
    """

    def __init__(self, language: str, language_code: tree_sitter.Language):
        self.language = language
        self.language_code = language_code
        self._parser = tree_sitter.Parser(language_code)

    # ------------------------------------------------------------- parsing
    @abstractmethod
    def parse(self, source_code: str, file_path: str = "") -> FileTrace:
        """Parse source and return a :class:`FileTrace`."""

    @abstractmethod
    def extract_functions(self, tree: tree_sitter.Tree, source_code: str) -> list[FunctionTrace]:
        """Extract per-function traces from a parsed tree."""

    @abstractmethod
    def extract_imports(self, tree: tree_sitter.Tree, source_code: str) -> list[str]:
        """Extract imported module names from a parsed tree."""

    @abstractmethod
    def detect_frameworks(self, imports: list[str]) -> list[str]:
        """Map import names to framework tokens."""

    # ------------------------------------------------------------ byte-safe
    def _parse_source(self, source_code: str) -> tuple[tree_sitter.Tree, bytes]:
        """Encode, parse, and return the tree together with the exact bytes.

        The encoded bytes are returned because every subsequent node lookup
        slices them. Slicing the decoded ``str`` instead is the bug this
        signature exists to make impossible.
        """
        raw = source_code.encode("utf-8", errors="replace")
        return self._parser.parse(raw), raw

    def _get_node_text(self, node: tree_sitter.Node, raw: bytes) -> str:
        """Decode a node's source text from the encoded buffer.

        Args:
            node: AST node.
            raw: The exact UTF-8 bytes handed to tree-sitter.

        Returns:
            Decoded node text.
        """
        return raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _node_line(self, node: tree_sitter.Node) -> int:
        """1-indexed line of a node."""
        return node.start_point[0] + 1

    def _node_column(self, node: tree_sitter.Node) -> int:
        """0-indexed column of a node."""
        return node.start_point[1]

    # -------------------------------------------------------- node helpers
    def _get_function_name(self, node: tree_sitter.Node, raw: bytes) -> str:
        """Extract a function name, handling the common language layouts."""
        for child in node.children:
            if child.type in ("identifier", "function_declarator", "type_identifier"):
                return self._get_node_text(child, raw)
        # C-style: declarator wraps the name
        for child in node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        return self._get_node_text(sub, raw)
        return "unknown"

    def _get_decorator_names(self, node: tree_sitter.Node, raw: bytes) -> list[str]:
        """Extract decorator names. Language-specific parsers override this."""
        decorators: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                for dec_child in child.children:
                    if dec_child.type in ("identifier", "attribute", "call"):
                        name = self._get_node_text(dec_child, raw)
                        if name:
                            decorators.append(name)
        return decorators

    def _get_argument_names(self, node: tree_sitter.Node, raw: bytes) -> list[str]:
        """Extract parameter names. Language-specific parsers override this."""
        args: list[str] = []
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type == "identifier":
                        args.append(self._get_node_text(param, raw))
        return args

    def _get_call_name(self, node: tree_sitter.Node, raw: bytes) -> str:
        """Resolve the callee of a call node to a dotted name."""
        for child in node.children:
            if child.type in ("identifier", "attribute", "field_expression"):
                return self._get_node_text(child, raw)
        return "unknown"

    def _is_sink(self, call_name: str) -> bool:
        """True when ``call_name`` resolves to a sink."""
        return canonical_sink(call_name) is not None

    def _get_sink_canonical(self, call_name: str) -> str | None:
        """Canonical sink name for a call, or ``None``."""
        return canonical_sink(call_name)


__all__ = [
    "BaseParser",
    "FileTrace",
    "FunctionTrace",
    "Token",
    "SECURITY_DECORATORS",
]
