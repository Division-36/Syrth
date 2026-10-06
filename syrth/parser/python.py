"""
SYRTH Python Parser
===================
Tree-sitter based Python front end with intraprocedural taint analysis.

What this module fixes relative to the previous release
------------------------------------------------------
*   **f-strings propagate.** ``f"...{x}..."`` is an ``interpolation`` child in
    tree-sitter's grammar; the previous version had no case for it and
    therefore missed the single most common injection idiom in modern Python.
*   **``.format()`` and ``%`` propagate.**
*   **Keyword arguments are analysed.** ``subprocess.run(args=cmd, shell=True)``
    and ``cursor.execute(query=q)`` were previously invisible.
*   **Taint is seeded from parameter position, not parameter name.** Every
    parameter is a source, so ``def f(name)`` and ``def f(user_id)`` behave
    identically. The previous version seeded taint only when a parameter name
    matched one of eight regexes, which made recall a function of a developer's
    naming choices.
*   **Sanitisers are modelled.** ``shlex.quote``, ``os.path.basename``,
    ``html.escape`` and friends kill the categories they actually protect.
*   **Parameterised queries are safe.** ``cursor.execute(sql, params)`` routes
    the second argument through a structural kill.
*   **Module-scope calls are analysed.** They were previously discarded
    entirely, so a module-level ``os.system(user_input)`` was reported clean.
*   **Node text is decoded from bytes.** See :mod:`syrth.parser.base`.

Complexity
----------
Intraprocedural and flow-insensitive within a function: the analysis over-
approximates both branches of a conditional, which is sound for finding flows
and documented as such. Interprocedural propagation lives in
:mod:`syrth.interproc`.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

import tree_sitter
import tree_sitter_python

from ..containment import containment_guards
from ..registry import (
    CATEGORY_CWE,
    FRAMEWORK_MAP,
    SECURITY_DECORATORS,
    SQL_KEYWORDS,
    Bindings,
    Category,
    Origin,
    amplifier_for,
    canonical_sink,
    kill_for,
    sink_spec_for,
)
from ..taint.engine import (
    GUARD_REACHABLE_CATEGORIES,
    GUARD_STRENGTH,
    TaintEngine,
    TaintValue,
)
from ..trace import (
    DETECTOR_AMPLIFIER,
    DETECTOR_TAINT,
    EDGE_ARG,
    EDGE_ASSIGN,
    EDGE_ATTR,
    EDGE_ATTR_ASSIGN,
    EDGE_AUG_ASSIGN,
    EDGE_BRANCH,
    EDGE_CALL,
    EDGE_COMPREHENSION,
    EDGE_CONCAT,
    EDGE_FSTRING,
    EDGE_INDEX,
    EDGE_ITER,
    EDGE_PARAM,
    EDGE_PERCENT,
    EDGE_RETURN,
    EDGE_WITH,
    STEP_KIND_GUARD,
    STEP_KIND_PROPAGATE,
    STEP_KIND_SANITIZE,
    STEP_KIND_SINK,
    STEP_KIND_SOURCE,
    Trace,
    TraceStep,
)
from .base import BaseParser, FileTrace, FunctionTrace, Token
from .guards import body_terminates, classify_regex_guard, classify_test, unwrap_not

#: Confidence assigned to a confirmed source-to-sink flow with no mitigation.
BASE_TAINT_CONFIDENCE = 0.90
#: Confidence multiplier when a partial mitigation was observed on the path.
PARTIAL_MITIGATION_FACTOR = 0.65
#: Confidence assigned to an amplifier finding (no taint needed).
AMPLIFIER_CONFIDENCE = 0.60

#: Tree-sitter node types that are literal at runtime. Interpolated strings are
#: excluded deliberately: ``"<b>%s</b>" % value`` is not a constant even though
#: the format text is.
_CONSTANT_NODE_TYPES = frozenset({
    "string", "integer", "float", "true", "false", "none",
    "string_literal", "integer_literal", "float_literal",
})
#: Confidence penalty per additional propagation step, to reflect that longer
#: chains are harder to trigger. Bounded below by MIN_TAINT_CONFIDENCE.
STEP_DECAY = 0.01
MIN_TAINT_CONFIDENCE = 0.55

#: Maximum expression nesting depth the analyser will descend into.
#:
#: tree-sitter builds a left-leaning tree for operator chains, so one binary
#: expression recurses once per operator. Beyond this budget the remaining
#: operands are treated as unknown and the file is reported as over-budget
#: rather than crashing. The limit is far above any human-written expression and
#: far below the interpreter stack limit for this call depth.
MAX_EXPRESSION_DEPTH = 150

#: Statement nodes that introduce a new lexical scope for bindings.
_SCOPE_NODES = frozenset(
    {
        "function_definition",
        "async_function_definition",
        "lambda",
        "class_definition",
        "list_comprehension",
        "set_comprehension",
        "dictionary_comprehension",
        "generator_expression",
    }
)

#: Expression nodes whose evaluation yields no attacker-controlled data.
_LITERAL_NODES = frozenset(
    {
        "integer", "float", "true", "false", "none", "ellipsis",
        "string", "concatenated_string", "raw_string",
    }
)


@dataclass
class _CallArg:
    """One resolved argument of a call, with its position."""

    index: int | None        # positional index, None for keyword/splat
    keyword: str | None      # keyword name, None for positional/splat
    value: TaintValue
    node: tree_sitter.Node
    is_splat: bool = False


class _GuardFunctionVisitor(ast.NodeVisitor):
    """Collect function line ranges so a guard can be attributed to one."""

    def __init__(self) -> None:
        self.ranges: list[tuple[int, int, str]] = []

    def _record(self, node: ast.AST, name: str) -> None:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", None) or start
        self.ranges.append((start, end, name))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._record(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._record(node, node.name)


def _attach_containment_guards(
    functions: list[FunctionTrace], source_code: str,
    caller_truncated: bool = False,
) -> None:
    """Record each function's containment guards, keyed by line.

    Failure is silent and total: no guards are attached, so the analyser behaves
    exactly as it did before this feature existed. A partial result would be worse
    than none, because a guard attributed to the wrong function suppresses
    findings in the wrong place.

    ``caller_truncated`` is the tree-sitter parse's own depth signal. When the
    tree was already truncated the analysis is incomplete by design, and adding a
    second, independently budgeted pass over a hostile input is how a bounded
    analyser becomes an unbounded one. Two adversarial regressions came from
    exactly that: deeply nested expressions are cheap to skip and expensive to
    walk, so they are skipped.
    """
    if caller_truncated:
        return
    try:
        module = ast.parse(source_code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return
    guards = containment_guards(module)
    if not guards:
        return
    visitor = _GuardFunctionVisitor()
    visitor.visit(module)
    for function in functions:
        for start, end, name in visitor.ranges:
            if name == function.name and start == function.lineno:
                function.guards = [
                    (guard.line, guard.names, guard.scope)
                    for guard in guards
                    if start <= guard.line <= end
                ]
                function.sink_argument_names = _sink_argument_names(module, start, end)
                function.guarded_returns = _guarded_returns(module, start, end, guards)
                break



def _guarded_returns(
    module: ast.Module, start: int, end: int, guards
) -> bool:
    """Whether every value this function returns is dominated by a guard.

    This is what lets a guard reach a sink in a *different* function. Starlette's
    ``lookup_path`` checks containment and then returns the path; its caller feeds
    that path to ``FileResponse``. The guard is real, it just sits one call away
    from the sink.

    The condition is deliberately "every return", not "some return". One guarded
    return alongside one unguarded early return means the caller can still receive
    an unvalidated value, and propagating the guard on the strength of the guarded
    branch would invent a safety property the code does not have. A function with
    no explicit return, or one whose returns happen before any guard, is not
    guarded either -- absence of evidence is not evidence.
    """
    body_guards = [g for g in guards if start <= g.line <= end]
    returns = [
        n for n in ast.walk(module)
        if isinstance(n, ast.Return) and start <= n.lineno <= end
    ]
    if not returns or not body_guards:
        return False
    for node in returns:
        if node.value is None:
            continue
        if any(g.line > node.lineno for g in body_guards):
            # A return before every guard: the caller can get an unvalidated value.
            return False
        names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
        if not names:
            # A constant return hands back nothing untrusted. Starlette's
            # ``return "", None`` on the rejection path is exactly this, and
            # treating it as unproven would make every guarded helper look
            # unguarded.
            continue
        # Every name the return reads has to be covered, not merely one of them.
        # An intersection is far too weak: a guard over ``(full, directory)`` would
        # "cover" ``return os.path.join(directory, path)`` because ``directory``
        # happens to appear in both, while ``path`` was never constrained at all.
        if not any(g.line < node.lineno and names <= g.names for g in body_guards):
            return False
    return True


def _sink_argument_names(
    module: ast.Module, start: int, end: int
) -> dict[int, frozenset[str]]:
    """Identifiers read by the first argument of each call, keyed by line.

    Restricted to a function's line range. The scan layer uses this to check that
    a containment guard and a sink concern the same variable, which is what stops
    "validate one path, open another" from being treated as guarded.
    """
    out: dict[int, frozenset[str]] = {}
    for node in ast.walk(module):
        if not isinstance(node, ast.Call) or not (start <= node.lineno <= end):
            continue
        argument = node.args[0] if node.args else None
        if argument is None:
            continue
        names = {n.id for n in ast.walk(argument) if isinstance(n, ast.Name)}
        # A direct nested call names its callee in the source of the argument, so
        # ``FileResponse(lookup_path(root, path))`` has to expose ``lookup_path``.
        # Without this the interprocedural check compared a callee name against
        # argument *variables* -- two different namespaces -- and never matched.
        if isinstance(argument, ast.Call):
            callee = argument.func
            if isinstance(callee, ast.Name):
                names.add(callee.id)
            elif isinstance(callee, ast.Attribute):
                names.add(callee.attr)
        if names:
            out.setdefault(node.lineno, names)
    return out


class PythonParser(BaseParser):
    """Python front end producing :class:`FileTrace` with taint certificates."""

    def __init__(self) -> None:
        super().__init__(
            language="python",
            language_code=tree_sitter.Language(tree_sitter_python.language()),
        )
        self._bindings = Bindings()
        self._taint_engine = TaintEngine()
        self._values: dict[str, TaintValue] = {}
        self._current: FunctionTrace | None = None
        self._file: FileTrace = FileTrace()
        self._depth = 0
        self._depth_exceeded = False

    # =================================================================== API
    def parse(self, source_code: str, file_path: str = "") -> FileTrace:
        """Parse Python source and extract security-relevant traces.

        Args:
            source_code: Python source text.
            file_path: Optional path recorded on the result and its traces.

        Returns:
            A :class:`FileTrace`. Tree-sitter is fault tolerant, so malformed
            source still yields a trace object; ``parse_errors`` reports whether
            the parse was clean.
        """
        tree, raw = self._parse_source(source_code)
        self._raw = raw
        self._file = FileTrace(path=file_path)
        self._file.parse_errors = _has_error_node(tree.root_node)
        self._bindings = Bindings()
        self._depth = 0
        self._depth_exceeded = False

        self._collect_imports(tree.root_node, raw, self._file.imports)
        self._file.imports = sorted(set(self._file.imports))
        self._file.framework_tokens = self.detect_frameworks(self._file.imports)
        self._file.bindings = self._bindings

        functions: list[FunctionTrace] = []
        self._find_functions(tree.root_node, raw, functions)
        self._file.functions = functions
        if functions:
            # Attaching guards here rather than in ``extract_functions`` matters:
            # this ``parse`` does not call that method, so the hook had to go where
            # the function list is actually built.
            _attach_containment_guards(
                functions, source_code, caller_truncated=self._depth_exceeded
            )

        # Module scope: anything not inside a function body.
        self._analyse_module_scope(tree.root_node, raw)

        if self._depth_exceeded:
            # Say so. A truncated analysis that looks identical to a complete one
            # is how a tool under-reports without anyone noticing.
            self._file.parse_errors = True

        self._values = {}
        self._current = None
        return self._file

    def extract_functions(self, tree: tree_sitter.Tree, source_code: str) -> list[FunctionTrace]:
        """Extract function traces from a parsed tree.

        Containment guards are attached here, per function, because this is the
        only place that still has the source text and the function line ranges.
        They are recognised with :mod:`ast` rather than tree-sitter: the shape is
        a statement-level pattern over a small primitive set, and the standard
        library parses it without any of this project's tree-sitter bindings.
        A file ``ast`` cannot parse yields no guards, which degrades to the
        previous behaviour rather than failing the scan.
        """
        raw = source_code.encode("utf-8", errors="replace")
        functions: list[FunctionTrace] = []
        self._find_functions(tree.root_node, raw, functions)
        if functions:
            _attach_containment_guards(
                functions, source_code, caller_truncated=self._depth_exceeded
            )
        return functions

    def extract_imports(self, tree: tree_sitter.Tree, source_code: str) -> list[str]:
        """Extract imported module names."""
        raw = source_code.encode("utf-8", errors="replace")
        imports: list[str] = []
        self._collect_imports(tree.root_node, raw, imports)
        return sorted(set(imports))
    def detect_frameworks(self, imports: list[str]) -> list[str]:
        """Map import names to framework tokens, deterministically."""
        found: list[str] = []
        for imp in sorted(imports):
            lower = imp.lower()
            for key, token in FRAMEWORK_MAP:
                if key in lower:
                    if token not in found:
                        found.append(token)
                    break
        return sorted(found)

    # ============================================================== imports
    def _collect_imports(
        self, node: tree_sitter.Node, raw: bytes, out: list[str]
    ) -> None:
        """Record ``import`` targets and build import bindings.

        Bindings are what let the sink resolver distinguish ``from pickle import
        loads`` (dangerous) from ``from json import loads`` (safe) without
        guessing.
        """
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    out.append(self._get_node_text(child, raw))
                elif child.type == "aliased_import":
                    for sub in child.children:
                        if sub.type == "dotted_name":
                            out.append(self._get_node_text(sub, raw))
            return
        if node.type == "import_from_statement":
            module: str | None = None
            for child in node.children:
                if module is None and child.type == "dotted_name":
                    module = self._get_node_text(child, raw)
                    out.append(module)
                elif child.type == "aliased_import":
                    parts = [
                        self._get_node_text(sub, raw)
                        for sub in child.children
                        if sub.type == "dotted_name"
                    ]
                    if module and parts:
                        self._bindings.bind_import(module, parts[0])
                elif child.type == "dotted_name" and module:
                    self._bindings.bind_import(module, self._get_node_text(child, raw))
            return
        # Iterative walk, not recursion. tree-sitter's tree depth grows with
        # expression length, so a long operator chain used to raise
        # RecursionError here before any taint analysis happened at all.
        pending = list(node.children)
        head = 0
        while head < len(pending):
            current = pending[head]
            head += 1
            if current.type == "import_statement":
                for child in current.children:
                    if child.type == "dotted_name":
                        out.append(self._get_node_text(child, raw))
                    elif child.type == "aliased_import":
                        for sub in child.children:
                            if sub.type == "dotted_name":
                                out.append(self._get_node_text(sub, raw))
                continue
            if current.type == "import_from_statement":
                module: str | None = None
                for child in current.children:
                    if module is None and child.type == "dotted_name":
                        module = self._get_node_text(child, raw)
                        out.append(module)
                    elif child.type == "aliased_import":
                        parts = [
                            self._get_node_text(sub, raw)
                            for sub in child.children
                            if sub.type == "dotted_name"
                        ]
                        if module and parts:
                            self._bindings.bind_import(module, parts[0])
                    elif child.type == "dotted_name" and module:
                        self._bindings.bind_import(module, self._get_node_text(child, raw))
                continue
            pending.extend(current.children)

    # ============================================================= functions
    def _find_functions(
        self, node: tree_sitter.Node, raw: bytes, out: list[FunctionTrace]
    ) -> None:
        """Collect every function definition, including nested ones.

        The traversal is iterative. Recursing over ``node.children`` overflowed
        the interpreter stack on a deep expression tree -- a 1000-term operator
        chain is 1000 levels deep in tree-sitter -- and raised
        :class:`RecursionError` out of ``scan_source``.
        """
        # Iterative walk in source order. A stack would reverse sibling order and
        # change which function lands at ``functions[0]``, which is an observable
        # part of the contract (``trace.functions`` is source-ordered).
        pending = list(node.children)
        head = 0
        while head < len(pending):
            child = pending[head]
            head += 1
            if child.type == "decorated_definition":
                for sub in child.children:
                    if sub.type in ("function_definition", "async_function_definition"):
                        out.append(self._analyse_function(sub, raw, child))
                        # Descend into the analysed body for nested functions.
                        # Only that body -- re-queueing the wrapper would
                        # analyse the same definition a second time.
                        pending.extend(sub.children)
                    elif sub.type != "decorator":
                        pending.append(sub)
            elif child.type in ("function_definition", "async_function_definition"):
                out.append(self._analyse_function(child, raw, None))
                # Nested definitions inside this body are separate functions and
                # must still be analysed; the previous release stopped at the
                # outer body and so never saw them.
                pending.extend(child.children)
            else:
                pending.extend(child.children)

    def _analyse_function(
        self,
        node: tree_sitter.Node,
        raw: bytes,
        decorated: tree_sitter.Node | None,
    ) -> FunctionTrace:
        """Build a :class:`FunctionTrace` and run the intraprocedural analysis."""
        name = self._get_function_name(node, raw)
        decorators = self._get_decorator_names(decorated or node, raw)
        args, positions = self._resolve_parameters(node, raw)

        trace = FunctionTrace(
            name=name,
            decorators=decorators,
            args=args,
            arg_positions=positions,
            lineno=self._node_line(node),
            has_auth_decorator=any(d in SECURITY_DECORATORS for d in decorators),
            has_csrf_exempt="csrf_exempt" in decorators,
        )

        # Every parameter is a source, whatever it is called. This is the
        # rename-invariance guarantee: parameter spelling is never consulted.
        # Parameters are seeded with a *symbolic* origin carrying their position
        # (``PARAM#<index>``) so that the interprocedural layer can tell which
        # arguments of a call actually reach a sink.
        previous_values = self._values
        previous_current = self._current
        self._values = {}
        self._current = trace

        for index, arg_name in positions:
            if arg_name in ("self", "cls"):
                # ``self``/``cls`` are not externally controlled, but the object
                # they reference carries state across the whole class.
                self._values[arg_name] = TaintValue(
                    origins=frozenset({Origin.GLOBAL}),
                    path=(
                        TraceStep(self._node_line(node), 0, STEP_KIND_SOURCE, EDGE_PARAM,
                                  arg_name),
                    ),
                )
                continue
            self._values[arg_name] = TaintValue(
                origins=frozenset({param_origin(index)}),
                path=(
                    TraceStep(self._node_line(node), 0, STEP_KIND_SOURCE, EDGE_PARAM,
                              arg_name),
                ),
            )

        end_line = self._node_line(node)
        for child in node.children:
            if child.type == "block":
                for stmt in child.children:
                    self._statement(stmt, raw)
                end_line = max(end_line, self._node_line(child))

        trace.end_lineno = end_line
        self._finalise_trace(trace)
        self._values = previous_values
        self._current = previous_current
        return trace
    def _resolve_parameters(
        self, node: tree_sitter.Node, raw: bytes
    ) -> tuple[list[str], list[tuple[int, str]]]:
        """Return declared parameter names and their positional indices.

        ``*args`` and ``**kwargs`` are recorded with the index they occupy so a
        sink schema can still address them, but they are additionally marked by
        the ``*``/``**`` prefix being retained in :attr:`FunctionTrace.arg_positions`.
        """
        names: list[str] = []
        positions: list[tuple[int, str]] = []
        index = 0
        for child in node.children:
            if child.type != "parameters":
                continue
            for param in child.children:
                if param.type in ("comment",):
                    continue
                if param.type == "list_splat_pattern":
                    names.append("*" + self._first_identifier(param, raw))
                    positions.append((index, "*" + self._first_identifier(param, raw)))
                    index += 1
                    continue
                if param.type == "dictionary_splat_pattern":
                    names.append("**" + self._first_identifier(param, raw))
                    positions.append((index, "**" + self._first_identifier(param, raw)))
                    index += 1
                    continue
                name = self._first_identifier(param, raw)
                if not name:
                    continue
                names.append(name)
                positions.append((index, name))
                index += 1
        return names, positions

    def _first_identifier(self, node: tree_sitter.Node, raw: bytes) -> str:
        """First identifier text inside a node, or an empty string."""
        if node.type in ("identifier", "typed_parameter", "default_parameter",
                         "typed_default_parameter"):
            return self._get_node_text(node, raw).split(":")[0].split("=")[0].strip()
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child, raw)
        return ""

    # =========================================================== module scope
    def _analyse_module_scope(self, root: tree_sitter.Node, raw: bytes) -> None:
        """Analyse statements that are not inside a function body."""
        self._current = None
        self._values = {}
        self._walk_top_level(root, raw)

    def _walk_top_level(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Recurse into module scope, stopping at any function or class body."""
        for child in node.children:
            if child.type in ("function_definition", "async_function_definition",
                              "decorated_definition", "class_definition",
                              "lambda"):
                # Class bodies execute at import time; their contents are
                # analysed as module scope because decorators and default
                # arguments are evaluated eagerly.
                if child.type == "decorated_definition":
                    for sub in child.children:
                        if sub.type == "decorator":
                            self._expression(sub, raw)
                    continue
                if child.type == "class_definition":
                    self._class_scope(child, raw)
                continue
            self._statement(child, raw)

    def _class_scope(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse a class body: decorators, bases and defaults run eagerly."""
        for child in node.children:
            if child.type == "block":
                for stmt in child.children:
                    if stmt.type in ("function_definition", "async_function_definition"):
                        # Default values and decorators still execute.
                        for sub in stmt.children:
                            if sub.type == "parameters":
                                for param in sub.children:
                                    if param.type in ("default_parameter",
                                                      "typed_default_parameter"):
                                        self._expression(param.children[-1], raw)
                        continue
                    self._statement(stmt, raw)
            else:
                self._expression(child, raw)

    # ============================================================ statements
    def _statement(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse one statement in the current scope."""
        kind = node.type
        if kind == "expression_statement":
            # tree-sitter wraps assignments, augmented assignments and del
            # statements in an expression_statement, so the inner node has to be
            # unwrapped before dispatching.
            children = [c for c in node.children if c.type != "comment"]
            if not children:
                return
            inner = children[0]
            if inner.type == "augmented_assignment":
                self._augmented_assignment(inner, raw)
            elif inner.type == "assignment":
                self._assignment(inner, raw)
            elif inner.type == "named_expression":
                self._expression(inner, raw)
            else:
                self._expression(inner, raw)
        elif kind in ("assignment", "short_variable_declaration"):
            self._assignment(node, raw)
        elif kind == "augmented_assignment":
            self._augmented_assignment(node, raw)
        elif kind == "named_expression":
            self._expression(node, raw)
        elif kind == "return_statement":
            self._return(node, raw)
        elif kind == "if_statement":
            self._branch(node, raw)
        elif kind in ("for_statement", "for_in_clause", "async_for_statement"):
            self._for_statement(node, raw)
        elif kind == "while_statement":
            self._branch(node, raw)
        elif kind == "with_statement":
            self._with_statement(node, raw)
        elif kind == "try_statement":
            self._try_statement(node, raw)
        elif kind == "match_statement":
            self._match_statement(node, raw)
        elif kind in ("import_statement", "import_from_statement"):
            self._collect_imports(node, raw, [])
        elif kind == "class_definition":
            self._class_scope(node, raw)
        elif kind == "raise_statement":
            for child in node.children:
                if child.type != "comment":
                    self._expression(child, raw)
        elif kind == "global_statement":
            for child in node.children:
                if child.type == "identifier":
                    self._values.setdefault(
                        self._get_node_text(child, raw),
                        TaintValue(origins=frozenset({Origin.GLOBAL})),
                    )
        elif kind in ("delete_statement", "pass_statement", "break_statement",
                      "continue_statement", "assert_statement", "comment"):
            return
        elif kind in ("function_definition", "async_function_definition",
                      "decorated_definition", "lambda"):
            # Function bodies execute later; their definitions are recorded by
            # _find_functions. Defaults and decorators execute now.
            self._function_header_effects(node, raw)
        else:
            for child in node.children:
                self._expression(child, raw)

    def _function_header_effects(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Evaluate decorators and default arguments, which run eagerly."""
        if node.type == "decorated_definition":
            for child in node.children:
                if child.type == "decorator":
                    self._expression(child, raw)
                else:
                    self._function_header_effects(child, raw)
            return
        if node.type == "lambda":
            for child in node.children:
                if child.type == "lambda_parameters":
                    for param in child.children:
                        if param.type in ("default_parameter", "typed_default_parameter"):
                            self._expression(param.children[-1], raw)
            return
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type in ("default_parameter", "typed_default_parameter"):
                        self._expression(param.children[-1], raw)

    def _assignment(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Handle ``target = value`` for every target shape.

        Covers the four tree-sitter shapes that matter: a plain target, a
        ``pattern_list`` target with a parallel ``expression_list`` right-hand
        side, an attribute target (``self.x``) and a subscript target.
        """
        children = [c for c in node.children if c.type != "comment"]
        if len(children) < 2:
            return
        value_node = children[-1]
        targets = children[:-1]

        # ``pattern_list`` + ``expression_list`` is a parallel assignment; pair
        # the elements up positionally.
        pattern_target = next((t for t in targets if t.type == "pattern_list"), None)
        if pattern_target is not None and value_node.type == "expression_list":
            values = [c for c in value_node.children if c.type != ","]
            targets_in_pattern = [c for c in pattern_target.children if c.type != ","]
            for target, value in zip(targets_in_pattern, values, strict=False):
                self._bind_target(target, self._expression(value, raw), EDGE_ASSIGN, raw)
            return

        value = self._expression(value_node, raw)
        for target in targets:
            self._bind_target(target, value, EDGE_ASSIGN, raw)

    def _augmented_assignment(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Handle ``target op= value``.

        The previous implementation lost taint here entirely, so
        ``msg += request.GET['x']`` produced no flow.
        """
        children = [c for c in node.children if c.type not in ("comment",)]
        if len(children) < 3:
            return
        target = children[0]
        operator = children[1]
        value_node = children[2]
        right = self._expression(value_node, raw)
        edge = EDGE_ASSIGN
        if operator.type == "binary_operator":
            op = self._get_node_text(operator, raw).strip()
            if op == "+":
                edge = EDGE_CONCAT
            elif op == "%":
                edge = EDGE_PERCENT
        current = self._read_target(target, raw)
        combined = self._merge(current, right, self._step(node, edge))
        self._bind_target(target, combined, EDGE_AUG_ASSIGN, raw)

    def _bind_target(
        self, target: tree_sitter.Node, value: TaintValue, edge: str, raw: bytes
    ) -> None:
        """Store ``value`` under every name bound by ``target``.

        Handles identifiers, ``self`` attributes, subscripts, tuples/lists and
        parenthesised targets. The previous implementation handled only bare
        identifiers, so ``self.query = request.GET['q']`` lost its taint.
        """
        kind = target.type
        if kind in ("identifier", "as_pattern_target"):
            name = self._get_node_text(target, raw)
            self._values[name] = value
        elif kind == "attribute":
            name = self._resolve_name(target, raw)
            head, _, attr = name.partition(".")
            step = self._step(target, edge or EDGE_ATTR_ASSIGN, name)
            base = self._values.get(head)
            if base is None:
                # ``self.x = tainted`` marks the owning object as globally
                # reachable so a later ``self.x`` read propagates.
                self._values[head] = TaintValue(
                    origins=value.origins or frozenset({Origin.GLOBAL}),
                    path=value.path + (step,),
                )
                if attr:
                    self._values[name] = value
            else:
                self._values[name] = value
        elif kind == "subscript":
            base = self._resolve_name(target, raw)
            if base:
                step = self._step(target, edge or EDGE_INDEX)
                self._values[base] = self._merge(self._values.get(base, TaintValue()),
                                                 value, step)
        elif kind in ("pattern_list", "tuple", "list", "parenthesized_expression"):
            names = [c for c in target.children if c.type != ","]
            for child in names:
                self._bind_target(child, value, edge, raw)
        elif kind == "starred_pattern":
            names = [c for c in target.children if c.type not in (",", "starred_pattern")]
            for child in names:
                self._bind_target(child, value, edge, raw)
        else:
            name = self._resolve_name(target, raw)
            if name:
                self._values[name] = value

    def _read_target(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Read the current value bound to an assignment target."""
        if node.type == "identifier":
            return self._values.get(self._get_node_text(node, raw), TaintValue())
        if node.type == "attribute":
            return self._resolve_value(node, raw)
        if node.type == "subscript":
            base = self._resolve_name(node, raw)
            if base:
                return self._values.get(base, TaintValue())
        return TaintValue()

    def _return(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse the returned expression, including returned calls."""
        children = [c for c in node.children if c.type != "comment"]
        if not children:
            return
        value = self._expression(children[-1], raw)
        name = self._resolve_name(children[-1], raw)
        if self._current is not None:
            self._current.returns.append(name or "expr")
            self._values["__return__"] = self._merge(
                self._values.get("__return__", TaintValue()), value,
                self._step(node, EDGE_RETURN),
            )

    def _branch(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse a conditional.

        Every non-block child is evaluated: the condition, and the condition of
        each ``elif``. Evaluating only the first child would silently skip the
        condition, because tree-sitter emits the ``if`` keyword as a child.
        Both branches are then analysed and their taint merged, which
        over-approximates reachability. That is sound for finding flows and is
        the documented trade-off.
        """
        for child in node.children:
            if child.type == "block":
                self._block(child, raw)
            elif child.type in ("else_clause", "elif_clause"):
                self._statement(child, raw)
            elif child.type in ("comment", "if", "elif", "else"):
                continue
            else:
                self._expression(child, raw)
        # A guard constrains a tainted value without sanitising it. This is
        # graded evidence, not a proof: no guard ever clears ``origins``, and a
        # guarded flow stays in the trace so it can still be reviewed.
        if node.type == "if_statement":
            self._apply_guards(node, raw)

    def _apply_guards(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Record guard strength for values constrained by an ``if`` statement.

        Only a *terminating* guard constrains the code that follows it, because
        only then is the fall-through path known to hold the safe values. A
        guard that does not terminate is recorded too, but as weaker evidence,
        since the value is also still live on the branch that was taken.
        """
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            return

        classified = classify_test(condition, raw)
        regex_guard = False
        if classified is None:
            # ``if not re.match(r"^[a-z0-9_]+$", name): return`` -- an anchored
            # charset validation. It rules out path traversal, but not command
            # injection or XSS, so it constrains FILE only.
            regex_name = classify_regex_guard(unwrap_not(condition), raw)
            if regex_name is None:
                return
            classified = ("equality", regex_name)
            regex_guard = True
        kind, name = classified
        terminates = body_terminates(consequence, raw)

        current = self._values.get(name)
        if current is None or not current.origins:
            return

        guards = current.guards | {kind if terminates else f"weak_{kind}"}
        # A terminating guard constrains every category whose danger depends on
        # the value's content; a non-terminating one is weaker still. A charset
        # guard is narrower: it only removes path separators, so it speaks to
        # FILE and nothing else.
        if regex_guard:
            categories = frozenset({Category.FILE})
        else:
            categories = GUARD_REACHABLE_CATEGORIES if terminates else frozenset()
        # The marker step is what actually carries the guard downstream: every
        # propagation path copies ``path``, so the strength reaches the sink
        # even through expressions that rebuild the value from scratch.
        marker = TraceStep(
            self._node_line(node),
            self._node_column(node),
            STEP_KIND_GUARD,
            kind if terminates else f"weak_{kind}",
            name,
        )
        self._values[name] = TaintValue(
            origins=current.origins,
            neutralised=current.neutralised,
            partial=current.partial | categories,
            path=current.path + (marker,),
            kills=current.kills,
            constant=current.constant,
            guards=guards,
        )

    def _for_statement(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse ``for`` and ``async for``.

        tree-sitter lays the statement out positionally as
        ``[for, <target>, in, <iterable>, :, <block>]``, so the target and the
        iterable are read by position. Matching them by node *type* is wrong
        because both are usually bare identifiers.
        """
        if node.type == "for_in_clause":
            self._bind_for_clause(node, raw)
            return
        children = [c for c in node.children if c.type != "comment"]
        if len(children) >= 3 and children[0].type in ("for", "async"):
            target, iterable = _for_clause_parts(node)
            if target is not None:
                self._bind_target(
                    target,
                    self._expression(iterable, raw) if iterable is not None else TaintValue(),
                    EDGE_ITER,
                    raw,
                )
        for child in node.children:
            if child.type == "block":
                self._block(child, raw)

    def _bind_for_clause(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Bind a comprehension / ``for_in_clause`` loop variable."""
        target, iterable = _for_clause_parts(node)
        if target is None:
            return
        value = self._expression(iterable, raw) if iterable is not None else TaintValue()
        self._bind_target(target, value, EDGE_ITER, raw)

    def _with_statement(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse ``with`` items, propagating taint into ``as`` targets.

        tree-sitter wraps the whole item in an ``as_pattern`` whose children are
        ``[<context expression>, "as", <as_pattern_target>]``.
        """
        for child in node.children:
            if child.type == "with_clause":
                for item in child.children:
                    if item.type != "with_item":
                        continue
                    self._bind_with_item(item, raw)
            elif child.type == "block":
                self._block(child, raw)

    def _bind_with_item(self, item: tree_sitter.Node, raw: bytes) -> None:
        """Bind the ``as`` targets of one ``with`` item."""
        parts = [p for p in item.children if p.type != "comment"]
        if not parts:
            return
        holder = parts[0]
        if holder.type in ("as_pattern", "as_pattern_target"):
            context = holder.children[0] if holder.children else None
            targets = [
                p for p in holder.children
                if p.type in ("as_pattern_target", "identifier", "attribute")
            ]
        else:
            context = holder
            targets = [p for p in parts[1:] if p.type not in ("as", ",")]
        if context is None:
            return
        value = self._expression(context, raw)
        for target in targets:
            self._bind_target(target, value, EDGE_WITH, raw)

    def _try_statement(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse the try body, every handler, ``else`` and ``finally``."""
        for child in node.children:
            if child.type == "block":
                self._block(child, raw)
            elif child.type in ("except_clause", "finally_clause"):
                for sub in child.children:
                    if sub.type == "block":
                        self._block(sub, raw)
                    else:
                        self._expression(sub, raw)

    def _match_statement(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse ``match`` subjects and case bodies."""
        for child in node.children:
            if child.type == "match_block":
                for case in child.children:
                    if case.type == "case_clause":
                        for sub in case.children:
                            self._expression(sub, raw)
            else:
                self._expression(child, raw)

    def _block(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Analyse every statement in a block."""
        for child in node.children:
            self._statement(child, raw)

    # =========================================================== expressions
    def _expression(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Evaluate an expression, returning its :class:`TaintValue`."""
        kind = node.type

        if kind == "identifier":
            name = self._get_node_text(node, raw)
            return self._values.get(name, TaintValue())

        if kind == "attribute":
            return self._resolve_value(node, raw)

        if kind == "subscript":
            return self._resolve_subscript(node, raw)

        if kind == "call":
            return self._call(node, raw)

        if kind in ("string", "raw_string"):
            return self._string_value(node, raw)

        if kind == "concatenated_string":
            merged = TaintValue()
            step = self._step(node, EDGE_CONCAT)
            for child in node.children:
                merged = self._merge(merged, self._string_value(child, raw), step)
            return merged

        if kind == "binary_operator":
            return self._binary(node, raw)

        if kind in ("boolean_operator", "comparison_operator"):
            merged = TaintValue()
            step = self._step(node, EDGE_BRANCH)
            for child in node.children:
                merged = self._merge(merged, self._expression(child, raw), step)
            return merged

        if kind in ("conditional_expression", "parenthesized_expression",
                    "as_expression"):
            merged = TaintValue()
            step = self._step(node, EDGE_BRANCH)
            for child in node.children:
                merged = self._merge(merged, self._expression(child, raw), step)
            return merged

        if kind in ("not_operator", "unary_operator", "await", "yield"):
            merged = TaintValue()
            for child in node.children:
                merged = self._merge(merged, self._expression(child, raw),
                                     self._step(node, EDGE_CALL))
            return merged

        if kind in ("list", "set", "tuple"):
            merged = TaintValue()
            step = self._step(node, EDGE_INDEX)
            for child in node.children:
                if child.type == ",":
                    continue
                merged = self._merge(merged, self._expression(child, raw), step)
            return merged

        if kind == "dictionary":
            merged = TaintValue()
            step = self._step(node, EDGE_INDEX)
            for child in node.children:
                if child.type in ("pair",):
                    for sub in child.children:
                        merged = self._merge(merged, self._expression(sub, raw), step)
                elif child.type not in (",", "comment"):
                    merged = self._merge(merged, self._expression(child, raw), step)
            return merged

        if kind in ("list_comprehension", "set_comprehension", "generator_expression",
                    "dictionary_comprehension"):
            return self._comprehension(node, raw)

        if kind == "lambda":
            return self._lambda(node, raw)

        if kind == "named_expression":
            # Walrus operator: ``(x := expr)``.
            children = [c for c in node.children if c.type not in ("comment", "=")]
            if len(children) >= 2:
                value = self._expression(children[-1], raw)
                self._bind_target(children[0], value, EDGE_ASSIGN, raw)
                return value
            return TaintValue()

        if kind in _LITERAL_NODES:
            return TaintValue()

        if kind in ("integer", "float", "true", "false", "none", "comment", "type"):
            return TaintValue()

        merged = TaintValue()
        step = self._step(node, EDGE_CALL)
        for child in node.children:
            merged = self._merge(merged, self._expression(child, raw), step)
        return merged

    def _lambda(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Analyse a lambda: its default arguments and its body."""
        merged = TaintValue()
        for child in node.children:
            if child.type == "lambda_parameters":
                for param in child.children:
                    if param.type in ("default_parameter", "typed_default_parameter"):
                        merged = self._merge(merged, self._expression(param.children[-1],
                                                                      raw),
                                             self._step(node, EDGE_CALL))
            else:
                merged = self._merge(merged, self._expression(child, raw),
                                     self._step(node, EDGE_CALL))
        return merged

    def _comprehension(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Analyse a comprehension.

        Python evaluates the outermost iterable first and the element expression
        last, but tree-sitter emits the element expression *before* the
        ``for_in_clause``. Binding loop variables in a single left-to-right pass
        would therefore evaluate the body against a variable that is not yet
        bound, so the clauses are bound in a dedicated first pass.
        """
        merged = TaintValue()
        step = self._step(node, EDGE_COMPREHENSION)
        shadowed: list[tuple[str, TaintValue | None]] = []

        def note_shadow(name: str) -> None:
            if name:
                shadowed.append((name, self._values.get(name)))

        # Pass 1: bind every loop variable, outermost clause first.
        for clause in (c for c in node.children if c.type == "for_in_clause"):
            target, iterable = _for_clause_parts(clause)
            iterable_value = (
                self._expression(iterable, raw) if iterable is not None else TaintValue()
            )
            if target is not None:
                note_shadow(self._get_node_text(target, raw))
                self._bind_target(target, iterable_value, EDGE_ITER, raw)
            merged = self._merge(merged, iterable_value, step)

        # Pass 2: the element expression and any ``if`` filters.
        for child in node.children:
            if child.type in ("for_in_clause", "comment"):
                continue
            merged = self._merge(merged, self._expression(child, raw), step)

        for name, previous in shadowed:
            if previous is None:
                self._values.pop(name, None)
            else:
                self._values[name] = previous
        return merged

    def _string_value(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Evaluate a string literal, including f-string interpolations.

        tree-sitter models an f-string as a ``string`` node whose children are
        ``interpolation`` nodes. The previous implementation had no
        ``interpolation`` case, so every f-string was treated as a constant and
        every f-string injection was missed.
        """
        text = self._get_node_text(node, raw)
        if self._current is not None and self._is_sql_string(text):
            self._current.has_sql_string = True

        merged = TaintValue()
        interpolation_seen = False
        for child in node.children:
            if child.type == "interpolation":
                # An f-string interpolation node holds the substituted
                # expression between braces. Its taint must be merged, otherwise
                # every f-string looks like a constant.
                interpolation_seen = True
                for part in child.children:
                    if part.type in ("{", "}", "format_specifier", "comment"):
                        continue
                    inner = self._expression(part, raw)
                    if inner.origins:
                        merged = self._merge(
                            merged, inner, self._step(node, EDGE_FSTRING)
                        )
                continue
            if child.type in ("escape_sequence", "string_start", "string_content",
                              "string_end", "string_name", "format_specifier",
                              "comment"):
                continue
            inner = self._expression(child, raw)
            if inner.origins:
                interpolation_seen = True
                merged = self._merge(merged, inner, self._step(node, EDGE_FSTRING))
        if interpolation_seen and not merged.origins:
            # An f-string with no tainted interpolation is still a template, so
            # downstream string operations must treat it as a format sink.
            self._record_format_sink(node, raw)
        return merged

    def _binary(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Evaluate a binary operation, distinguishing concat from percent.

        tree-sitter builds a left-leaning tree for an operator chain, so this
        recurses once per operator. ``x = 1 + 1 + ...`` repeated a few hundred
        times therefore exhausted the interpreter stack and raised
        :class:`RecursionError` out of ``scan_source``. The budget below turns
        that crash into a bounded, reported result. Beyond it the operands are
        treated as unknown rather than the call failing, because dropping the
        expression entirely would understate taint on a path we simply did not
        follow -- and silently is not acceptable either, so it is recorded.
        """
        if self._depth > MAX_EXPRESSION_DEPTH:
            self._depth_exceeded = True
            return TaintValue()
        self._depth += 1
        try:
            children = [c for c in node.children if c.type not in ("comment",)]
            operator = (
                self._get_node_text(children[1], raw).strip() if len(children) >= 3 else ""
            )
            edge = EDGE_PERCENT if operator == "%" else EDGE_CONCAT
            merged = TaintValue()
            step = self._step(node, edge)
            for child in children:
                if child.type == "identifier" and operator == "%" and not merged.origins:
                    # ``"..." % (a, b)`` -- the right operand is a tuple.
                    pass
                merged = self._merge(merged, self._expression(child, raw), step)
            if operator == "%" and merged.origins:
                self._record_format_sink(node, raw)
            return merged
        finally:
            self._depth -= 1

    def _resolve_value(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Resolve an attribute access to a value.

        A tainted receiver yields a tainted result; an unrecognised attribute of
        a known source object is itself a source (``request.method``).
        """
        name = self._resolve_name(node, raw)
        if not name:
            return TaintValue()
        if name in self._values:
            return self._values[name]
        head = name.split(".")[0]
        if head in self._values:
            base = self._values[head]
            if base.origins:
                return TaintValue(
                    origins=base.origins,
                    neutralised=base.neutralised,
                    partial=base.partial,
                    path=base.path + (self._step(node, EDGE_ATTR, name),),
                )
            return TaintValue(path=base.path)
        origin = self._source_origin_of(name)
        if origin is not None:
            return TaintValue(
                origins=frozenset({origin}),
                path=(self._step(node, STEP_KIND_SOURCE, EDGE_ATTR, name),),
            )
        return TaintValue()

    def _resolve_subscript(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Resolve ``base[index]``.

        The base object is what carries the taint; the index is also propagated
        so that ``data[request.GET['k']]`` is detected.
        """
        children = list(node.children)
        if not children:
            return TaintValue()
        base = self._expression(children[0], raw)
        merged = base
        step = self._step(node, EDGE_INDEX)
        for child in children[1:]:
            if child.type in ("]", "slice"):
                continue
            merged = self._merge(merged, self._expression(child, raw), step)
        if not base.origins:
            name = self._resolve_name(node, raw)
            origin = self._source_origin_of(name) if name else None
            if origin is not None:
                return TaintValue(
                    origins=frozenset({origin}),
                    path=(self._step(node, STEP_KIND_SOURCE, EDGE_INDEX, name or ""),),
                )
        return merged

    def _resolve_name(self, node: tree_sitter.Node, raw: bytes) -> str:
        """Resolve an expression to a dotted name where one exists."""
        kind = node.type
        if kind == "identifier":
            return self._get_node_text(node, raw)
        if kind == "attribute":
            head = node.children[0] if node.children else None
            tail = node.children[-1] if len(node.children) >= 2 else None
            if head is not None and tail is not None:
                base = self._resolve_name(head, raw)
                attr = self._get_node_text(tail, raw)
                return f"{base}.{attr}" if base else attr
        if kind == "call":
            return self._resolve_name(node.children[0], raw) if node.children else ""
        if kind == "subscript":
            return self._resolve_name(node.children[0], raw) if node.children else ""
        if kind in ("parenthesized_expression", "as_expression"):
            return self._resolve_name(node.children[-1], raw) if node.children else ""
        if kind in ("attribute", "await", "starred_expression"):
            return self._resolve_name(node.children[0], raw) if node.children else ""
        return ""

    def _source_origin_of(self, name: str) -> str | None:
        """Classify a dotted name as a taint source, honouring import bindings."""
        from ..registry import source_origin

        if "." not in name:
            bound = self._bindings.origin_for(name)
            if bound is not None:
                return bound
        return source_origin(name)

    # ================================================================= calls
    def _call(self, node: tree_sitter.Node, raw: bytes) -> TaintValue:
        """Evaluate a call: resolve callee, evaluate arguments, apply schema."""
        call_name = self._get_call_name(node, raw)
        if call_name in ("unknown", ""):
            return TaintValue()

        if self._current is not None:
            self._current.calls.append(call_name)
        else:
            self._file.module_calls.append(call_name)

        arguments = self._collect_arguments(node, raw)

        if self._current is not None:
            self._current.invocations.append(
                (
                    call_name,
                    self._node_line(node),
                    tuple(tuple(sorted(a.value.origins)) for a in arguments),
                    tuple((a.index, a.keyword) for a in arguments),
                )
            )
        else:
            self._file.invocations.append(
                (
                    call_name,
                    self._node_line(node),
                    tuple(tuple(sorted(a.value.origins)) for a in arguments),
                    tuple((a.index, a.keyword) for a in arguments),
                )
            )

        # Amplifiers are checked before sinks: ``mark_safe`` is not a call that
        # *consumes* untrusted data, it is a call that *asserts* safety, and the
        # assertion is the defect whether or not any taint is present.
        amplifier = amplifier_for(call_name, self._bindings)
        if amplifier is not None and arguments:
            self._note_sanitiser(amplifier.name)
            self._record_amplifier(call_name, amplifier, arguments[0], node, raw)
            return self._return_value_of(call_name, arguments, node, raw)

        result = self._apply_sanitiser(call_name, arguments, node, raw)
        if result is not None:
            return result

        self._check_sink(call_name, arguments, node, raw)
        return self._return_value_of(call_name, arguments, node, raw)

    def _collect_arguments(self, node: tree_sitter.Node, raw: bytes) -> list[_CallArg]:
        """Evaluate every argument, recording position and keyword name."""
        out: list[_CallArg] = []
        for child in node.children:
            if child.type != "argument_list":
                continue
            positional = 0
            for arg in child.children:
                if arg.type in (",", "(", ")"):
                    continue
                if arg.type == "comment":
                    continue
                if arg.type == "keyword_argument":
                    name_node = arg.children[0] if arg.children else None
                    value_node = arg.children[-1] if arg.children else None
                    keyword = (
                        self._get_node_text(name_node, raw)
                        if name_node is not None and name_node.type == "identifier"
                        else None
                    )
                    if value_node is None:
                        continue
                    out.append(
                        _CallArg(
                            index=None,
                            keyword=keyword,
                            value=self._expression(value_node, raw),
                            node=arg,
                            is_splat=value_node.type in ("list_splat", "dictionary_splat"),
                        )
                    )
                    continue
                if arg.type in ("list_splat", "dictionary_splat"):
                    out.append(
                        _CallArg(
                            index=None,
                            keyword=None,
                            value=self._expression(arg, raw),
                            node=arg,
                            is_splat=True,
                        )
                    )
                    continue
                out.append(
                    _CallArg(
                        index=positional,
                        keyword=None,
                        value=self._expression(arg, raw),
                        node=arg,
                    )
                )
                positional += 1
        return out

    def _note_sanitiser(self, name: str) -> None:
        """Record that a sanitiser was applied in the current scope."""
        if self._current is not None and name not in self._current.sanitisers:
            self._current.sanitisers.append(name)
        elif self._current is None:
            module = getattr(self._file, "sanitisers", None)
            if module is None:
                module = []
                self._file.sanitisers = module
            if name not in module:
                module.append(name)

    def _apply_sanitiser(
        self, call_name: str, arguments: list[_CallArg], node: tree_sitter.Node, raw: bytes
    ) -> TaintValue | None:
        """Apply a sanitiser to its target argument.

        Returns:
            The post-sanitiser value for the sanitiser argument, or ``None`` when
            the call is not a sanitiser.
        """
        spec = kill_for(call_name, self._bindings)
        if spec is None:
            return None
        target = spec.arg_index
        selected: _CallArg | None = None
        if spec.kills or spec.produces:
            for arg in arguments:
                if arg.index == target or (arg.index is None and arg.keyword is None
                                           and target == 0 and not arg.is_splat):
                    selected = arg
                    break
        if selected is None and arguments:
            selected = arguments[0]
        if selected is None:
            return TaintValue()

        value = selected.value

        # A sanitiser neutralises its argument whether or not that argument was
        # tracked as tainted. Returning early for an untracked argument meant the
        # kill was never applied to the returned value, so ``Markup(escape(x))``
        # -- escaping before asserting safety, the canonical correct pattern --
        # was reported as an XSS amplifier because ``escape`` had not been
        # consulted at all. The early return also contradicted the comment below
        # it, which says an untracked sanitiser is still worth recording.
        self._note_sanitiser(spec.name)

        if spec.produces:
            # Amplifier: the assertion itself is the finding, independent of
            # whether any untrusted data reached it.
            self._record_amplifier(call_name, spec, selected, node, raw)
            return TaintValue(path=value.path)

        if spec.full:
            return TaintValue(
                origins=value.origins,
                neutralised=value.neutralised | spec.kills,
                partial=value.partial,
                path=value.path + (self._step(node, STEP_KIND_SANITIZE,
                                             f"kill:{spec.name}", call_name),),
                kills=value.kills + (spec.name,),
            )
        return TaintValue(
            origins=value.origins,
            neutralised=value.neutralised,
            partial=value.partial | spec.kills,
            path=value.path + (self._step(node, STEP_KIND_SANITIZE,
                                         f"partial:{spec.name}", call_name),),
            kills=value.kills + (spec.name,),
        )

    def _check_format_sink(
        self, call_name: str, arguments: list[_CallArg], node: tree_sitter.Node, raw: bytes
    ) -> None:
        """Record ``.format``/``%``-style string builders as XSS-relevant."""
        if not call_name.endswith((".format", ".format_map")):
            return
        if self._current is None:
            return
        self._current.calls.append("str.format")

    def _record_format_sink(self, node: tree_sitter.Node, raw: bytes) -> None:
        """Note that a template string was built from tainted data."""
        if self._current is None:
            return
        self._current.calls.append("str.format")

    def _check_sink(
        self, call_name: str, arguments: list[_CallArg], node: tree_sitter.Node, raw: bytes
    ) -> None:
        """Evaluate a call against the sink schema and emit traces."""
        canonical = canonical_sink(call_name, self._bindings)
        if canonical is None:
            return
        spec = sink_spec_for(canonical)
        if spec is None:
            return

        if self._current is not None:
            if canonical not in self._current.sinks:
                self._current.sinks.append(canonical)
            self._current.call_sites.append(
                (canonical, call_name, self._node_line(node), self._node_column(node))
            )
        else:
            self._file.call_sites.append(
                (canonical, call_name, self._node_line(node), self._node_column(node))
            )

        structural = self._structural_kill(spec.category, call_name, arguments, raw)

        for arg in arguments:
            if arg.keyword is not None:
                dangerous = structural is None and spec.is_dangerous_keyword(arg.keyword)
            elif arg.index is None:
                # Splatted argument: the target position is unknown, so the
                # conservative answer is "dangerous".
                dangerous = structural is None
            else:
                dangerous = structural is None and spec.is_dangerous_position(arg.index)
            if not dangerous:
                continue
            value = arg.value
            if not value.origins:
                continue
            if spec.category in value.neutralised:
                # Fully sanitised for this category: not a finding.
                continue
            self._emit_taint_trace(spec, call_name, arg, value, node, raw,
                                   partial=spec.category in value.partial)

    def _structural_kill(
        self,
        category: str,
        call_name: str,
        arguments: list[_CallArg],
        raw: bytes,
    ) -> str | None:
        """Detect an in-call argument schema that neutralises the sink.

        Two cases are modelled:

        *   ``subprocess.run(argv, shell=False)`` where ``argv`` is a list or
            tuple: an argv-style invocation never re-parses the argument, so
            shell metacharacters are inert.
        *   ``cursor.execute(sql, params)``: handled declaratively by
            :attr:`SinkSpec.safe_positions`, so no special case is needed here.
        """
        if category != Category.EXEC:
            return None
        shell_kwarg = None
        for arg in arguments:
            if arg.keyword == "shell":
                shell_kwarg = arg
        if shell_kwarg is None:
            return None
        text = self._get_node_text(shell_kwarg.node, raw).strip()
        if text in ("shell=False", "shell=0", "shell=()"):
            first = arguments[0] if arguments else None
            if first is not None and first.node is not None:
                if first.node.type in ("list", "tuple"):
                    return "argv-list-shell-false"
        return None

    def _emit_taint_trace(
        self,
        spec,
        call_name: str,
        arg: _CallArg,
        value: TaintValue,
        node: tree_sitter.Node,
        raw: bytes,
        partial: bool,
    ) -> None:
        """Build and record a confirmed source-to-sink trace."""
        steps = value.path + (
            self._step(node, EDGE_ARG if arg.keyword is None else f"kw:{arg.keyword}",
                       self._get_node_text(arg.node, raw)),
            TraceStep(self._node_line(node), self._node_column(node), STEP_KIND_SINK,
                      call_name, self._get_node_text(arg.node, raw)),
        )
        confidence = BASE_TAINT_CONFIDENCE
        notes: list[str] = []
        if partial:
            confidence *= PARTIAL_MITIGATION_FACTOR
            notes.append(
                "a partial mitigation was observed on this path; the flow may still "
                "be exploitable"
            )
        confidence -= STEP_DECAY * max(0, len(steps) - 3)
        confidence = max(MIN_TAINT_CONFIDENCE, confidence)
        # Guard evidence is applied *after* the floor on purpose.
        # MIN_TAINT_CONFIDENCE exists to stop step decay from silently erasing a
        # genuine long chain; it must not also override a guard. Applying the
        # guard before the floor made PARTIAL_MITIGATION_FACTOR unable to cross
        # the reporting threshold, so every mitigated flow stayed a finding.
        guard = _strongest_guard(steps)
        if guard is not None:
            confidence = max(0.05, confidence - GUARD_STRENGTH[guard])
            notes.append(
                f"a terminating {guard} guard constrains this value; the flow is "
                "reported for review rather than as a confirmed finding, and is "
                "not a patch candidate"
            )
        sink_arg = (
            f"kw:{arg.keyword}" if arg.keyword is not None
            else ("splat" if arg.index is None else f"pos:{arg.index}")
        )
        reported_origins = display_origins(value.origins)
        indices = param_indices(value.origins)
        # Refine the generic PARAM label where a framework request object is
        # declared. See refine_origin: this is a label change only.
        if Origin.PARAM in reported_origins:
            refined = refine_origin(Origin.PARAM, self._current)
            # dict.fromkeys de-duplicates while preserving order: when the set
            # already contains REQUEST alongside PARAM, refining PARAM to
            # REQUEST would otherwise yield the same origin twice.
            reported_origins = tuple(
                dict.fromkeys(
                    refined if o == Origin.PARAM else o for o in reported_origins
                )
            )
        if reported_origins == (Origin.GLOBAL,):
            # A flow that originates only in process-global state is a
            # propagation, not an external input; report it, but rank it below
            # a flow that starts at a request or a parameter.
            confidence = min(confidence, 0.65)
            notes.append(
                "flow originates in process-global state rather than an external input"
            )
        trace = Trace(
            function=self._current.name if self._current else "<module>",
            lineno=self._current.lineno if self._current else 0,
            cwe=spec.cwe,
            category=spec.category,
            sink=spec.name,
            sink_call=call_name,
            sink_line=self._node_line(node),
            sink_arg=sink_arg,
            origins=reported_origins,
            steps=tuple(steps),
            kills=tuple(sorted(set(value.kills))),
            confidence=round(confidence, 4),
            detector=DETECTOR_TAINT,
            file=self._file.path,
            notes=tuple(notes),
            param_indices=indices,
        )
        self._record(trace)

    def _record_amplifier(
        self, call_name: str, spec, arg: _CallArg, node: tree_sitter.Node, raw: bytes
    ) -> None:
        """Record an amplifier finding: a sanitiser assertion that creates a sink.

        ``mark_safe(clean_value)`` is the canonical case. The developer asserted
        safety; if the assertion is wrong the value is injected, and no taint
        needs to be present for the assertion to be the defect.

        An assertion whose argument was already fully sanitised for every
        category the assertion produces is *not* reported:
        ``mark_safe(html.escape(x))`` is contradictory but not exploitable, and
        reporting it would put noise back into the output the sanitiser model
        exists to remove.
        """
        if spec.produces and spec.produces <= arg.value.neutralised:
            return

        # An assertion about a literal cannot be wrong. ``Markup("<li>...")``
        # applied to a constant string is not an assertion anyone could have got
        # wrong, and reporting it put a finding on Airflow's pagination helper,
        # which builds static markup. The premise of the amplifier detector is
        # "the developer asserted safety and may be wrong", and a constant is
        # outside that premise.
        if spec.produces and self._is_constant_expression(arg.node):
            return
        steps = (
            self._step(node, STEP_KIND_SOURCE, "assert-safe", call_name),
            TraceStep(self._node_line(node), self._node_column(node), STEP_KIND_SINK,
                      call_name, self._get_node_text(arg.node, raw)),
        )
        origins = display_origins(arg.value.origins)
        confidence = AMPLIFIER_CONFIDENCE + (0.15 if origins else 0.0)
        trace = Trace(
            function=self._current.name if self._current else "<module>",
            lineno=self._current.lineno if self._current else 0,
            cwe=CATEGORY_CWE[Category.XSS],
            category=Category.XSS,
            sink="XSS_OUTPUT",
            sink_call=call_name,
            sink_line=self._node_line(node),
            sink_arg=f"pos:{arg.index}" if arg.index is not None else "arg:*",
            origins=origins,
            steps=steps,
            kills=(),
            confidence=round(min(0.95, confidence), 4),
            detector=DETECTOR_AMPLIFIER,
            file=self._file.path,
            notes=(f"amp:{spec.name}", spec.description),
            param_indices=param_indices(arg.value.origins),
        )
        self._record(trace)

    def _is_constant_expression(self, node: tree_sitter.Node | None) -> bool:
        """Whether an expression is a literal with no runtime variability.

        F-strings, ``%`` and ``.format`` produce strings from other values, so
        they are not constant even when every substituted piece looks literal;
        treating them as constant would suppress the common
        ``Markup("<b>%s</b>" % value)`` shape, which is a genuine amplifier.
        """
        if node is None:
            return False
        return node.type in _CONSTANT_NODE_TYPES

    def _return_value_of(
        self, call_name: str, arguments: list[_CallArg], node: tree_sitter.Node, raw: bytes
    ) -> TaintValue:
        """Compute the taint of a call's return value.

        A call result is tainted when any of its arguments is tainted, unless the
        call is a reader that introduces a *new* origin. ``parse()``-style
        constructors are treated as propagators, which is the conservative choice.
        """
        merged = TaintValue()
        step = self._step(node, EDGE_CALL, call_name)
        for arg in arguments:
            merged = self._merge(merged, arg.value, step)

        origin = self._source_origin_of(call_name)
        if origin is not None and origin != Origin.GLOBAL:
            # A reader: the result carries the reader's origin, but keeps any
            # taint that was already present in its receiver.
            return TaintValue(
                origins=frozenset({origin}) | merged.origins,
                neutralised=merged.neutralised,
                partial=merged.partial,
                path=merged.path
                + (self._step(node, STEP_KIND_SOURCE, EDGE_CALL, call_name),),
                kills=merged.kills,
            )
        return merged

    # ================================================================ helpers
    def _record(self, trace: Trace) -> None:
        """Attach a trace to the current function or to module scope."""
        if self._current is not None:
            existing = {t.location_key for t in self._current.traces}
            if trace.location_key not in existing:
                self._current.traces.append(trace)
        else:
            existing = {t.location_key for t in self._file.module_traces}
            if trace.location_key not in existing:
                self._file.module_traces.append(trace)

    def _merge(
        self, left: TaintValue, right: TaintValue, step: TraceStep
    ) -> TaintValue:
        """Merge two taint values.

        Delegates to :meth:`syrth.taint.engine.TaintEngine.merge` so the front
        end and every other consumer share one definition of these semantics.
        Two copies of this rule is how the previous release ended up with a
        parser that laundered sanitised values differently from the engine that
        documented the behaviour.
        """
        return self._taint_engine.merge([left, right], step=step)
    def _step(
        self, node: tree_sitter.Node, edge: str, detail: str = "", kind: str = STEP_KIND_PROPAGATE
    ) -> TraceStep:
        """Build a propagation step anchored at ``node``."""
        text = detail
        if not text:
            return TraceStep(self._node_line(node), self._node_column(node), kind, edge)
        return TraceStep(
            self._node_line(node), self._node_column(node), kind, edge,
            _normalise_detail(text),
        )

    def _is_sql_string(self, text: str) -> bool:
        """True when a string literal contains a SQL keyword."""
        if len(text) < 8:
            return False
        upper = text.upper()
        return any(keyword in upper for keyword in SQL_KEYWORDS)

    def _finalise_trace(self, trace: FunctionTrace) -> None:
        """Derive compatibility tokens and interprocedural bookkeeping.

        Produces:
            * ``flows`` / ``tainted:`` tokens from the confirmed traces.
            * ``symbolic_origins``: variable -> symbolic origins, the map the
              interprocedural layer uses to decide which arguments of a call
              carry taint.
            * ``returns_param_indices``: parameters whose taint reaches the
              return value.
        """
        for trace_item in trace.traces:
            for origin in trace_item.origins:
                token = f"flow:{origin}->{trace_item.sink}"
                if token not in trace.flows:
                    trace.flows.append(token)
        trace.flows.sort()

        symbolic: dict[str, tuple[str, ...]] = {}
        for name, value in self._values.items():
            if value.origins:
                symbolic[name] = tuple(sorted(value.origins))
        trace.symbolic_origins = dict(sorted(symbolic.items()))

        returned = self._values.get("__return__", TaintValue())
        trace.returns_param_indices = sorted(param_indices(returned.origins))


def _for_clause_parts(
    node: tree_sitter.Node,
) -> tuple[tree_sitter.Node | None, tree_sitter.Node | None]:
    """Split a ``for_in_clause`` into its target and iterable nodes.

    tree-sitter lays the clause out as ``[for, <target>, in, <iterable>]``, so
    the two are located by the position of the ``in`` token. Matching by node
    type would be wrong, because both sides are usually bare identifiers.
    """
    children = [c for c in node.children if c.type != "comment"]
    for position, child in enumerate(children):
        if child.type == "in" and position >= 1:
            target = children[position - 1]
            iterable = children[position + 1] if position + 1 < len(children) else None
            return target, iterable
    return None, None


def _normalise_detail(text: str) -> str:
    """Collapse whitespace and truncate a detail string."""
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= 80 else collapsed[:79] + "â€¦"


PARAM_ORIGIN_PREFIX = "PARAM#"


def param_origin(index: int) -> str:
    """Symbolic taint origin identifying parameter ``index``."""
    return f"{PARAM_ORIGIN_PREFIX}{index}"


def _strongest_guard(steps: Iterable[TraceStep]) -> str | None:
    """Strongest *terminating* guard recorded on a propagation path.

    Reads the guard markers appended by ``_apply_guards``. Weak (non-terminating)
    guards are ignored here: they constrain the branch that was taken, not the
    code that follows, so they are not evidence about this path.
    """
    found: str | None = None
    for step in steps:
        if step.kind != STEP_KIND_GUARD:
            continue
        # The guard strength travels in ``edge``; ``detail`` carries the name.
        strength = step.edge
        if strength in GUARD_STRENGTH:
            found = strength
    return found


def refine_origin(origin: str, function: FunctionTrace) -> str:
    """Refine a generic ``PARAM`` label to ``REQUEST`` where that is accurate.

    The *symbolic* origin stays position-based, so rename invariance and the
    interprocedural layer are unaffected. Only the displayed label is refined,
    and only for a parameter declared with exactly the conventional framework
    request name. ``PARAM`` and ``REQUEST`` are both external origins with
    identical severity and identical effect on whether a flow is reported, so no
    verdict can depend on this.

    "Which external source?" is the first question a reader asks of a finding,
    and "some parameter" is a worse answer than "an HTTP request".
    """
    from ..registry import REQUEST_OBJECT_NAMES

    if origin != Origin.PARAM or function is None:
        return origin
    declared = {name for _index, name in function.arg_positions}
    if declared & REQUEST_OBJECT_NAMES:
        return Origin.REQUEST
    return origin


def parse_param_origin(origin: str) -> int | None:
    """Parameter index encoded in ``origin``, or ``None`` when not a parameter."""
    if origin.startswith(PARAM_ORIGIN_PREFIX):
        tail = origin[len(PARAM_ORIGIN_PREFIX):]
        if tail.isdigit():
            return int(tail)
    return None


def display_origins(origins: Iterable[str]) -> tuple[str, ...]:
    """Map symbolic origins onto the reported origin vocabulary."""
    mapped = {Origin.PARAM if o.startswith(PARAM_ORIGIN_PREFIX) else o for o in origins}
    return tuple(sorted(mapped))


def param_indices(origins: Iterable[str]) -> tuple[int, ...]:
    """Parameter indices encoded in a symbolic origin set, sorted."""
    indices = {parse_param_origin(o) for o in origins}
    return tuple(sorted(i for i in indices if i is not None))


def _handles(node: tree_sitter.Node) -> bool:
    """True when a node is a with-statement item that binds a resource handle."""
    return node.type in ("with_statement", "with_clause", "with_item")


def children_condition_names(node: tree_sitter.Node, raw: bytes) -> list[str]:
    """Identifiers mentioned in a guard condition.

    A guard that compares or membership-tests a value is a partial mitigation:
    it constrains the value but does not by itself make it safe.
    """
    names: list[str] = []
    stack = list(node.children[:1])
    while stack:
        current = stack.pop()
        if current.type == "identifier":
            names.append(raw[current.start_byte:current.end_byte].decode("utf-8", "replace"))
        stack.extend(current.children)
    return names


def _has_error_node(node: tree_sitter.Node) -> bool:
    """True when the parse tree contains an ERROR or MISSING node.

    Iterative on purpose. This walked the tree recursively, and tree-sitter
    produces a left-leaning tree whose depth grows with the length of an operator
    chain, so ``x = 1 + 1 + ... (500 times)`` overflowed the interpreter stack and
    raised :class:`RecursionError` out of ``scan_source``. A static analyser that
    crashes on hostile input is a denial of service on its own primary function.
    """
    pending = [node]
    while pending:
        current = pending.pop()
        if current.type in ("ERROR", "MISSING"):
            return True
        pending.extend(current.children)
    return False


__all__ = ["PythonParser", "Token"]
