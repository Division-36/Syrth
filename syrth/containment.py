"""Containment guards: recognising "this path cannot escape" from control flow.

Why this is a separate mechanism
--------------------------------
A registry kill says "this call turns a dangerous value into a safe one" --
``os.path.basename`` strips directories from a path, so the path it returns cannot
escape. Containment is not that shape. ``os.path.commonpath([root, target])``
computes a *decision*; the code is safe only if it then exits when the decision is
bad, and unsafe if it ignores the answer:

    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside")          # safe
    _ = os.path.commonpath([root, target])   # still vulnerable

Registering ``commonpath`` as a kill therefore does not merely risk false
positives, it does nothing at all: the tainted flow to ``open`` runs through
``os.path.join``, not through the ``commonpath`` call, so a kill applied to the
commonpath argument never touches it. Measured, both the guarded and unguarded
forms keep reporting. What is needed is not a better kill and not a value-level
sensitivity, but a statement-level fact: *the sink is dominated by a containment
test whose failure exits.*

Scope and honesty of the guarantee
----------------------------------
The recogniser is deliberately syntactic and narrow:

* the guard must be an ``if`` whose test contains a containment primitive;
* its body must exit unconditionally (``raise``, ``return``, a call to
  ``abort``/``os._exit``, or ``continue``/``break``);
* the sink must appear **after** the guard in the same function;
* the sink's path expression must mention a name the guard tested.

``continue`` and ``break`` are exits of the *loop*, not of the function, so a guard
that uses one is only given a ``scope``: the line range of the loop body it
dominates. A sink outside that range is still reachable on another iteration or
after the loop, and suppressing it would delete a finding for no reason.

What that does **not** claim: dominator analysis, alias resolution, or any
judgement about whether the test is the *right* test. A guard that is present but
wrong still suppresses. That is a real false-negative risk and it is why the
primitive set is restricted to expressions whose semantics are containment by
construction, and why the finding is downgraded rather than deleted -- the class
stays visible, its evidence is marked structural.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

#: Attribute and function names that make an expression a containment test.
_CONTAINMENT_NAMES = frozenset({
    "commonpath", "commonprefix", "relative_to", "isabs", "realpath",
    "is_relative_to",
})

#: Method names that are containment tests when called on a path-like receiver.
_CONTAINMENT_METHODS = frozenset({"relative_to", "is_relative_to"})

#: Comparisons that make an expression a containment decision.
_COMPARISONS = (ast.Eq, ast.NotEq, ast.In)

#: Calls that end the enclosing function when they appear alone in a branch body.
_EXIT_CALLS = frozenset({"abort", "os._exit", "sys.exit", "die"})

#: Statements that end the enclosing *loop* rather than the function.
_LOOP_EXITS = (ast.Break, ast.Continue)

#: Nodes whose body a loop exit leaves behind.
_LOOPS = (ast.For, ast.AsyncFor, ast.While)


@dataclass(frozen=True)
class ContainmentGuard:
    """A containment test whose failure exits the function.

    Attributes:
        line: 1-based line of the ``if`` statement.
        names: Identifiers the test reads, used to check the sink shares state
            with the guard rather than being an unrelated path.
        scope: Inclusive line range this guard dominates, or ``None`` when the
            guard exits the whole function. A loop exit is bounded to its loop
            body; anything else would be reachable on a later iteration.
    """

    line: int
    names: frozenset[str] = field(default_factory=frozenset)
    scope: tuple[int, int] | None = None


def _names_in(node: ast.AST) -> set[str]:
    """Every identifier read by an expression."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _has_containment_primitive(node: ast.AST) -> bool:
    """Whether the expression contains a containment decision."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr in _CONTAINMENT_NAMES:
                return True
            if isinstance(func, ast.Name) and func.id in _CONTAINMENT_NAMES:
                return True
        if isinstance(child, ast.Attribute) and child.attr in _CONTAINMENT_METHODS:
            return True
        if isinstance(child, ast.Compare):
            # ``path.startswith(root)`` and ``x in root`` are containment tests.
            if any(isinstance(op, _COMPARISONS) for op in child.ops):
                left = child.left
                if isinstance(left, ast.Call):
                    func = left.func
                    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                    if name in {"startswith", "commonprefix", "join", "abspath", "normpath"}:
                        return True
                if any(
                    isinstance(c, ast.Call)
                    and isinstance(c.func, ast.Attribute)
                    and c.func.attr in {"startswith", "dirname", "abspath", "normpath", "realpath"}
                    for c in list(child.comparators) + [left]
                ):
                    return True
    return False


def _exit_kind(body: list[ast.stmt]) -> str | None:
    """How a branch body leaves its enclosing scope.

    ``"function"`` for an exit that ends the whole function, ``"loop"`` for one
    that only ends the current iteration, ``None`` when the body falls through.
    The distinction is load-bearing: a loop exit cannot justify suppressing a
    sink that lies outside the loop.
    """
    if not body:
        return None
    first = body[0]
    if isinstance(first, (ast.Raise, ast.Return)):
        return "function"
    if isinstance(first, _LOOP_EXITS):
        return "loop"
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Call):
        func = first.value.func
        name = (
            func.attr if isinstance(func, ast.Attribute)
            else getattr(func, "id", "")
        )
        return "function" if name in _EXIT_CALLS else None
    return None


def containment_guards(tree: ast.AST) -> list[ContainmentGuard]:
    """Every containment guard in a module, in source order."""
    # Nearest enclosing loop per ``if`` line, so a ``continue`` guard can be
    # bounded to the body it actually dominates.
    loop_spans: list[tuple[int, int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, _LOOPS):
            continue
        last = node.body[-1]
        end = getattr(last, "end_lineno", None) or node.lineno
        loop_spans.append((node.lineno, end, node.lineno))

    def scope_for(line: int, kind: str | None) -> tuple[int, int] | None:
        if kind != "loop":
            return None
        enclosing = [span for span in loop_spans if span[0] < line <= span[1]]
        if not enclosing:
            return None
        # Innermost loop wins: it is the one the exit actually leaves.
        best = min(enclosing, key=lambda span: span[1] - span[0])
        return (best[0], best[1])

    guards: list[ContainmentGuard] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        kind = _exit_kind(node.body)
        if kind is None or node.orelse:
            # An ``if`` with an ``else`` is a selection, not a guard: one of the
            # two branches always runs. Treating it as a guard would suppress
            # whichever branch the sink is in.
            continue
        if not _has_containment_primitive(node.test):
            continue
        guards.append(ContainmentGuard(
            line=node.lineno,
            names=_names_in(node.test),
            scope=scope_for(node.lineno, kind),
        ))
    return sorted(guards, key=lambda g: g.line)


def sink_is_guarded(
    tree: ast.AST,
    sink_line: int,
    sink_names: frozenset[str] | set[str] = frozenset(),
) -> ContainmentGuard | None:
    """The containment guard that dominates a sink, if one does.

    The guard must precede the sink and must share state with it. Without the
    sharing check, a function that validates one path and then opens a different
    one would suppress, which is a false negative a reviewer would immediately
    notice.
    """
    guards = containment_guards(tree)
    if not guards:
        return None
    for guard in guards:
        if guard.line >= sink_line:
            continue
        if guard.scope is not None and not (
            guard.scope[0] <= sink_line <= guard.scope[1]
        ):
            continue
        if not sink_names or (guard.names & sink_names):
            return guard
    return None

# Rejected: recognising ``".." in PurePath(x).parts`` as a containment primitive.
#
# It is Django's own traversal check, so the intent is right, and it silences two
# real corpus findings. It is still wrong here, because the guard constrains one
# name while the sink joins several:
#
#     if ".." in PurePath(filename).parts:
#         raise ValueError()
#     return os.path.normpath(os.path.join(dirname, filename))
#
# For ``../../etc/passwd`` the basename is ``passwd`` -- no ``..`` -- so the guard
# passes while ``dirname`` still walks upwards. Tightening the sharing rule to
# "every name the sink reads must be covered" rejects that case but then also
# rejects the genuine fix, because that one depends on ``get_valid_name()``
# sanitising the basename, which is a framework method this analyser cannot see.
#
# Neither branch is decidable from the syntax, so the finding stands. Closing this
# needs to know which join argument the guard constrains, which is value-level.
