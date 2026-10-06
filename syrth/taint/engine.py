"""
SYRTH Taint Engine
==================
Value-level taint state and the operations that combine it.

Model
-----
A :class:`TaintValue` carries four things:

``origins``
    The set of taint origins that reached the value. An empty set means the
    value is not attacker influenced.
``neutralised``
    Sink categories that a *full* sanitiser has rendered safe for this value.
    A value sanitised with ``shlex.quote`` has ``EXEC`` here, so it can still be
    reported for SQL injection. This is what makes kills category-typed rather
    than global.
``partial``
    Sink categories with a *partial* mitigation. These are still reported, at
    reduced confidence, because a partial mitigation is not a proof of safety.
``path``
    The propagation steps from source to this value, used to render a trace and
    to decide which branch produced the shortest explanation.

Merge semantics
---------------
``neutralised`` intersects and ``partial`` unions. A value is rendered safe for
a category only when *every* tainted operand was sanitised for it, so a
sanitised value cannot launder an unsanitised one.

Guards
------
A guard constrains a tainted value without sanitising it. Guards are graded,
because they are not equally strong evidence:

``allowlist``
    ``if value not in ("a", "b"): return`` -- the value was compared against a
    literal set of constants and the offending branch terminates, so on the
    fall-through path only those constants survive. This is the pattern real
    code uses to stop injection, and ignoring it produced a false-alarm rate of
    roughly one half on the project's own mitigated examples.
``denylist``
    ``if value in BLOCKED: return`` -- narrows the domain but the complement of
    an arbitrary set is still attacker-controlled.
``equality``
    ``if value == "constant"`` -- pins a single value.

None of these is a *proof* of safety, so no guard ever clears ``origins`` and
none of them satisfies the mechanical patch-verification requirement that the
flow be gone. They are recorded, surfaced in the trace, and used to rank the
finding below an unconstrained flow so that a guarded flow is a review item
rather than a headline finding. :data:`GUARD_STRENGTH` holds the deduction.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace

from ..registry import (
    Category,
    KillSpec,
    Origin,
    canonical_sink,
    kill_for,
    sink_spec_for,
    source_origin,
)
from ..trace import STEP_KIND_SANITIZE, STEP_KIND_SOURCE, TraceStep

#: Confidence deducted from a finding whose value is constrained by a guard.
#:
#: A guard is evidence, not proof: ``if cmd not in ("ls", "pwd"): return`` before
#: ``subprocess.run(cmd, shell=True)`` stops the attack the tool reports, but a
#: reviewer still has to confirm the allowlist itself is well chosen. The
#: deduction is sized so a guarded flow lands below the 0.5 reporting threshold
#: and is therefore surfaced as a review item instead of a finding, while
#: remaining visible and machine-readable rather than being silently dropped.
GUARD_STRENGTH: dict[str, float] = {
    "allowlist": 0.45,
    "denylist": 0.25,
    "equality": 0.15,
}

#: Categories a membership/equality guard can plausibly constrain. A guard that
#: compares against a literal only says something about *which* values may
#: reach the sink; it cannot by itself neutralise a deserialisation sink, whose
#: danger does not depend on the value's content.
GUARD_REACHABLE_CATEGORIES: frozenset = frozenset(
    {
        Category.EXEC,
        Category.SQL,
        Category.XSS,
        Category.FILE,
        Category.REDIRECT,
    }
)


@dataclass(frozen=True)
class TaintValue:
    """Taint state for one expression.

    Attributes:
        origins: Taint origins that reached the value.
        neutralised: Categories fully sanitised for this value.
        partial: Categories partially mitigated for this value.
        path: Propagation steps, source first.
        constant: True when the value is a compile-time constant.
        kills: Sanitiser names observed while producing the value.
        guards: Graded guard descriptors constraining this value.
    """

    origins: frozenset = frozenset()
    neutralised: frozenset = frozenset()
    partial: frozenset = frozenset()
    path: tuple[TraceStep, ...] = ()
    constant: bool = False
    kills: tuple[str, ...] = ()
    guards: frozenset = frozenset()

    @property
    def tainted(self) -> bool:
        """True when the value carries at least one taint origin."""
        return bool(self.origins)

    @property
    def guard_strength(self) -> str | None:
        """Strongest guard constraining this value, or ``None``.

        ``"allowlist"`` is the strongest: the value was checked against a
        literal set of constants and the offending branch returns, so on the
        fall-through path only those constants remain. It is still not a
        *proof* -- see :data:`GUARD_STRENGTH`.
        """
        for name in ("allowlist", "denylist", "equality"):
            if name in self.guards:
                return name
        return None

    @property
    def external(self) -> bool:
        """True when the value is reachable by an external attacker.

        ``GLOBAL`` is deliberately excluded: process-global state is a
        propagation vector but not itself an external input, so a
        parameter-to-global-to-sink chain is reported with lower confidence
        than a direct parameter-to-sink chain.
        """
        return bool(self.origins - frozenset({Origin.GLOBAL}))

    def sanitised_for(self, category: str) -> bool:
        """True when ``category`` is fully neutralised for this value."""
        return category in self.neutralised

    def partially_mitigated(self, category: str) -> bool:
        """True when ``category`` has only a partial mitigation."""
        return category in self.partial

    def with_origin(self, origin: str, step: TraceStep | None = None) -> TaintValue:
        """Return a copy carrying one additional origin."""
        if not self.origins:
            return TaintValue(
                origins=frozenset({origin}),
                path=(step,) if step else (),
            )
        if origin in self.origins:
            return self
        return replace(self, origins=self.origins | {origin})

    def with_kill(self, spec: KillSpec, step: TraceStep | None = None) -> TaintValue:
        """Apply a sanitiser to this value.

        A full kill adds to ``neutralised``; a partial kill adds to ``partial``.
        Neither removes origins, because a sanitiser protects only the
        categories it declares.
        """
        step = step or TraceStep(0, 0, STEP_KIND_SANITIZE, f"kill:{spec.name}")
        if spec.full:
            return TaintValue(
                origins=self.origins,
                neutralised=self.neutralised | spec.kills,
                partial=self.partial,
                path=self.path + (step,),
                constant=self.constant,
                kills=self.kills + (spec.name,),
            )
        return TaintValue(
            origins=self.origins,
            neutralised=self.neutralised,
            partial=self.partial | spec.kills,
            path=self.path + (step,),
            constant=self.constant,
            kills=self.kills + (spec.name,),
        )

    def append(self, step: TraceStep) -> TaintValue:
        """Return a copy with one more propagation step."""
        if not step.line or (self.path and self.path[-1].line == step.line):
            return self
        return replace(self, path=self.path + (step,))

    def to_dict(self) -> dict:
        """Plain-dict view, for debugging and serialisation."""
        return {
            "origins": sorted(self.origins),
            "neutralised": sorted(self.neutralised),
            "partial": sorted(self.partial),
            "kills": list(self.kills),
            "path": [s.to_dict() for s in self.path],
        }


@dataclass
class TaintState:
    """Mutable per-function taint context.

    Retained as the public state container used by :class:`TaintEngine` and by
    external integrations. The engine's operations are pure functions over
    :class:`TaintValue`; this class is the convenient mutable wrapper.

    Attributes:
        bindings: Maps a variable name to its :class:`TaintValue`.
        flows: Confirmed ``flow:<ORIGIN>-><SINK>`` tokens, for compatibility.
        tainted_sinks: Canonical sink names reached by tainted data.
    """

    bindings: dict = field(default_factory=dict)
    flows: list = field(default_factory=list)
    tainted_sinks: set = field(default_factory=set)

    def value(self, name: str) -> TaintValue:
        """Current value bound to ``name``, or a clean value."""
        return self.bindings.get(name, TaintValue())


class TaintEngine:
    """Language-agnostic taint operations over :class:`TaintValue`.

    The engine is deliberately free of syntax-tree knowledge; the parser supplies
    resolved call names and the engine applies the registry semantics. That
    separation is what lets the same engine serve the JavaScript and Java front
    ends without duplicating the security model.
    """

    # ---------------------------------------------------------- resolution
    def canonical_sink(self, call_name: str, bindings=None) -> str | None:
        """Canonical sink name for a call, deterministically."""
        return canonical_sink(call_name, bindings)

    def sink_category(self, canonical: str) -> str | None:
        """``SCAT:<CAT>`` token for a canonical sink name, or ``None``."""
        spec = sink_spec_for(canonical)
        return spec.scat_token if spec else None

    def is_high_risk_sink(self, canonical: str) -> bool:
        """True when the canonical sink is in the high-risk set."""
        spec = sink_spec_for(canonical)
        return bool(spec and spec.high_risk)

    def origin_of(self, name: str, bindings=None) -> str | None:
        """Classify ``name`` as a taint source, or return ``None``."""
        if not name:
            return None
        if bindings is not None and "." not in name:
            bound = bindings.origin_for(name)
            if bound is not None:
                return bound
        return source_origin(name)

    def kill_for(self, call_name: str, bindings=None) -> KillSpec | None:
        """Resolve a sanitiser call name to its :class:`KillSpec`."""
        return kill_for(call_name, bindings)

    # ------------------------------------------------------------ sources
    def source_value(self, origin: str, step: TraceStep | None = None) -> TaintValue:
        """Build a taint value originating from ``origin``."""
        return TaintValue(origins=frozenset({origin}), path=(step,) if step else ())

    def parameter_source(self, name: str, line: int) -> TaintValue:
        """Build a taint value for a function parameter.

        Every parameter is a source regardless of its spelling. This is the
        rename-invariance guarantee: the verdict cannot depend on whether the
        developer called the variable ``user_id`` or ``x``.
        """
        return TaintValue(
            origins=frozenset({Origin.PARAM}),
            path=(TraceStep(line, 0, STEP_KIND_SOURCE, "param", name),),
        )

    # --------------------------------------------------------- propagation
    def propagate_through_assignment(
        self, target: str, value: TaintValue, state: TaintState
    ) -> None:
        """Bind ``target`` to ``value`` in ``state``."""
        state.bindings[target] = value

    def propagate_through_binop(self, *operands: TaintValue, step: TraceStep | None = None) -> TaintValue:
        """Union the taint of several operands of one operation."""
        return self.merge(operands, step=step)

    def merge(self, operands: Sequence[TaintValue], step: TraceStep | None = None) -> TaintValue:
        """Merge operands into one value.

        Only *tainted* operands participate in the neutralisation intersection.
        An untainted literal carries no protection to contribute, so it must not
        launder the sanitisation applied to the tainted operand beside it:
        ``os.system("ls " + shlex.quote(x))`` stays protected, while
        ``execute("SELECT " + safe(x) + raw)`` does not, because one of its two
        tainted operands is unsanitised.

        Args:
            operands: Values being combined. ``None`` entries are treated as
                clean.
            step: Optional propagation step appended to the merged path.

        Returns:
            The merged value.
        """
        values = [v if v is not None else TaintValue() for v in operands]
        if not values:
            return TaintValue()

        tainted = [v for v in values if v.origins]
        if not tainted:
            return TaintValue(
                constant=all(v.constant for v in values),
                partial=frozenset().union(*(v.partial for v in values)) if values
                else frozenset(),
            )

        origins: frozenset = frozenset().union(*(v.origins for v in tainted))
        neutralised = tainted[0].neutralised
        for value in tainted[1:]:
            neutralised = neutralised & value.neutralised
        partial: frozenset = frozenset().union(*(v.partial for v in tainted))
        path = _shortest_path(tainted)

        kills: list[str] = []
        for value in tainted:
            for kill in value.kills:
                if kill not in kills:
                    kills.append(kill)

        merged = TaintValue(
            origins=origins,
            neutralised=neutralised,
            partial=partial,
            path=path,
            constant=False,
            kills=tuple(kills),
        )
        return merged.append(step) if step is not None else merged

    def apply_kill(
        self, value: TaintValue, spec: KillSpec, step: TraceStep | None = None
    ) -> TaintValue:
        """Apply a sanitiser to a value."""
        return value.with_kill(spec, step)

    # ---------------------------------------------------------------- sinks
    def is_dangerous_argument(
        self, canonical: str, index: int | None, keyword: str | None
    ) -> bool:
        """True when the given argument position is dangerous for a sink."""
        spec = sink_spec_for(canonical)
        if spec is None:
            return False
        if keyword is not None:
            return spec.is_dangerous_keyword(keyword)
        if index is None:
            return True
        return spec.is_dangerous_position(index)

    def check_sink(
        self,
        canonical: str,
        origins: Iterable[str],
        category: str,
        neutralised: Iterable[str] = (),
        partial: Iterable[str] = (),
    ) -> str:
        """Decide whether a candidate flow is reportable.

        Args:
            canonical: Canonical sink name.
            origins: Origins that reached the sink.
            category: Sink category.
            neutralised: Categories fully sanitised on the path.
            partial: Categories partially mitigated on the path.

        Returns:
            ``"report"``, ``"partial"`` or ``"suppressed"``.
        """
        if not origins:
            return "suppressed"
        if category in frozenset(neutralised):
            return "suppressed"
        if category in frozenset(partial):
            return "partial"
        return "report"

    def flows_for(self, origins: Iterable[str], canonical: str) -> list:
        """Compatibility ``flow:`` tokens for an origin/sink pair."""
        return [f"flow:{origin}->{canonical}" for origin in sorted(set(origins))]

    def tainted_tokens(self, tainted_sinks: Iterable[str]) -> list:
        """``tainted:`` tokens for a set of canonical sinks."""
        return [f"tainted:{sink}" for sink in sorted(set(tainted_sinks))]

    def propagate_through_call(
        self, callee: str, arguments: Sequence[TaintValue], bindings=None
    ) -> TaintValue:
        """Taint of a call's return value.

        A call result inherits the taint of its arguments and, when the callee is
        a recognised external-state reader, gains that reader's origin.
        """
        merged = self.merge(list(arguments))
        origin = self.origin_of(callee, bindings)
        if origin is not None and origin != Origin.GLOBAL:
            return TaintValue(
                origins=merged.origins | {origin},
                neutralised=merged.neutralised,
                partial=merged.partial,
                path=merged.path,
                kills=merged.kills,
            )
        return merged


def _shortest_path(values: Sequence[TaintValue]) -> tuple[TraceStep, ...]:
    """Pick the most explanatory path among tainted operands, deterministically.

    "Most explanatory" is the shortest path: every extra hop is a place where a
    reader has to verify one more step. Ties are broken by comparing the paths
    themselves so the choice does not depend on operand order.
    """
    candidates = [v.path for v in values if v.origins and v.path]
    if not candidates:
        return ()
    return min(candidates, key=lambda p: (len(p), p))


__all__ = ["TaintEngine", "TaintState", "TaintValue", "Category", "Origin"]
