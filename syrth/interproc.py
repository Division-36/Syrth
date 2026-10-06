"""
SYRTH Interprocedural Layer
===========================
Call-graph construction, per-function summaries and a fixed-point reachability
pass that decides which flows survive across function boundaries.

Why this exists
---------------
An intraprocedural analysis reports ``execute(query)`` inside a helper but cannot
tell whether that helper is ever reached with attacker-controlled data. Two
consequences follow:

*   **False positives.** ``helper(constant)`` looks identical to
    ``helper(user_input)`` without a call graph. This is where most of the noise
    in rule-based scanners comes from.
*   **Missing paths.** A real injection split across ``entry()`` ->
    ``build_query()`` -> ``execute()`` is invisible to any single-function view,
    so a patch that sanitises inside ``build_query()`` cannot be shown to have
    killed anything.

Algorithm
---------
1.  Index every function by its qualified name (``helper``, ``Class.method``)
    across all analysed files.
2.  Seed taint from *entry points*: functions with no caller inside the analysed
    set have every parameter considered externally influenced, which mirrors the
    intraprocedural assumption for a standalone file.
3.  Iterate a monotone fixed point:
    ``tainted_params[caller][i]`` propagates to ``tainted_params[callee][j]`` when
    the caller passes a tainted argument at position ``j``.
    ``returns_param_indices`` closes the loop for pass-through helpers.
4.  Emit, for every call edge, a trace whose steps span caller and callee, so the
    reported path is the path a reader can verify.

Complexity is bounded by ``O(sum of call edges)`` iterations, which terminates
because the taint sets only ever grow and are finite.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from .registry import Origin
from .trace import (
    EDGE_CALL,
    EDGE_PARAM,
    STEP_KIND_PROPAGATE,
    STEP_KIND_SOURCE,
    Trace,
    TraceStep,
)


@dataclass
class FunctionSummary:
    """Everything the fixed point needs to know about one function.

    Attributes:
        name: Simple name, e.g. ``build_query``.
        qualname: ``Class.method`` when the function is a method.
        file: Source path.
        lineno: 1-indexed definition line.
        param_count: Number of declared parameters.
        var_origins: ``variable -> symbolic origins`` from the intraprocedural pass.
        returns_params: Parameter indices whose taint reaches the return value.
        sink_params: ``canonical_sink -> parameter indices`` reaching that sink.
        self_origins: Origins that appear at a sink without passing through any
            parameter (``input()``, ``os.environ``, a request object, ...).
        invocations: ``(callee, line, per-argument origins, per-argument
            (index, keyword))`` recorded by the parser.
        sink_protected: ``canonical_sink -> categories neutralised`` for sinks
            whose only path runs through a full sanitiser.
    """

    name: str
    qualname: str
    file: str
    lineno: int
    param_count: int
    var_origins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    returns_params: tuple[int, ...] = ()
    sink_params: dict[str, tuple[int, ...]] = field(default_factory=dict)
    self_origins: set[str] = field(default_factory=set)
    invocations: list[tuple[str, int, tuple[tuple[str, ...], ...], tuple]] = field(
        default_factory=list
    )
    sink_protected: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class CrossFunctionTrace:
    """A flow that crosses at least one function boundary.

    Attributes:
        trace_id: Identity of the composed trace, stable across line shifts.
        cwe: CWE identifier of the terminal sink.
        category: Sink category.
        sink: Canonical sink name.
        sink_call: Sink call as written.
        sink_file: File containing the sink.
        sink_line: Line of the sink call.
        chain: Enclosing function names from entry point to sink.
        entry_file: File containing the entry function.
        entry_line: Line of the entry function.
        origins: Taint origins at the entry point.
        param_indices: Entry-point parameter indices carrying the taint.
        steps: Full path, entry point first, sink last.
        kills: Sanitisers observed along the path.
        confidence: Confidence after interprocedural length discount.
    """

    trace_id: str
    cwe: str
    category: str
    sink: str
    sink_call: str
    sink_file: str
    sink_line: int
    chain: tuple[str, ...]
    entry_file: str
    entry_line: int
    origins: tuple[str, ...]
    param_indices: tuple[int, ...]
    steps: tuple[TraceStep, ...]
    kills: tuple[str, ...]
    confidence: float


def _param_index(origin: str) -> int | None:
    """Parameter index encoded in a symbolic origin, or ``None``."""
    prefix = "PARAM#"
    if origin.startswith(prefix):
        tail = origin[len(prefix):]
        if tail.isdigit():
            return int(tail)
    return None


class CallGraph:
    """Call graph over one or more analysed files.

    The graph is a plain directed multigraph keyed by qualified function name.
    Construction is deterministic: files are processed in sorted path order and
    edges are emitted in source order, so two runs over the same inputs produce
    byte-identical output.
    """

    def __init__(self) -> None:
        self.summaries: dict[str, FunctionSummary] = {}
        self.edges: list[tuple[str, str, int, int]] = []   # caller, callee, line, arg_index
        self.traces_by_sink: dict[str, list[Trace]] = {}
        self.module_traces: list[Trace] = []
        #: Number of fixed-point iterations consumed by the last
        #: :meth:`propagate` call. Recorded so callers can assert convergence.
        self.iterations: int = 0
        #: Tainted parameters per function, filled in by :meth:`propagate`.
        self.tainted: dict[str, set[int]] = {}
        #: ``{function: {parameter index: responsible entry points}}``.
        self.provenance: dict[str, dict[int, set[str]]] = {}

    # ---------------------------------------------------------------- build
    @classmethod
    def build(cls, file_traces: Sequence) -> CallGraph:
        """Build a call graph from a sequence of ``FileTrace`` objects."""
        graph = cls()
        for file_trace in sorted(file_traces, key=lambda t: t.path or ""):
            graph._add_file(file_trace)
        return graph

    def _add_file(self, file_trace) -> None:
        """Index every function in one file and record its call edges."""
        path = file_trace.path
        self.module_traces.extend(file_trace.module_traces)

        for func in file_trace.functions:
            # Class context is not tracked by the front end, so the qualified
            # name is the plain function name. Two definitions sharing a name
            # are merged rather than silently dropped.
            qualname = func.name
            summary = FunctionSummary(
                name=func.name,
                qualname=qualname,
                file=path,
                lineno=func.lineno,
                param_count=len(func.arg_positions),
                var_origins=dict(func.symbolic_origins),
                returns_params=tuple(func.returns_param_indices),
                invocations=list(func.invocations),
            )
            for trace in func.traces:
                params = set()
                for origin in getattr(trace, "param_indices", ()) or ():
                    params.add(int(origin))
                sink = trace.sink
                summary.sink_params.setdefault(sink, set())
                summary.sink_params[sink] = params  # type: ignore[assignment]
                if not params:
                    summary.self_origins.update(trace.origins)
                elif len(trace.origins) == 1 and Origin.PARAM in trace.origins:
                    # Parameter-only flow: nothing external was observed inside
                    # this function, so ``self_origins`` stays empty and
                    # reachability is decided entirely by the caller.
                    pass
                if trace.kills:
                    summary.sink_protected.setdefault(sink, set()).update(trace.kills)
            summary.sink_params = {k: tuple(sorted(v)) for k, v in summary.sink_params.items()}
            existing = self.summaries.get(qualname)
            if existing is None:
                self.summaries[qualname] = summary
            else:
                # Two definitions with one name (a conditional redefinition, or a
                # stub plus an implementation). Merge rather than silently drop
                # one, and record the ambiguity so the report can say so.
                self._merge_summaries(existing, summary)

            self.traces_by_sink.setdefault(qualname, []).extend(func.traces)

    def _merge_summaries(self, existing: FunctionSummary, incoming: FunctionSummary) -> None:
        """Merge two summaries that share a qualified name."""
        existing.var_origins.update(incoming.var_origins)
        existing.returns_params = tuple(
            sorted(set(existing.returns_params) | set(incoming.returns_params))
        )
        existing.self_origins |= incoming.self_origins
        existing.param_count = max(existing.param_count, incoming.param_count)
        existing.invocations.extend(incoming.invocations)
        for sink, params in incoming.sink_params.items():
            merged = set(existing.sink_params.get(sink, ())) | set(params)
            existing.sink_params[sink] = tuple(sorted(merged))
        for sink, kills in incoming.sink_protected.items():
            existing.sink_protected.setdefault(sink, set()).update(kills)
        existing.lineno = min(existing.lineno or incoming.lineno,
                              incoming.lineno or existing.lineno)

    # ------------------------------------------------------------- querying
    def callees(self) -> set[str]:
        """Names that are called somewhere in the analysed set."""
        called: set[str] = set()
        for summary in self.summaries.values():
            for callee, _line, _origins, _kwargs in summary.invocations:
                called.add(self.resolve(callee) or callee)
        return called

    def callers(self) -> set[str]:
        """Names that are never called from inside the analysed set."""
        return set(self.summaries) - self.callees()

    def entry_points(self) -> list[str]:
        """Entry-point names, sorted for determinism."""
        return sorted(self.callers())

    def resolve(self, call_name: str) -> str | None:
        """Resolve a call name to a known function, honouring ``self``/``cls``."""
        if call_name in self.summaries:
            return call_name
        tail = call_name.rpartition(".")[2]
        if tail in self.summaries:
            return tail
        for qualname in sorted(self.summaries):
            if qualname.rpartition(".")[2] == tail:
                return qualname
        return None

    # ----------------------------------------------------------- fixed point
    def propagate(self) -> dict[str, set[int]]:
        """Compute tainted parameters per function by monotone fixed point.

        Alongside the tainted set, records *provenance*: which entry points are
        responsible for tainting each parameter. Provenance is what lets the
        resolver emit a path from a real entry point instead of asserting that
        every helper is reachable.

        Returns:
            ``{qualified name: set of tainted parameter indices}``.
        """
        tainted: dict[str, set[int]] = {}
        provenance: dict[str, dict[int, set[str]]] = {}

        for name in self.entry_points():
            summary = self.summaries[name]
            tainted[name] = set(range(summary.param_count))
            provenance[name] = {
                index: {name} for index in range(summary.param_count)
            }

        changed = True
        iterations = 0
        max_iterations = max(8, 2 * len(self.summaries) + 8)
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for name in sorted(self.summaries):
                caller = self.summaries[name]
                caller_tainted = tainted.get(name, set())
                if not caller_tainted:
                    continue
                for callee_name, _line, arg_origins, arg_slots in caller.invocations:
                    target = self.resolve(callee_name)
                    if target is None:
                        continue
                    target_summary = self.summaries[target]
                    incoming = set(tainted.get(target, set()))
                    incoming_sources: dict[int, set[str]] = {}

                    for position, origins in enumerate(arg_origins):
                        if position >= len(arg_slots):
                            continue
                        index, _keyword = arg_slots[position]
                        sources: set[str] = set()
                        if index is None:
                            # Splatted argument: every parameter of the callee is
                            # reachable through it.
                            for position_index in range(target_summary.param_count):
                                sources |= _origin_sources(
                                    origins, caller_tainted, provenance.get(name, {})
                                )
                                if sources:
                                    incoming.add(position_index)
                                    incoming_sources.setdefault(
                                        position_index, set()
                                    ).update(sources)
                            continue
                        if not _origins_reach_taint(origins, caller_tainted):
                            continue
                        sources = _origin_sources(
                            origins, caller_tainted, provenance.get(name, {})
                        )
                        if not sources:
                            # The argument carries a self-seeded external origin
                            # (a request object, the environment). The caller is
                            # then itself the entry point for this flow.
                            sources = {name}
                        incoming.add(index)
                        incoming_sources.setdefault(index, set()).update(sources)

                    if not incoming <= tainted.get(target, set()):
                        tainted[target] = incoming
                        changed = True
                    if target not in provenance:
                        provenance[target] = {}
                    for index, sources in incoming_sources.items():
                        bucket = provenance[target].setdefault(index, set())
                        if not sources <= bucket:
                            bucket |= sources
                            changed = True

        self.tainted = tainted
        self.provenance = provenance
        self.iterations = iterations
        return tainted

    def resolve_traces(self) -> list[CrossFunctionTrace]:
        """Emit one :class:`CrossFunctionTrace` per entry-point-reachable flow.

        A flow is emitted only when a *named entry point* is responsible for the
        taint that reaches the sink. A helper that is never called, or is only
        ever called with clean values, produces nothing.
        """
        self.propagate()
        provenance = self.provenance
        emitted: list[CrossFunctionTrace] = []

        for sink_fn in sorted(self.summaries):
            summary = self.summaries[sink_fn]
            sink_params = self.summaries[sink_fn].sink_params
            for sink in sorted(sink_params):
                params = set(sink_params[sink])
                tainted_here = params & set(self.tainted.get(sink_fn, set()))
                if tainted_here:
                    # Which entry points are responsible for each tainted
                    # parameter? Provenance answers this without guessing.
                    responsible: dict[str, set[int]] = {}
                    for index in tainted_here:
                        for entry in provenance.get(sink_fn, {}).get(index, set()):
                            responsible.setdefault(entry, set()).add(index)
                    for entry in sorted(responsible):
                        emitted.append(
                            self._compose(
                                entry, sink_fn, sink, sorted(responsible[entry])
                            )
                        )
                    continue
                if not params and summary.self_origins:
                    # The flow is seeded inside this function by an external
                    # read (a request object, the environment, stdin) rather than
                    # by a tainted parameter, so the function is its own entry.
                    emitted.append(self._compose(sink_fn, sink_fn, sink, []))

        emitted.sort(key=lambda t: (t.entry_file, t.entry_line, t.sink, t.trace_id))
        return emitted

    def _compose(
        self, entry: str, sink_fn: str, sink: str, params: Sequence[int]
    ) -> CrossFunctionTrace:
        """Build one composed trace from an entry point to a sink in ``sink_fn``."""
        entry_summary = self.summaries[entry]
        sink_summary = self.summaries[sink_fn]

        target: Trace | None = None
        for candidate in self.traces_by_sink.get(sink_fn, []):
            if candidate.sink != sink:
                continue
            if set(params) and set(candidate.param_indices) & set(params):
                target = candidate
                break
        if target is None:
            for candidate in self.traces_by_sink.get(sink_fn, []):
                if candidate.sink == sink:
                    target = candidate
                    break

        chain = self._chain(entry, sink_fn)
        if target is None:
            cwe = ""
            category = ""
            sink_call = sink
            sink_line = 0
            kills: tuple[str, ...] = ()
            confidence = 0.5
            origins: tuple[str, ...] = tuple(sorted(sink_summary.self_origins))
        else:
            steps = target.steps
            cwe = target.cwe
            category = target.category
            sink_call = target.sink_call
            sink_line = target.sink_line
            kills = target.kills
            confidence = target.confidence
            origins = target.origins

        if params:
            origin_steps = tuple(
                TraceStep(
                    entry_summary.lineno, 0, STEP_KIND_SOURCE, EDGE_PARAM,
                    _param_name(entry_summary, index),
                )
                for index in params
            )
        elif origins:
            origin_steps = (
                TraceStep(
                    entry_summary.lineno, 0, STEP_KIND_SOURCE, EDGE_PARAM,
                    " / ".join(origins),
                ),
            )
        else:
            origin_steps = ()
        bridge = tuple(
            TraceStep(entry_summary.lineno, 0, STEP_KIND_PROPAGATE, EDGE_CALL, name)
            for name in chain[1:]
        )
        composed = origin_steps + bridge + steps
        discount = max(0, len(composed) - 4) * 0.01
        confidence = max(0.5, confidence - discount)

        return CrossFunctionTrace(
            trace_id=_compose_id(entry, sink_fn, sink, params),
            cwe=cwe,
            category=category,
            sink=sink,
            sink_call=sink_call,
            sink_file=sink_summary.file,
            sink_line=sink_line,
            chain=tuple(chain),
            entry_file=entry_summary.file,
            entry_line=entry_summary.lineno,
            origins=origins,
            param_indices=tuple(params),
            steps=composed,
            kills=kills,
            confidence=round(confidence, 4),
        )

    def _chain(self, entry: str, target: str) -> list[str]:
        """Recover one concrete call path from ``entry`` to ``target``."""
        if entry == target:
            return [entry]
        summary = self.summaries.get(entry)
        if summary is None:
            return [entry, target]
        for callee_name, _line, _origins, _slots in summary.invocations:
            resolved = self.resolve(callee_name)
            if resolved is None:
                continue
            tail = self._chain(resolved, target)
            if tail and tail[0] == resolved:
                return [entry] + tail
        return [entry, target]


def _param_name(summary: FunctionSummary, index: int) -> str:
    """Best-effort display name for parameter ``index`` of a function."""
    for name, origins in sorted(summary.var_origins.items()):
        if f"PARAM#{index}" in origins:
            return name
    return f"arg{index}"


def _origin_sources(
    origins: Sequence[str],
    caller_tainted: set[int],
    caller_provenance: Mapping[int, set[str]],
) -> set[str]:
    """Entry points responsible for tainting an argument.

    A ``PARAM#k`` origin contributes the provenance of that parameter in the
    caller; an external origin contributes the caller itself, because a value
    read from the request or the environment originates there.
    """
    sources: set[str] = set()
    for origin in origins:
        if origin.startswith("PARAM#"):
            index = _param_index(origin)
            if index is not None and index in caller_tainted:
                sources |= caller_provenance.get(index, set())
        elif origin and origin != Origin.GLOBAL:
            sources.add("__external__")
    return sources

    def _chain(
        self, entry: str, target: str, tainted: Mapping[str, set[int]]
    ) -> list[str]:
        """Recover one concrete call path from ``entry`` to ``target``."""
        if entry == target:
            return [entry]
        summary = self.summaries.get(entry)
        if summary is None:
            return [target]
        for callee_name, _line, _origins, _slots in summary.invocations:
            resolved = self.resolve(callee_name)
            if resolved is None:
                continue
            tail = self._chain(resolved, target, tainted)
            if tail and tail[0] == resolved:
                return [entry] + tail
        return [entry, target]


def _compose_id(entry: str, sink_fn: str, sink: str, params: Iterable[int]) -> str:
    """Stable identity for a composed trace, independent of line numbers."""
    import hashlib

    key = "{}|{}|{}|{}".format(
        entry, sink_fn, sink, ",".join(str(p) for p in sorted(params))
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _origins_reach_taint(origins: Sequence[str], caller_tainted: set[int]) -> bool:
    """True when an argument's origins reach a parameter that is already tainted.

    An origin is either ``PARAM#<i>`` -- tainted when ``i`` is in
    ``caller_tainted`` -- or an external source such as ``REQUEST``. ``GLOBAL``
    is process state rather than an external input, so it does not taint a
    callee parameter on its own.
    """
    for origin in origins:
        if origin.startswith("PARAM#"):
            index = _param_index(origin)
            if index is not None and index in caller_tainted:
                return True
        elif origin and origin != Origin.GLOBAL:
            return True
    return False


def _resolve_callee(call_name: str) -> str:
    """Normalise a recorded call name for edge keys."""
    return call_name


__all__ = [
    "CallGraph",
    "CrossFunctionTrace",
    "FunctionSummary",
]
