"""
SYRTH Trace Certificate
=======================
A :class:`Trace` is a *verifiable statement* that untrusted data reaches a
dangerous operation, together with the evidence for it.

This is the primitive the rest of the product is built on:

*   :mod:`syrth.diff` compares traces between two revisions to answer "did this
    patch remove the flow, introduce a new one, or leave it dangling?".
*   Reports render a trace as a source-to-sink path rather than a bare label.
*   ``syrth.patch`` consumes traces to propose and mechanically verify fixes.

Identity
--------
A trace's identity (:attr:`Trace.trace_id`) is computed from the *structural*
content of the flow -- function name, canonical sink, sink argument position,
taint-origin set and the sequence of propagation edges. Line numbers are
deliberately **excluded**, so a trace keeps its identity when unrelated lines
are inserted above it. That is what makes revision-to-revision comparison
usable in a real repository.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

#: Bumped whenever the on-disk shape of a trace changes. Consumers must refuse
#: to mix traces of different major versions during a diff.
SCHEMA_VERSION = 3

#: Edge kinds recorded on a propagation step.
EdgeKind = str

EDGE_PARAM = "param"
EDGE_ASSIGN = "assign"
EDGE_ATTR_ASSIGN = "attr-assign"
EDGE_AUG_ASSIGN = "aug-assign"
EDGE_CONCAT = "concat"
EDGE_FSTRING = "fstring"
EDGE_FORMAT = "format"
EDGE_PERCENT = "percent"
EDGE_INDEX = "index"
EDGE_ATTR = "attr"
EDGE_BRANCH = "branch"
EDGE_CALL = "call"
EDGE_ITER = "iter"
EDGE_WITH = "with"
EDGE_COMPREHENSION = "comprehension"
EDGE_RETURN = "return"
EDGE_ARG = "arg"

STEP_KIND_SOURCE = "source"
STEP_KIND_PROPAGATE = "propagate"
STEP_KIND_SANITIZE = "sanitize"
STEP_KIND_SINK = "sink"
#: Marks a *guard*: a conditional that constrains a value without sanitising
#: it. Emitted with a detail of ``allowlist``/``denylist``/``equality`` and the
#: variable name, so the strength travels with the value through every
#: propagation that copies the step list.
STEP_KIND_GUARD = "guard"

#: Detector identifiers. ``taint`` means an external origin reached the sink;
#: ``amplifier`` means a sanitiser-like assertion created the sink.
DETECTOR_TAINT = "taint"
DETECTOR_AMPLIFIER = "amplifier"
DETECTOR_PATTERN = "pattern"
DETECTOR_ML = "ml"


@dataclass(frozen=True, order=True)
class TraceStep:
    """One step of a source-to-sink path.

    Ordered so that two paths can be compared lexicographically when the taint
    engine picks the most explanatory one; that makes the choice independent of
    the order the operands happened to be visited in.

    Attributes:
        line: 1-indexed source line.
        column: 0-indexed source column.
        kind: One of ``source``/``propagate``/``sanitize``/``sink``.
        edge: The propagation edge, e.g. ``fstring`` or ``arg:0``.
        detail: Rendered expression text, truncated for report stability.
    """

    line: int
    column: int
    kind: str
    edge: EdgeKind
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "edge": self.edge,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TraceStep:
        return cls(
            line=int(data.get("line", 0)),
            column=int(data.get("column", 0)),
            kind=str(data.get("kind", STEP_KIND_PROPAGATE)),
            edge=str(data.get("edge", "")),
            detail=str(data.get("detail", "")),
        )


def _normalise_text(text: str, limit: int = 80) -> str:
    """Collapse whitespace and truncate, so detail text cannot affect identity."""
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "…"
    return collapsed


@dataclass(frozen=True)
class Trace:
    """A single source-to-sink finding with its supporting evidence.

    Attributes:
        function: Enclosing function name.
        lineno: 1-indexed line of the function definition.
        cwe: CWE identifier, e.g. ``CWE-89``.
        category: Sink category, e.g. ``SQL``.
        sink: Canonical sink name, e.g. ``SQL_EXECUTE``.
        sink_call: The call as written, e.g. ``cursor.execute``.
        sink_line: 1-indexed line of the sink call.
        sink_arg: How the data entered the sink, e.g. ``pos:0``/``kw:sql``.
        origins: Sorted taint-origin set that reached the sink.
        steps: The propagation path, source first, sink last.
        kills: Sanitisers observed on the path. A non-empty list with a
            ``full`` kill would have suppressed the finding, so its presence
            here always means the kill was partial or applied to a different
            argument.
        confidence: Calibrated-ish score in ``[0, 1]``. For taint findings this
            is structural, not a vote share.
        detector: Which detector produced the trace.
        file: Source path, when known.
        notes: Human-facing remarks.
        param_indices: Indices of the enclosing function's parameters that carry
            the taint. Recorded so the interprocedural layer can decide whether a
            flow is reachable from a caller's tainted argument.
        call_chain: Enclosing function names traversed to reach this sink, for
            flows that cross more than one function.
    """

    function: str
    lineno: int
    cwe: str
    category: str
    sink: str
    sink_call: str
    sink_line: int
    sink_arg: str
    origins: tuple[str, ...] = ()
    steps: tuple[TraceStep, ...] = ()
    kills: tuple[str, ...] = ()
    confidence: float = 0.0
    detector: str = DETECTOR_TAINT
    file: str = ""
    notes: tuple[str, ...] = ()
    param_indices: tuple[int, ...] = ()
    call_chain: tuple[str, ...] = ()

    # ------------------------------------------------------------------ id
    def structural_key(self) -> str:
        """Identity key that ignores line numbers.

        Two analyses of the same flow in the same function produce the same key
        even when the file has shifted, which is exactly the property a
        revision diff needs.
        """
        parts = [
            self.function,
            self.sink,
            self.sink_arg,
            ",".join(self.origins),
            ",".join(step.edge for step in self.steps),
        ]
        return "\x1f".join(parts)

    @property
    def trace_id(self) -> str:
        """Stable 16-hex-character identifier derived from :meth:`structural_key`."""
        return hashlib.sha256(self.structural_key().encode("utf-8")).hexdigest()[:16]

    @property
    def location_key(self) -> str:
        """Location-sensitive key, used to distinguish repeated flows."""
        return f"{self.trace_id}:{self.sink_line}"

    # ------------------------------------------------------------- render
    def render(self) -> str:
        """Render the source-to-sink path as a human-readable block."""
        lines = [f"{self.cwe} [{self.category}] in {self.function}() (line {self.lineno})"]
        if self.file:
            lines[0] = f"{lines[0]}  [{self.file}]"
        for step in self.steps:
            marker = {
                STEP_KIND_SOURCE: ">>",
                STEP_KIND_PROPAGATE: "  ",
                STEP_KIND_SANITIZE: "//",
                STEP_KIND_SINK: "<<",
            }.get(step.kind, "  ")
            detail = f"  {step.detail}" if step.detail else ""
            lines.append(f"  {marker} L{step.line:<5} {step.edge:<16}{detail}")
        lines.append(
            f"  origin(s): {', '.join(self.origins) or 'n/a'}"
            f"   arg: {self.sink_arg}   detector: {self.detector}"
            f"   confidence: {self.confidence:.2f}"
        )
        if self.kills:
            lines.append(f"  sanitiser(s) seen on path: {', '.join(self.kills)}")
        for note in self.notes:
            lines.append(f"  ! {note}")
        return "\n".join(lines)

    def summary(self) -> str:
        """One-line summary suitable for grep and SARIF messages."""
        return (
            f"{self.cwe} {self.category} sink '{self.sink}' reached from "
            f"{'/'.join(self.origins) or 'unknown origin'} via {self.sink_arg}"
        )

    # -------------------------------------------------------- (de)serialise
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "file": self.file,
            "function": self.function,
            "lineno": self.lineno,
            "cwe": self.cwe,
            "category": self.category,
            "sink": self.sink,
            "sink_call": self.sink_call,
            "sink_line": self.sink_line,
            "sink_arg": self.sink_arg,
            "origins": list(self.origins),
            "steps": [step.to_dict() for step in self.steps],
            "kills": list(self.kills),
            "confidence": round(float(self.confidence), 6),
            "detector": self.detector,
            "notes": list(self.notes),
            "param_indices": list(self.param_indices),
            "call_chain": list(self.call_chain),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Trace:
        schema = int(data.get("schema", 0))
        if schema != SCHEMA_VERSION:
            raise ValueError(
                f"Trace schema {schema} is not supported (expected {SCHEMA_VERSION})"
            )
        return cls(
            function=str(data.get("function", "")),
            lineno=int(data.get("lineno", 0)),
            cwe=str(data.get("cwe", "")),
            category=str(data.get("category", "")),
            sink=str(data.get("sink", "")),
            sink_call=str(data.get("sink_call", "")),
            sink_line=int(data.get("sink_line", 0)),
            sink_arg=str(data.get("sink_arg", "")),
            origins=tuple(str(o) for o in data.get("origins", ())),
            steps=tuple(TraceStep.from_dict(s) for s in data.get("steps", ())),
            kills=tuple(str(k) for k in data.get("kills", ())),
            confidence=float(data.get("confidence", 0.0)),
            detector=str(data.get("detector", DETECTOR_TAINT)),
            file=str(data.get("file", "")),
            notes=tuple(str(n) for n in data.get("notes", ())),
            param_indices=tuple(int(i) for i in data.get("param_indices", ())),
            call_chain=tuple(str(c) for c in data.get("call_chain", ())),
        )

    def with_confidence(self, confidence: float) -> Trace:
        """Return a copy carrying a different confidence."""
        return replace(self, confidence=float(confidence))

    def with_file(self, file: str) -> Trace:
        """Return a copy attributed to a different file path."""
        return replace(self, file=file)


def sort_traces(traces: Iterable[Trace]) -> list[Trace]:
    """Deterministic ordering: by file, then line, then identity."""
    return sorted(
        traces,
        key=lambda t: (t.file, t.lineno, t.sink_line, t.sink, t.trace_id),
    )


def traces_to_json(traces: Sequence[Trace], indent: int | None = 2) -> str:
    """Serialise traces to a JSON document."""
    return json.dumps([t.to_dict() for t in traces], indent=indent, sort_keys=True)


def traces_from_json(payload: str) -> list[Trace]:
    """Deserialise traces from a JSON document."""
    data = json.loads(payload)
    if isinstance(data, Mapping):
        data = data.get("traces", [])
    return [Trace.from_dict(item) for item in data]


__all__ = [
    "SCHEMA_VERSION",
    "EDGE_ARG",
    "EDGE_ASSIGN",
    "EDGE_ATTR",
    "EDGE_ATTR_ASSIGN",
    "EDGE_AUG_ASSIGN",
    "EDGE_BRANCH",
    "EDGE_CALL",
    "EDGE_COMPREHENSION",
    "EDGE_CONCAT",
    "EDGE_FORMAT",
    "EDGE_FSTRING",
    "EDGE_INDEX",
    "EDGE_ITER",
    "EDGE_PARAM",
    "EDGE_PERCENT",
    "EDGE_RETURN",
    "EDGE_WITH",
    "STEP_KIND_PROPAGATE",
    "STEP_KIND_SANITIZE",
    "STEP_KIND_SINK",
    "STEP_KIND_SOURCE",
    "DETECTOR_AMPLIFIER",
    "DETECTOR_ML",
    "DETECTOR_PATTERN",
    "DETECTOR_TAINT",
    "Trace",
    "TraceStep",
    "sort_traces",
    "traces_from_json",
    "traces_to_json",
]
