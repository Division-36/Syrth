"""Component ablation for the risk-model contract.

The five metrics in :mod:`benchmarks.risk_metrics` are computed by a pipeline
with four analysis decisions that could each be responsible for the result:

*   per-sink argument schemas (which arguments are dangerous),
*   category-typed sanitisers (what a kill neutralises),
*   guard evidence (inline guards and containment checks),
*   position-seeded parameters (every parameter is a source).

This module disables one decision at a time and re-measures. It is the
difference between "the contract reports 111/116" and "the contract reports
111/116 *because* of these four rules", which is the question a reader of the
paper actually has.

Each variant patches at run time; nothing in the product is conditional on this
file except the :func:`syrth.parser.python.parameter_is_source` seam, which is
documented as existing for exactly this purpose.

Usage::

    python -m benchmarks.ablation --dataset data/corpus.jsonl
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import json
import pathlib
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from benchmarks import risk_metrics
from benchmarks.run_benchmarks import load_records
from syrth import registry
from syrth.parser import python as pyparser
from syrth.scan import SyrthScanner

# ---------------------------------------------------------------------------
# Variants
# ---------------------------------------------------------------------------


@contextmanager
def _patched(target: Any, attribute: str, replacement: Any) -> Iterator[None]:
    """Set ``target.attribute`` for the duration of the block."""
    original = getattr(target, attribute)
    setattr(target, attribute, replacement)
    try:
        yield
    finally:
        setattr(target, attribute, original)


def _always_dangerous_position(self: Any, index: int) -> bool:
    return True


def _always_dangerous_keyword(self: Any, name: str | None) -> bool:
    return True


def _untyped_kill_for(original: Callable[..., Any]) -> Callable[..., Any]:
    """A ``kill_for`` that neutralises every category, not just its own."""
    every_category = frozenset(registry.CATEGORIES)

    def kill_for(call_name: str, bindings: Any = None) -> Any:
        spec = original(call_name, bindings)
        if spec is None:
            return None
        return dataclasses.replace(spec, kills=every_category)

    return kill_for


_REQUESTISH = frozenset(
    {"request", "req", "data", "payload", "body", "form", "params", "query"}
)


def _looks_external(name: str) -> bool:
    """The name-based rule a naive analyser would use."""
    lowered = name.lower()
    return lowered in _REQUESTISH or lowered.startswith(("request", "req_"))


def _no_guards(self: Any, node: Any, raw: bytes) -> None:
    return None


@contextmanager
def variant(name: str) -> Iterator[None]:
    """Apply one ablation, or none for ``"full"``."""
    if name == "full":
        yield
        return

    if name == "no-schemas":
        with _patched(
            registry.SinkSpec, "is_dangerous_position", _always_dangerous_position
        ), _patched(
            registry.SinkSpec, "is_dangerous_keyword", _always_dangerous_keyword
        ):
            yield
        return

    if name == "untyped-kills":
        with _patched(
            pyparser, "kill_for", _untyped_kill_for(pyparser.kill_for)
        ), _patched(
            registry, "kill_for", _untyped_kill_for(registry.kill_for)
        ):
            yield
        return

    if name == "no-guards":
        import syrth.scan as scan_module

        with _patched(
            pyparser.PythonParser, "_apply_guards", _no_guards
        ), _patched(
            scan_module, "_containment_evidence", lambda file_trace: {}
        ):
            yield
        return

    if name == "no-inline-guards":
        with _patched(pyparser.PythonParser, "_apply_guards", _no_guards):
            yield
        return

    if name == "no-containment":
        import syrth.scan as scan_module

        with _patched(
            scan_module, "_containment_evidence", lambda file_trace: {}
        ):
            yield
        return

    if name == "name-sources":
        with _patched(pyparser, "parameter_is_source", _looks_external):
            yield
        return

    if name == "no-interproc":
        with _patched(
            risk_metrics,
            "SyrthScanner",
            functools.partial(SyrthScanner, interprocedural=False),
        ):
            yield
        return

    raise ValueError(f"unknown variant: {name}")


VARIANT_ORDER = (
    "full",
    "no-schemas",
    "untyped-kills",
    "no-inline-guards",
    "no-containment",
    "no-guards",
    "name-sources",
    "no-interproc",
)


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def _spurious(outcomes: Any) -> tuple[int, int]:
    """Classes named with no sink in the source, over classes named."""
    spurious = sum(len(outcome.spurious) for outcome in outcomes)
    reported = sum(len(outcome.reported) for outcome in outcomes)
    return spurious, reported


def _cross_function(records: Any, interprocedural: bool) -> int:
    """Traces resolved across function boundaries, by mode."""
    scanner = SyrthScanner(interprocedural=interprocedural)
    total = 0
    for record in records:
        report = scanner.scan_source(record.source, record.group)
        total += len(report.cross_function)
    return total


def run(dataset: str, variants: tuple[str, ...] = VARIANT_ORDER) -> dict[str, Any]:
    records = load_records(dataset)
    rows: dict[str, Any] = {}

    for name in variants:
        started = time.perf_counter()
        with variant(name):
            metrics, outcomes = risk_metrics.evaluate(records)
        elapsed = time.perf_counter() - started
        spurious, reported = _spurious(outcomes)
        rows[name] = {
            "records": metrics.records,
            "coverage": [metrics.covered_classes, metrics.expected_classes],
            "coverage_rate": round(metrics.category_coverage, 4),
            "spurious": [spurious, reported],
            "rank": [metrics.rank_agreements, metrics.rank_pairs],
            "rename": [metrics.rename_stable, metrics.rename_checked],
            "kill": [metrics.patch_kills, metrics.patch_attempts],
            "determinism": [
                metrics.determinism_agreements,
                metrics.determinism_checks,
            ],
            "seconds": round(elapsed, 3),
        }

    rows["interprocedural"] = {
        "cross_function_on": _cross_function(records, True),
        "cross_function_off": _cross_function(records, False),
    }
    return {"dataset": dataset, "rows": rows}


def _render(result: dict[str, Any]) -> str:
    lines = [
        f"{'variant':<18} {'coverage':>10} {'spurious':>9} {'rename':>8} "
        f"{'kill':>8} {'det':>8} {'sec':>7}",
        "-" * 76,
    ]
    for name, row in result["rows"].items():
        if name == "interprocedural":
            continue
        coverage = f"{row['coverage'][0]}/{row['coverage'][1]}"
        spurious = f"{row['spurious'][0]}/{row['spurious'][1]}"
        rename = f"{row['rename'][0]}/{row['rename'][1]}"
        kill = f"{row['kill'][0]}/{row['kill'][1]}"
        det = f"{row['determinism'][0]}/{row['determinism'][1]}"
        lines.append(
            f"{name:<18} {coverage:>10} {spurious:>9} {rename:>8} "
            f"{kill:>8} {det:>8} {row['seconds']:>7.1f}"
        )
    inter = result["rows"]["interprocedural"]
    lines.append("")
    lines.append(
        "cross-function traces: "
        f"{inter['cross_function_on']} with the call graph, "
        f"{inter['cross_function_off']} without"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ablate the analyser's decisions.")
    parser.add_argument("--dataset", required=True, help="JSONL of records")
    parser.add_argument("--json", default=None, help="write the table here")
    parser.add_argument(
        "--variants",
        default=",".join(VARIANT_ORDER),
        help="comma-separated subset of variants",
    )
    args = parser.parse_args(argv)

    variants = tuple(v.strip() for v in args.variants.split(",") if v.strip())
    result = run(args.dataset, variants)
    print(_render(result))

    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
