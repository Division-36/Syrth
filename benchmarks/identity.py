"""Identity stability under renaming.

``risk_metrics.rename_invariance`` answers a narrow question: does the *set of
reported classes* survive renaming. It does, trivially, because a class is named
from a sink contact whether or not a flow was confirmed.

The stronger claim is that the certificate's ``trace_id`` survives renaming, and
that one is not free: the key includes the origin set and the enclosing function
name, both of which can be name-derived. Renaming a parameter that was recognised
as a request object changes its origin label from ``REQUEST`` to ``PARAM``; renaming
a function changes the scope the key is computed in.

This harness measures all three scopes separately so the paper can report the
distinction instead of blurring it:

``parameters``
    Only parameter names, ``self``/``cls`` excluded. A flow that depends on a
    parameter's spelling shows up here.
``functions``
    Only function definition names. Identity is expected to change: the function
    scopes the flow by design.
``all``
    ``alpha_rename`` -- every renameable identifier, which is the transform the
    published rename-invariance metric uses.

Usage::

    python -m benchmarks.identity --dataset data/corpus.jsonl
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import pathlib
import random
import tokenize
from collections.abc import Iterable
from typing import Any

from benchmarks.run_benchmarks import (
    _significant_tokens,
    alpha_rename,
    import_bound_names,
    load_records,
)
from syrth.scan import SyrthScanner

# ---------------------------------------------------------------------------
# Selective renaming
# ---------------------------------------------------------------------------


def _rewrite(source: str, table: dict[str, str]) -> str:
    """Apply ``table`` to identifiers, leaving attributes, kwargs and imports."""
    if not table:
        return source
    import_bound = import_bound_names(source)
    classified = _significant_tokens(source)
    by_offset = {
        token.start: table[token.string]
        for token, in_import, after_as, after_dot, kwarg in classified
        if token.type == tokenize.NAME
        and token.string in table
        and token.string not in import_bound
        and not after_dot
        and not kwarg
        and (not in_import or after_as)
    }
    if not by_offset:
        return source
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    pieces = [
        (token.type, by_offset.get(token.start, token.string), token.start,
         token.end, token.line)
        for token in tokens
    ]
    try:
        return tokenize.untokenize(pieces)
    except (ValueError, IndexError):  # pragma: no cover - tokenizer invariant
        return source


def _fresh_table(names: Iterable[str], seed: int) -> dict[str, str]:
    unique = sorted(set(names))
    rng = random.Random(seed)
    return {name: f"zz{i}_{rng.randrange(16 ** 6):06x}" for i, name in enumerate(unique)}


def _parameter_names(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for arg in (
                list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
            ):
                found.add(arg.arg)
    return found - {"self", "cls"}


def _function_names(source: str) -> set[str]:
    return {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name not in {"__init__", "__call__"}
    }


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def _fingerprint(report: Any) -> dict[str, Any]:
    confirmed = [f for f in report.findings if f.detector != "pattern"]
    return {
        "classes": frozenset(f.cwe for f in report.findings),
        "identities": sorted(f.trace_id for f in confirmed),
        "origins": sorted(tuple(f.origins) for f in confirmed),
        "confirmed": len(confirmed),
    }


def _scope(name: str, source: str, seed: int) -> str | None:
    if name == "all":
        renamed = alpha_rename(source, seed)
        return renamed if renamed != source else None
    try:
        names = _parameter_names(source) if name == "parameters" else _function_names(source)
    except SyntaxError:
        return None
    renamed = _rewrite(source, _fresh_table(names, seed))
    return renamed if renamed != source else None


def measure(dataset: str, seed: int = 42) -> dict[str, Any]:
    records = load_records(dataset)
    scanner = SyrthScanner()
    scopes = ("parameters", "functions", "all")
    stats = {
        scope: {
            "checked": 0,
            "classes_stable": 0,
            "identities_stable": 0,
            "origins_stable": 0,
            "confirmed_before": 0,
            "confirmed_after": 0,
        }
        for scope in scopes
    }

    for record in records:
        before = _fingerprint(scanner.scan_source(record.source, record.group))
        for scope in scopes:
            renamed = _scope(scope, record.source, seed)
            if renamed is None:
                continue
            after = _fingerprint(scanner.scan_source(renamed, record.group))
            row = stats[scope]
            row["checked"] += 1
            row["classes_stable"] += before["classes"] == after["classes"]
            row["identities_stable"] += before["identities"] == after["identities"]
            row["origins_stable"] += before["origins"] == after["origins"]
            row["confirmed_before"] += before["confirmed"]
            row["confirmed_after"] += after["confirmed"]

    return {"dataset": dataset, "seed": seed, "scopes": stats}


def _render(result: dict[str, Any]) -> str:
    lines = [
        f"{'scope':<12} {'records':>8} {'classes':>10} {'identities':>12} "
        f"{'origins':>10} {'flows':>12}",
        "-" * 70,
    ]
    for scope, row in result["scopes"].items():
        checked = row["checked"]
        lines.append(
            f"{scope:<12} {checked:>8} "
            f"{row['classes_stable']:>4}/{checked:<5} "
            f"{row['identities_stable']:>4}/{checked:<7} "
            f"{row['origins_stable']:>4}/{checked:<5} "
            f"{row['confirmed_before']:>5}->{row['confirmed_after']:<6}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure identity stability.")
    parser.add_argument("--dataset", required=True, help="JSONL of records")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", default=None, help="write the table here")
    args = parser.parse_args(argv)

    result = measure(args.dataset, args.seed)
    print("=" * 70)
    print("Certificate identity under renaming")
    print("=" * 70)
    print(_render(result))

    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
