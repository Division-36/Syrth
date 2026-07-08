"""
SYRTH: Scan Your Risk Trace History
====================================
syrth_scan.py — Production inference script.

Modes:
    --mode dev    Loads the .joblib bundle (PyTorch inference).
    --mode fast   Uses the compiled C engine (syrth_engine.h → .so).

Usage:
    python syrth_scan.py --file views.py --mode dev
    python collect.py --single-file views.py | python syrth_scan.py --mode dev
    python syrth_scan.py --file views.py --mode dev --threshold 0.70
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_JOBLIB   = "syrth_model.joblib"
DEFAULT_C_HEADER = "syrth_engine.h"
CONFIDENCE_DISCLAIMER = 0.60

CWE_DESCRIPTIONS: dict[str, str] = {
    "SQLi":          "SQL Injection (CWE-89) — user input reaches raw SQL execution",
    "XSS":           "Cross-Site Scripting (CWE-79) — unsanitised input rendered as HTML",
    "PathTraversal": "Path Traversal (CWE-22) — user input used in filesystem path",
    "OpenRedirect":  "Open Redirect (CWE-601) — user-controlled redirect target",
    "RCE":           "Remote Code Execution (CWE-94) — user input evaluated as code",
}

CWE_IDS: list[str] = [
    "CWE-89", "CWE-79",
    "CWE-22", "CWE-601", "CWE-94",
]

CLASS_NAMES: list[str] = [
    "SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE",
]

# ---------------------------------------------------------------------------
# Inference — DEV mode (joblib)
# ---------------------------------------------------------------------------

def _load_joblib_bundle(path: str) -> dict[str, Any]:
    try:
        import joblib
    except ImportError:
        sys.stderr.write("[SYRTH scan] ERROR: joblib not installed.\n")
        sys.exit(1)
    if not Path(path).exists():
        sys.stderr.write(
            f"[SYRTH scan] ERROR: Model bundle not found: {path}\n"
            "  Run: python train_model.py --dataset _dataset.json\n"
        )
        sys.exit(1)
    return joblib.load(path)


def _dev_predict(tokens: list[str], bundle: dict[str, Any]) -> list[tuple[str, float]]:
    try:
        import torch
        import torch.nn.functional as F
    except ImportError:
        sys.stderr.write("[SYRTH scan] ERROR: PyTorch not installed.\n")
        sys.exit(1)

    sys.path.insert(0, str(Path(__file__).parent))
    from train_model import SyrthEncoder, SyrthTokenizer, MAX_SEQ_LEN

    cfg   = bundle["model_config"]
    vocab = bundle["tokenizer_vocab"]

    tok = SyrthTokenizer()
    tok.vocab    = vocab
    tok._next_id = max(vocab.values()) + 1

    model = SyrthEncoder(
        vocab_size=cfg["vocab_size"],
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg.get("ffn_dim", 128),
        num_classes=cfg["num_classes"],
        dropout=0.0,
    )

    import numpy as np
    state_dict = {
        k: torch.from_numpy(v.astype(np.float32))
        for k, v in bundle["model_state_dict"].items()
    }
    model.load_state_dict(state_dict)
    model.eval()

    ids = tok.encode(tokens)
    x   = torch.tensor([ids], dtype=torch.long)
    with torch.no_grad():
        probs = F.softmax(model(x), dim=-1)[0].numpy()

    return sorted(
        zip(CLASS_NAMES, probs.tolist()),
        key=lambda t: t[1],
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Inference — FAST mode (C engine)
# ---------------------------------------------------------------------------

_C_WRAPPER_TEMPLATE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "{header_path}"

void syrth_run(
    const char** tokens, int num_tokens,
    int* out_class, float* out_conf
) {{
    syrth_predict(tokens, num_tokens, out_class, out_conf);
}}
"""


def _build_fast_engine(header_path: str) -> ctypes.CDLL:
    header  = Path(header_path).resolve()
    so_path = header.parent / "syrth_engine.so"
    needs_compile = (
        not so_path.exists()
        or header.stat().st_mtime > so_path.stat().st_mtime
    )
    if needs_compile:
        wrapper_src = _C_WRAPPER_TEMPLATE.format(header_path=str(header))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as tmp:
            tmp.write(wrapper_src)
            c_path = tmp.name
        try:
            result = subprocess.run(
                ["gcc", "-O2", "-shared", "-fPIC", "-lm", c_path, "-o", str(so_path)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                sys.stderr.write(f"[SYRTH scan] gcc failed:\n{result.stderr}\n")
                sys.exit(1)
        finally:
            Path(c_path).unlink(missing_ok=True)
        sys.stderr.write(f"[SYRTH scan] C engine compiled → {so_path}\n")

    lib = ctypes.CDLL(str(so_path))
    lib.syrth_run.argtypes = [
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_int,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_float),
    ]
    lib.syrth_run.restype = None
    return lib


def _fast_predict(tokens: list[str], lib: ctypes.CDLL) -> list[tuple[str, float]]:
    c_tokens  = (ctypes.c_char_p * len(tokens))(*[t.encode("utf-8") for t in tokens])
    out_class = ctypes.c_int(0)
    out_conf  = ctypes.c_float(0.0)
    lib.syrth_run(c_tokens, len(tokens), ctypes.byref(out_class), ctypes.byref(out_conf))
    class_idx  = out_class.value
    conf       = out_conf.value
    class_name = CLASS_NAMES[class_idx] if 0 <= class_idx < len(CLASS_NAMES) else "Unknown"
    results    = [(class_name, conf)]
    for i, name in enumerate(CLASS_NAMES):
        if i != class_idx:
            results.append((name, 0.0))
    return results


# ---------------------------------------------------------------------------
# Trace helpers
# ---------------------------------------------------------------------------

def _tokens_from_trace(trace: dict[str, Any]) -> list[str]:
    """
    Extract token sequence from a collect.py JSON trace.

    Priority:
    1. Top-level 'tokens' key (new collect.py — combined dataset-compatible sequence)
    2. Per-function 'tokens' aggregation (old collect.py fallback)
    3. Diff mode — vulnerable function tokens
    """
    mode = trace.get("mode", "diff")

    if mode == "single":
        # New collect.py emits 'tokens' at top level (already combined)
        top = trace.get("tokens", [])
        if top:
            return top
        # Fallback: aggregate per-function tokens
        tokens: list[str] = []
        for func in trace.get("functions", []):
            tokens.extend(func.get("tokens", []))
        return tokens

    else:  # diff mode
        tokens = []
        funcs  = trace.get("functions", {})
        for func in funcs.get("removed", []):
            tokens.extend(func.get("tokens", []))
        for func in funcs.get("modified", []):
            tokens.extend(func.get("vulnerable_tokens", []))
        return tokens


def _extract_from_file(source_path: str) -> dict[str, Any]:
    """Run collect.py inline on source_path."""
    collect_script = Path(__file__).parent / "collect.py"
    result = subprocess.run(
        [sys.executable, str(collect_script), "--single-file", source_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"[SYRTH scan] collect.py error:\n{result.stderr}\n")
        sys.exit(1)
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _clean_output(source_label: str, mode: str, as_json: bool) -> None:
    """Emit a clean 'no patterns found' message without running inference."""
    if as_json:
        print(json.dumps({
            "syrth_version": "1.0.0",
            "source": source_label,
            "mode": mode,
            "prediction": None,
            "status": "clean",
            "message": (
                "No security-relevant patterns detected. "
                "File has no analysable sinks or dangerous calls."
            ),
        }, indent=2))
    else:
        print(f"\n{'━' * 56}")
        print(f"  SYRTH: Scan Your Risk Trace History")
        print(f"  Source : {source_label}")
        print(f"  Mode   : {mode.upper()}")
        print(f"{'━' * 56}")
        print(f"  ✓  No security-relevant patterns detected.")
        print(f"     File has no analysable sinks or dangerous calls.")
        print(f"     This may be a model, utility, or config file.")
        print(f"{'━' * 56}\n")


def _print_results(
    results: list[tuple[str, float]],
    source_label: str,
    mode: str,
    threshold: float,
) -> None:
    top_class, top_conf = results[0]

    print(f"\n{'━' * 56}")
    print(f"  SYRTH: Scan Your Risk Trace History")
    print(f"  Source : {source_label}")
    print(f"  Mode   : {mode.upper()}")
    print(f"{'━' * 56}")

    if top_conf < threshold:
        print(
            f"  ⚠  No high-confidence finding (top: {top_class} {top_conf:.0%})\n"
            f"     Confidence below threshold ({threshold:.0%})."
        )
    else:
        cwe_idx  = CLASS_NAMES.index(top_class) if top_class in CLASS_NAMES else -1
        cwe_id   = CWE_IDS[cwe_idx] if 0 <= cwe_idx < len(CWE_IDS) else ""
        cwe_desc = CWE_DESCRIPTIONS.get(top_class, top_class)
        print(f"\n  ► {top_class}: {top_conf:.0%}  [{cwe_id}]")
        print(f"    {cwe_desc}")
        if top_conf < CONFIDENCE_DISCLAIMER:
            print(f"\n  ⚠  Low confidence ({top_conf:.0%}). Manual review recommended.")

    # Secondary findings (dev mode only)
    if mode == "dev" and len(results) > 1:
        non_zero = [(n, c) for n, c in results[1:] if c >= 0.05]
        if non_zero:
            print("\n  Other possibilities:")
            for name, conf in non_zero[:3]:
                print(f"    • {name}: {conf:.0%}")

    print(f"{'━' * 56}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="syrth_scan.py",
        description="SYRTH: Scan Your Risk Trace History — Vulnerability scanner",
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--file", metavar="PATH",
                             help="Python source file to scan")
    input_group.add_argument("--stdin", action="store_true",
                             help="Read trace JSON from stdin")
    parser.add_argument("--mode",      choices=["fast", "dev"], default="dev")
    parser.add_argument("--model",     default=DEFAULT_JOBLIB)
    parser.add_argument("--engine",    default=DEFAULT_C_HEADER)
    parser.add_argument("--threshold", type=float, default=0.40)
    parser.add_argument("--json",      action="store_true")
    args = parser.parse_args()

    if not args.file and not args.stdin:
        if not sys.stdin.isatty():
            args.stdin = True
        else:
            parser.error(
                "Provide --file PATH or pipe trace JSON to stdin.\n"
                "Example: python collect.py --single-file views.py | "
                "python syrth_scan.py --mode dev"
            )

    # ── Load trace ──────────────────────────────────────────────────────────
    if args.file:
        source_label = args.file
        trace = _extract_from_file(args.file)
    else:
        source_label = "<stdin>"
        raw = sys.stdin.read().strip()
        try:
            trace = json.loads(raw)
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"[SYRTH scan] Invalid JSON from stdin: {exc}\n")
            sys.exit(1)

    tokens = _tokens_from_trace(trace)

    # ── Empty tokens → clean exit, no random prediction ─────────────────────
    # This handles: models.py, utils.py, config files, clean utility code.
    if not tokens:
        sys.stderr.write("[SYRTH scan] INFO: No security-relevant tokens found.\n")
        _clean_output(source_label, args.mode, args.json)
        sys.exit(0)

    # ── Run inference ────────────────────────────────────────────────────────
    if args.mode == "dev":
        bundle  = _load_joblib_bundle(args.model)
        results = _dev_predict(tokens, bundle)
    else:
        lib     = _build_fast_engine(args.engine)
        results = _fast_predict(tokens, lib)

    # ── Output ───────────────────────────────────────────────────────────────
    if args.json:
        top_class, top_conf = results[0]
        cwe_idx = CLASS_NAMES.index(top_class) if top_class in CLASS_NAMES else -1
        print(json.dumps({
            "syrth_version": "1.0.0",
            "source": source_label,
            "mode": args.mode,
            "prediction": {
                "class":       top_class,
                "cwe_id":      CWE_IDS[cwe_idx] if cwe_idx >= 0 else "",
                "confidence":  round(top_conf, 4),
                "description": CWE_DESCRIPTIONS.get(top_class, ""),
            },
            "all_classes": [
                {"class": n, "confidence": round(c, 4)}
                for n, c in results
            ],
        }, indent=2))
    else:
        _print_results(results, source_label, args.mode, args.threshold)


if __name__ == "__main__":
    main()
