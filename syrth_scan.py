"""
SYRTH: Scan Your Risk Trace History
====================================
syrth_scan.py — Production inference script with explainability.

Modes:
    --mode dev    Loads the .joblib bundle (PyTorch inference).
    --mode fast   Uses the compiled C engine (syrth_engine.h → .so).

Usage:
    python syrth_scan.py --file views.py --mode dev
    python collect.py --single-file views.py | python syrth_scan.py --mode dev
    python syrth_scan.py --file views.py --mode dev --threshold 0.70
    python syrth_scan.py --file views.py --mode dev --json  # includes explainability
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

DEFAULT_JOBLIB   = "syrth_ensemble.joblib"
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

    import numpy as np

    # Ensemble bundle (5 models)
    if "ensemble" in bundle:
        tok = SyrthTokenizer()
        tok.vocab = bundle["tokenizer_vocab"]

        models = []
        for name, mdata in bundle["ensemble"].items():
            cfg = mdata["model_config"]
            model = SyrthEncoder(
                vocab_size=cfg["vocab_size"],
                embed_dim=cfg["embed_dim"],
                ffn_dim=cfg["ffn_dim"],
                num_classes=cfg["num_classes"],
                dropout=0.0,
                aux_dim=0,
            )
            state = {k: torch.from_numpy(v.astype(np.float32)) for k, v in mdata["state_dict"].items()}
            model.load_state_dict(state)
            model.eval()
            models.append((model, max(mdata["heldout_acc"], 0.5)))

        ids = tok.encode(tokens)
        x = torch.tensor([ids], dtype=torch.long)
        with torch.no_grad():
            votes = torch.zeros(5)
            for model, weight in models:
                probs = F.softmax(model(x), dim=-1)[0]
                votes += probs * weight
            probs = (votes / votes.sum()).numpy()

        # Try meta-learner refinement
        meta_path = Path(__file__).parent / "syrth_meta.joblib"
        if meta_path.exists():
            try:
                from sklearn.linear_model import LogisticRegression
                from _rules import classify_by_rules
                meta_bundle = joblib.load(str(meta_path))
                lr = LogisticRegression(solver='lbfgs', max_iter=1000, C=1.0, random_state=42)
                lr.coef_ = np.array(meta_bundle["meta_model"]["coef"])
                lr.intercept_ = np.array(meta_bundle["meta_model"]["intercept"])
                lr.classes_ = np.array(meta_bundle["meta_model"]["classes"])
                lr.n_features_in_ = meta_bundle["meta_config"]["num_features"]

                # Build meta features
                pred = int(votes.argmax())
                conf = float(probs[pred])
                rule_result = classify_by_rules(tokens)
                rule_cls = rule_result.predicted_class
                rule_cf = rule_result.confidence
                rule_vt = rule_result.votes.total()
                has_t = any(t.startswith("tainted:") for t in tokens)

                feats = []
                feats.extend(float(votes[i]) for i in range(5))
                feats.append(conf)
                feats.extend(1.0 if i == pred else 0.0 for i in range(5))
                feats.append(1.0 if has_t else 0.0)
                feats.append(rule_cf)
                feats.append(min(rule_vt / 10.0, 1.0))
                if rule_vt > 0:
                    feats.extend(1.0 if i == rule_cls else 0.0 for i in range(5))
                else:
                    feats.extend([0.0] * 5)
                feats.append(1.0 if rule_vt > 0 else 0.0)

                meta_pred = int(lr.predict(np.array(feats, dtype=np.float32).reshape(1, -1))[0])
                if meta_pred != pred:
                    # Swap probabilities: boost meta-predicted class
                    meta_probs = probs.copy()
                    orig = meta_probs[meta_pred]
                    rce_i = 4
                    if meta_pred != rce_i:
                        meta_probs[meta_pred] = meta_probs[rce_i]
                        meta_probs[rce_i] = orig
                    meta_probs = meta_probs / meta_probs.sum()
                    probs = meta_probs
            except Exception:
                pass  # Meta-learner failed, use raw ensemble

        return sorted(
            zip(CLASS_NAMES, probs.tolist()),
            key=lambda t: t[1],
            reverse=True,
        )

    # Single model bundle (legacy)
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
# Explainability
# ---------------------------------------------------------------------------

# Token prefixes that indicate specific vulnerability patterns
_SINK_PREFIXES = {"sink:", "call:"}
_SOURCE_PREFIXES = {"arg:", "meta:"}
_AUTH_TOKENS = {"@login_required", "@csrf_exempt", "meta:has_auth", "meta:no_auth"}


def _compute_token_importance(
    tokens: list[str],
    bundle: dict[str, Any],
    predicted_class: str,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """
    Compute per-token importance for the predicted class.

    Uses embedding dot product with the final classification layer weights.
    Tokens whose embeddings align most with the class weights are most important.
    """
    try:
        import torch
        import numpy as np
    except ImportError:
        return []

    sys.path.insert(0, str(Path(__file__).parent))
    from train_model import SyrthEncoder, SyrthTokenizer

    # For ensemble bundles, use first model for explainability
    ensemble_aux_dim = 0
    if "ensemble" in bundle:
        first_name = next(iter(bundle["ensemble"]))
        mdata = bundle["ensemble"][first_name]
        cfg = mdata["model_config"]
        vocab = bundle["tokenizer_vocab"]
        state_dict = {
            k: torch.from_numpy(v.astype(np.float32))
            for k, v in mdata["state_dict"].items()
        }
        ensemble_aux_dim = cfg.get("aux_dim", 0)
    else:
        cfg = bundle["model_config"]
        vocab = bundle["tokenizer_vocab"]
        state_dict = {
            k: torch.from_numpy(v.astype(np.float32))
            for k, v in bundle["model_state_dict"].items()
        }

    tok = SyrthTokenizer()
    tok.vocab    = vocab
    tok._next_id = max(vocab.values()) + 1

    model = SyrthEncoder(
        vocab_size=cfg["vocab_size"],
        embed_dim=cfg["embed_dim"],
        ffn_dim=cfg.get("ffn_dim", 128),
        num_classes=cfg["num_classes"],
        dropout=0.0,
        aux_dim=ensemble_aux_dim,
    )
    model.load_state_dict(state_dict)
    model.eval()

    # Get the class index
    class_idx = CLASS_NAMES.index(predicted_class) if predicted_class in CLASS_NAMES else 0

    # Get the final classification layer weights for the predicted class
    # head is Sequential: Linear(256,1024) -> ReLU -> Dropout -> Linear(1024,512) -> ReLU -> Dropout -> Linear(512,5)
    # head[-1] = Linear(512, 5), weight shape = (5, 512)
    final_weight = model.head[-1].weight[class_idx]  # (512,)

    # Get embedding weights
    emb_weights = model.embedding.weight.data  # (vocab_size, embed_dim)

    # Project embedding weights through the MLP layers
    # Layer 0: Linear(256, 1024)
    w0 = model.head[0].weight.data  # (1024, 256)
    projected = torch.matmul(emb_weights, w0.T)  # (vocab_size, 1024)
    projected = torch.relu(projected)

    # Layer 3: Linear(1024, 512)
    w3 = model.head[3].weight.data  # (512, 1024)
    projected = torch.matmul(projected, w3.T)  # (vocab_size, 512)
    projected = torch.relu(projected)

    # Compute alignment with the final class weights
    importance_scores = torch.matmul(projected, final_weight)  # (vocab_size,)

    # Get unique tokens and their counts
    token_counts = {}
    for t in tokens:
        token_counts[t] = token_counts.get(t, 0) + 1

    # Score each unique token
    token_scores = []
    for token in set(tokens):
        if token in tok.vocab:
            idx = tok.vocab[token]
            score = importance_scores[idx].item()
            token_scores.append({
                "token": token,
                "importance": round(score, 4),
                "count": token_counts[token],
                "type": _classify_token(token),
            })

    # Sort by importance (absolute value) and return top_k
    token_scores.sort(key=lambda x: abs(x["importance"]), reverse=True)
    return token_scores[:top_k]


def _classify_token(token: str) -> str:
    """Classify a token into a category for display."""
    if token.startswith("sink:"):
        return "sink"
    elif token.startswith("call:"):
        return "call"
    elif token.startswith("arg:"):
        return "source"
    elif token.startswith("@"):
        return "decorator"
    elif token.startswith("def:"):
        return "function"
    elif token.startswith("meta:"):
        return "metadata"
    elif token.startswith("ret:"):
        return "return"
    else:
        return "other"


def _extract_per_function_patterns(trace: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract per-function vulnerability patterns from the trace.

    Returns a list of function-level findings with:
    - name: function name
    - lineno: line number
    - sinks: list of dangerous sinks found
    - has_auth: whether auth decorator is present
    - tokens: function's token sequence
    - risk_factors: list of risk indicators
    """
    functions = trace.get("functions", [])
    if not functions:
        return []

    patterns = []
    for func in functions:
        name = func.get("name", "<unknown>")
        lineno = func.get("lineno", 0)
        tokens = func.get("tokens", [])
        has_auth = func.get("has_auth_decorator", False)
        has_csrf_exempt = func.get("has_csrf_exempt", False)
        sinks = func.get("sinks", [])
        has_sql_string = func.get("has_sql_string", False)
        sink_count = func.get("sink_count", 0)

        # Identify risk factors
        risk_factors = []

        # Check for dangerous sinks
        sink_tokens = [t for t in tokens if t.startswith("sink:")]
        if sink_tokens:
            sink_names = [t.split(":", 1)[1] for t in sink_tokens]
            risk_factors.append(f"Dangerous sinks: {', '.join(sink_names)}")

        # Check for user input sources
        source_tokens = [t for t in tokens if t.startswith("arg:")]
        if source_tokens:
            source_names = [t.split(":", 1)[1] for t in source_tokens]
            risk_factors.append(f"User input sources: {', '.join(source_names)}")

        # Check auth status
        if has_auth:
            risk_factors.append("Has authentication decorator")
        else:
            risk_factors.append("No authentication decorator")

        if has_csrf_exempt:
            risk_factors.append("CSRF protection disabled")

        if has_sql_string:
            risk_factors.append("Contains SQL string literal")

        # Determine risk level
        risk_level = "low"
        if sink_count > 0 and not has_auth:
            risk_level = "high"
        elif sink_count > 0 or has_csrf_exempt:
            risk_level = "medium"

        if tokens:  # Only include functions with tokens
            patterns.append({
                "name": name,
                "lineno": lineno,
                "tokens": tokens,
                "sinks": sinks,
                "sink_count": sink_count,
                "has_auth": has_auth,
                "has_csrf_exempt": has_csrf_exempt,
                "has_sql_string": has_sql_string,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "token_count": len(tokens),
            })

    return patterns


def _generate_pattern_summary(
    predicted_class: str,
    confidence: float,
    per_function_patterns: list[dict[str, Any]],
    token_importance: list[dict[str, Any]],
) -> str:
    """
    Generate a human-readable summary of the vulnerability pattern.

    Describes WHAT was found, WHERE, and WHY it's risky.
    """
    if not per_function_patterns:
        return "No function-level patterns available."

    # Find high-risk functions
    high_risk = [p for p in per_function_patterns if p["risk_level"] == "high"]
    medium_risk = [p for p in per_function_patterns if p["risk_level"] == "medium"]

    lines = []

    # Overall assessment
    if confidence >= 0.8:
        assessment = "High confidence"
    elif confidence >= 0.6:
        assessment = "Moderate confidence"
    else:
        assessment = "Low confidence"

    lines.append(f"{assessment} classification as {predicted_class}")

    # Vulnerability chain description
    if high_risk:
        func = high_risk[0]
        sinks = func.get("sinks", [])
        if sinks:
            sink_str = ", ".join(sinks[:3])
            lines.append(
                f"Function '{func['name']}' (line {func['lineno']}) "
                f"contains dangerous sink(s): {sink_str}"
            )
            if not func["has_auth"]:
                lines.append("  -> No authentication guard present")
            if func["has_csrf_exempt"]:
                lines.append("  -> CSRF protection explicitly disabled")
        else:
            lines.append(
                f"Function '{func['name']}' (line {func['lineno']}) "
                f"has risk indicators but no explicit sinks"
            )
    elif medium_risk:
        func = medium_risk[0]
        lines.append(
            f"Function '{func['name']}' (line {func['lineno']}) "
            f"has potential risk factors"
        )

    # Top contributing tokens
    if token_importance:
        top_tokens = [t for t in token_importance[:5] if t["type"] in ("sink", "call", "source")]
        if top_tokens:
            token_strs = [f"{t['token']} ({t['type']})" for t in top_tokens]
            lines.append(f"Key tokens: {', '.join(token_strs)}")

    return "\n    ".join(lines)


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
    explainability: dict[str, Any] | None = None,
) -> None:
    top_class, top_conf = results[0]

    print(f"\n{'━' * 64}")
    print(f"  SYRTH: Scan Your Risk Trace History")
    print(f"  Source : {source_label}")
    print(f"  Mode   : {mode.upper()}")
    print(f"{'━' * 64}")

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

    # ── Explainability section ────────────────────────────────────────────
    if explainability and top_conf >= threshold:
        # Pattern summary
        pattern_summary = explainability.get("pattern_summary", "")
        if pattern_summary:
            print(f"\n  Pattern Analysis:")
            print(f"    {pattern_summary}")

        # Per-function breakdown
        per_function = explainability.get("per_function", [])
        if per_function:
            print(f"\n  Function Breakdown:")
            for func in per_function:
                risk_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                    func["risk_level"], "⚪"
                )
                sinks_str = ", ".join(func["sinks"][:3]) if func["sinks"] else "none"
                auth_str = "✓ auth" if func["has_auth"] else "✗ no auth"
                print(
                    f"    {risk_icon} {func['name']} (line {func['lineno']}): "
                    f"sinks=[{sinks_str}] {auth_str}"
                )
                for factor in func.get("risk_factors", []):
                    print(f"       → {factor}")

        # Token importance
        token_imp = explainability.get("token_importance", [])
        if token_imp:
            print(f"\n  Key Tokens:")
            for t in token_imp[:7]:
                bar_len = min(int(abs(t["importance"]) * 20), 20)
                bar = "█" * bar_len
                print(f"    {t['token']:<35} {bar} ({t['type']})")

    # Secondary findings (dev mode only)
    if mode == "dev" and len(results) > 1:
        non_zero = [(n, c) for n, c in results[1:] if c >= 0.05]
        if non_zero:
            print("\n  Other possibilities:")
            for name, conf in non_zero[:3]:
                print(f"    • {name}: {conf:.0%}")

    print(f"{'━' * 64}\n")


def _print_functional_results(
    findings: list[dict[str, Any]],
    file_class: str,
    file_conf: float,
    confirmed: bool,
    source_label: str,
    mode: str,
    threshold: float,
    explainability: dict[str, Any] | None,
) -> None:
    print(f"\n{'━' * 64}")
    print(f"  SYRTH: Scan Your Risk Trace History")
    print(f"  Source : {source_label}")
    print(f"  Mode   : {mode.upper()}")
    print(f"{'━' * 64}")

    if not findings:
        print(f"  ✓  No security-relevant functions detected.")
        print(f"{'━' * 64}\n")
        return

    cwe_idx = CLASS_NAMES.index(file_class) if file_class in CLASS_NAMES else -1
    cwe_id = CWE_IDS[cwe_idx] if 0 <= cwe_idx < len(CWE_IDS) else ""

    # OOD rejection
    if explainability and explainability.get("ood"):
        print(f"\n  ⚠  UNCERTAIN PREDICTION (confidence {file_conf:.0%} < threshold)")
        print(f"     This block has no strong vulnerability signal.")
        print(f"     Manual review required.")
        return

    # File-level verdict
    if confirmed:
        tag = "► CONFIRMED" if file_conf >= threshold else "► LIKELY"
        print(f"\n  {tag}: {file_class} ({file_conf:.0%})  [{cwe_id}]")
        print(f"    {CWE_DESCRIPTIONS.get(file_class, '')}")
    else:
        print(f"\n  ⚠  No confirmed taint flow. Best guess: {file_class} ({file_conf:.0%})")
        print(f"    Manual review recommended (no untrusted-input→sink path found).")

    # Per-function breakdown, taint-confirmed first
    print(f"\n  Function Breakdown:")
    order = sorted(findings, key=lambda f: (not f["has_taint"], -f["confidence"]))
    for f in order:
        if f["has_taint"]:
            icon = "🔴"
            status = "CONFIRMED"
        elif f["sinks"]:
            icon = "🟡"
            status = "review"
        else:
            icon = "🟢"
            status = "ok"
        sinks_str = ", ".join(f["sinks"][:3]) if f["sinks"] else "none"
        auth_str = "✓ auth" if f["has_auth"] else "✗ no auth"
        print(
            f"    {icon} {f['name']} (line {f['lineno']}): "
            f"{status} → {f['prediction']} {f['confidence']:.0%} | "
            f"sinks=[{sinks_str}] {auth_str}"
        )
        if f["has_taint"]:
            print(f"       taint path: {'; '.join(f['tainted_sinks'])}")

    # Token importance (top finding)
    if explainability:
        token_imp = explainability.get("token_importance", [])
        if token_imp:
            print(f"\n  Key Tokens (top confirmed finding):")
            for t in token_imp[:7]:
                bar_len = min(int(abs(t["importance"]) * 20), 20)
                bar = "█" * bar_len
                print(f"    {t['token']:<35} {bar} ({t['type']})")

    print(f"{'━' * 64}\n")


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
    parser.add_argument("--threshold", type=float, default=0.40,
                        help="Confidence threshold. Top prediction below this → Unknown (OOD)")
    parser.add_argument("--ood-threshold", type=float, default=None,
                        help="OOD rejection threshold (default: same as --threshold)")
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

    # ── Load model / engine ────────────────────────────────────────────────
    if args.mode == "dev":
        bundle = _load_joblib_bundle(args.model)
        lib = None
    else:
        bundle = None
        lib = _build_fast_engine(args.engine)

    def _predict(toks):
        if args.mode == "dev":
            return _dev_predict(toks, bundle)
        return _fast_predict(toks, lib)

    # ── Per-function, taint-confirmed analysis ──────────────────────────────
    # Each function is classified independently. A function is a CONFIRMED
    # finding only when untrusted input actually reaches a dangerous sink
    # (it carries a `tainted:<sink>` token). Safe sink usage (parameterised
    # query, escaped output, fixed command) produces no taint token and is
    # reported as safe / review-only — this is what stops the scanner from
    # false-positiving on benign code.
    patterns = _extract_per_function_patterns(trace)
    findings = []
    for p in patterns:
        ftoks = p.get("tokens", [])
        if not ftoks:
            continue
        preds = _predict(ftoks)
        cls, conf = preds[0]
        has_taint = any(t.startswith("tainted:") for t in ftoks)
        tainted_sinks = sorted({t.split(":", 1)[1] for t in ftoks if t.startswith("tainted:")})
        findings.append({
            "name": p["name"], "lineno": p["lineno"],
            "prediction": cls, "confidence": conf, "all_classes": preds,
            "has_taint": has_taint, "tainted_sinks": tainted_sinks,
            "sinks": p["sinks"], "has_auth": p["has_auth"],
            "risk_level": p["risk_level"], "risk_factors": p["risk_factors"],
            "tokens": ftoks,
        })

    tainted = [f for f in findings if f["has_taint"]]
    if tainted:
        top = max(tainted, key=lambda f: f["confidence"])
        file_class, file_conf = top["prediction"], top["confidence"]
        file_preds = top["all_classes"]
    else:
        # No confirmed taint path in the file: fall back to a discounted
        # whole-file prediction (low confidence → manual review).
        file_preds = _predict(tokens)
        file_class, file_conf = file_preds[0]
        file_conf *= 0.5

    # ── OOD rejection ───────────────────────────────────────────────────────
    # If top prediction confidence is below threshold, report as Unknown.
    # This improves precision by rejecting uncertain predictions.
    # Taint-confirmed findings ALWAYS override OOD (taint is highest precision).
    ood_threshold = args.ood_threshold if args.ood_threshold is not None else args.threshold
    is_ood = file_conf < ood_threshold and not tainted
    if is_ood:
        file_class = "Unknown"

    # ── Explainability (dev mode, top confirmed finding) ────────────────────
    explainability = None
    if args.mode == "dev":
        top_find = max(findings, key=lambda f: f["confidence"]) if findings else None
        token_importance = (
            _compute_token_importance(top_find["tokens"], bundle, top_find["prediction"])
            if top_find else []
        )
        pattern_summary = _generate_pattern_summary(
            file_class, file_conf, patterns, token_importance
        )
        explainability = {
            "per_function": findings,
            "token_importance": token_importance,
            "pattern_summary": pattern_summary,
            "ood": is_ood,
            "ood_threshold": ood_threshold,
        }

    # ── Output ───────────────────────────────────────────────────────────────
    if args.json:
        cwe_idx = CLASS_NAMES.index(file_class) if file_class in CLASS_NAMES else -1
        output = {
            "syrth_version": "1.0.0",
            "source": source_label,
            "mode": args.mode,
            "ood": is_ood,
            "prediction": {
                "class": file_class,
                "cwe_id": CWE_IDS[cwe_idx] if cwe_idx >= 0 else "",
                "confidence": round(file_conf, 4),
                "confirmed_flow": bool(tainted),
                "description": CWE_DESCRIPTIONS.get(file_class, ""),
            },
            "all_classes": [{"class": n, "confidence": round(c, 4)} for n, c in file_preds],
            "findings": [
                {
                    "function": f["name"], "line": f["lineno"],
                    "prediction": f["prediction"], "confidence": round(f["confidence"], 4),
                    "confirmed_flow": f["has_taint"], "tainted_sinks": f["tainted_sinks"],
                    "sinks": f["sinks"],
                }
                for f in findings
            ],
        }
        if explainability:
            output["explainability"] = explainability
        print(json.dumps(output, indent=2))
    else:
        _print_functional_results(
            findings, file_class, file_conf, bool(tainted),
            source_label, args.mode, args.threshold, explainability,
        )


if __name__ == "__main__":
    main()
