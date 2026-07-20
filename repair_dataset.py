#!/usr/bin/env python3
"""repair_dataset.py — Make an existing SYRTH dataset production-ready.

The datasets previously shipped with two problems:

  1. LEAK: training tokens included a literal ``cwe:<id>`` feature, which is
     the ground-truth label — the model could memorise the answer.
  2. MISALIGNMENT: training tokens were derived from advisory *text*
     (``cwe:/code:/framework:``) while syrth_scan.py emits a different scheme
     (``def:/arg:/sink:/call:/ret:/@decorator/meta:no_auth``). At inference most
     tokens hit <UNK>.
  3. CONTAMINATION: the "train" and "test" files were drawn from the same
     advisory pool with massive overlap, so the benchmark measured
     memorisation, not generalisation.

This script fixes all three WITHOUT re-downloading anything:

  * Re-tokenises every record from its stored ``description`` using
    harvester._build_advisory_tokens() (code blocks -> collect.py tokens,
    otherwise leak-free text tokens).
  * Deduplicates identical records.
  * Splits deterministically by content hash, stratified per class, so a
    sample can never appear in both train and test.

Usage:
    python repair_dataset.py [SOURCE.json] [TRAIN_OUT.json] [TEST_OUT.json]
Defaults: _full_dataset.json -> _balanced_dataset.json + testingMassiveDataset.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)

import harvester as H

RATIO = 0.2
SEED = 42
DEFAULT_TOP_K = 30000


def _record_hash(r: dict) -> str:
    # Key the split on (tokens, label) ONLY — not on the source id. This way
    # identical token sequences (even from different advisories) always land on
    # the same side, guaranteeing zero train/test leakage.
    key = json.dumps(
        {"tokens": r.get("tokens"), "label": r.get("label")},
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()


# Keep tokens that syrth_scan.py emits at inference time (def:/arg:/call:/
# sink:/ret:/@decorator/meta:no_auth/flow:) plus text-derived keywords
# (severity:/framework:) and advisory description words (txt:). We deliberately
# NOT include the label (cwe:) — that would leak the answer.
_ALLOWED_PREFIX = {"def", "arg", "call", "sink", "ret", "meta", "flow", "tainted", "severity", "framework", "txt", "txt2"}

# Code-only mode: only tokens that syrth_scan.py emits at inference on real
# source files.  Description text (txt:, txt2:, severity:, framework:, code:)
# is excluded because it is never available at scan time.  This produces a
# more honest and more accurate code-scanning model.
_CODE_ONLY_PREFIX = {"def", "arg", "call", "sink", "ret", "meta", "flow", "tainted"}

# Minimal English function-word stop list. Deliberately KEEPS security-domain
# words (command, arbitrary, file, system, injection, traversal, redirect,
# deserialization, script, query, sql, ...) — those are the discriminative
# signal that separates the 5 classes.
_STOP = set(
    "the a an and or of to in for with on by from at as is are was were be been being "
    "this that these those which it its their our your his her they them we you he she "
    "but if then than so can may might could would should will shall must do does did "
    "doing done have has had having not no nor only own same too very also just now up "
    "down off over under again further once here there all any both each few more most "
    "other some such per e.g i.e etc due via when where while who whom how what why into "
    "between about after before during within without am i you're"
    .split()
)


def _keep_token(t: str) -> bool:
    if t.startswith("@"):
        return True
    return t.split(":", 1)[0] in _ALLOWED_PREFIX


def _desc_tokens(description: str, desc_vocab: set[str] | None = None, limit: int = 150) -> list[str]:
    """Honest, non-label description features as `txt:` (unigram) and
    `txt2:` (bigram phrase) tokens.

    Phrases like 'sql injection', 'path traversal', 'open redirect',
    'arbitrary code' are highly class-specific and disambiguate the 5 classes.
    The ground-truth CWE label is NEVER included. When `desc_vocab` is given,
    only tokens present in that global top-K vocabulary are kept (bounds the
    model vocabulary so the C engine stays practical).
    """
    words = [w for w in re.findall(r"[a-z]{3,}", description.lower()) if w not in _STOP]
    out: list[str] = []
    seen: set[str] = set()
    # Unigrams
    for w in words:
        if w in seen:
            continue
        seen.add(w)
        tok = f"txt:{w}"
        if desc_vocab is None or tok in desc_vocab:
            out.append(tok)
        if len(out) >= limit:
            break
    # Bigrams (class-specific phrases)
    seen2: set[str] = set()
    for a, b in zip(words, words[1:]):
        big = f"{a}_{b}"
        if big in seen2:
            continue
        seen2.add(big)
        tok = f"txt2:{big}"
        if desc_vocab is None or tok in desc_vocab:
            out.append(tok)
        if len(out) >= limit + 120:
            break
    return out


def build_desc_vocab(records: list[dict], top_k: int = 5000) -> set[str]:
    """Global top-K description tokens across the corpus (bounds vocabulary)."""
    from collections import Counter
    cnt: Counter[str] = Counter()
    for r in records:
        desc = r.get("description") or r.get("summary") or ""
        cnt.update(_desc_tokens(desc))
    return set(t for t, _ in cnt.most_common(top_k))


def re_tokenize(records: list[dict], desc_vocab: set[str] | None = None,
                code_only: bool = False) -> list[dict]:
    """Re-tokenise records.

    When *code_only* is True (the production default), keep ONLY the tokens
    that syrth_scan.py emits at inference on real source files: AST-derived
    structural tokens (def:/arg:/sink:/call:/ret:/@/meta:) and taint-flow
    tokens (flow:/tainted:).  Description text (txt:/txt2:), severity,
    framework, and backtick-derived ``code:`` tokens are excluded because they
    are never available at scan time.

    When *code_only* is False (legacy behaviour), the full token set including
    description text is kept.
    """
    out: list[dict] = []
    skipped = 0
    for r in records:
        desc = r.get("description") or r.get("summary") or ""
        if code_only:
            # ── Code-only path: AST tokens from fenced code blocks only ──
            code_toks = H._tokens_from_advisory_code(desc)
            toks = [t for t in code_toks if t.startswith(tuple(_CODE_ONLY_PREFIX))
                    or t.startswith("@")]
            # Synthetic records store code tokens in the tokens field directly.
            if not toks and r.get("tokens"):
                toks = [t for t in r["tokens"]
                        if t.split(":", 1)[0] in _CODE_ONLY_PREFIX
                        or t.startswith("@")]
        else:
            # ── Legacy path: description text + code tokens ──────────────
            toks = H._build_advisory_tokens(desc, r.get("severity", ""),
                                             r.get("cwe_id", ""))
            toks = [t for t in toks if _keep_token(t)]
            toks = toks + _desc_tokens(desc, desc_vocab)
            if not toks and r.get("tokens"):
                toks = [t for t in r["tokens"] if _keep_token(t)]
        if not toks:
            skipped += 1
            continue
        fixed = dict(r)
        fixed["tokens"] = toks
        out.append(fixed)
    mode_label = "code-only" if code_only else "description-inclusive"
    sys.stderr.write(
        f"[repair] re-tokenized {len(out)} records ({skipped} dropped, "
        f"{mode_label})\n"
    )
    return out


def split_train_test(records: list[dict], ratio: float = RATIO, seed: int = SEED):
    """Leak-free, stratified train/test split.

    Splits within each class separately (preserving class proportions).
    The split is keyed on a STABLE advisory identity (ghsa_id / cve_ids), NOT
    on the token sequence, so the held-out set stays fixed across tokenizer
    changes and results are comparable. Identical (tokens, label) records are
    deduplicated so a duplicate can never appear in both sides (no leakage).
    """
    rng = random.Random(seed)

    def _stable_key(r: dict) -> str:
        return str(r.get("ghsa_id") or (r.get("cve_ids") or [""])[0] or id(r))

    def _content_key(r: dict) -> str:
        return json.dumps({"tokens": r.get("tokens"), "label": r.get("label")}, sort_keys=True)

    from collections import defaultdict
    by_label: dict[int, list] = defaultdict(list)
    for r in records:
        by_label[r.get("label", 0)].append(r)

    train: list[dict] = []
    test: list[dict] = []

    for label, group in by_label.items():
        # Stable order by advisory identity, then seeded shuffle (deterministic).
        ordered = sorted(group, key=_stable_key)
        seen: dict[str, dict] = {}
        for r in ordered:
            seen.setdefault(_content_key(r), r)
        unique = list(seen.values())
        rng.shuffle(unique)
        split = max(1, int(len(unique) * ratio + 0.5))
        test.extend(unique[:split])
        train.extend(unique[split:])

    return train, test


def _pack(records: list[dict]) -> dict:
    class_counts: dict[str, int] = {}
    for r in records:
        name = H.CWE_NAMES.get(r.get("cwe_id", ""), f"Class{r.get('label')}")
        class_counts[name] = class_counts.get(name, 0) + 1
    return {
        "syrth_version": "1.0.0",
        "num_classes": len(H.CWE_LABELS),
        "class_map": {str(v): k for k, v in H.CWE_LABELS.items()},
        "cwe_names": H.CWE_NAMES,
        "class_distribution": class_counts,
        "total_records": len(records),
        "records": records,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Repair/re-tokenise a SYRTH dataset into leak-free train/test.")
    ap.add_argument("--src", default="_full_dataset_5class.json")
    ap.add_argument("--train", default="_balanced_dataset.json")
    ap.add_argument("--test", default="testingMassiveDataset.json")
    ap.add_argument("--top-k", type=int, default=DEFAULT_TOP_K,
                    help="Bound description vocabulary to top-K tokens (keeps C engine practical).")
    ap.add_argument("--code-only", action="store_true", default=True,
                    help="Strip all description features (txt/txt2/severity/framework). "
                         "Produces a more honest and more accurate code-scanning model. [DEFAULT]")
    ap.add_argument("--with-description", action="store_true", default=False,
                    help="Include description text features (legacy mode, inflates headline accuracy).")
    args = ap.parse_args()

    code_only = not args.with_description

    src = Path(args.src)
    train_out = Path(args.train)
    test_out = Path(args.test)

    if not src.exists():
        sys.stderr.write(f"[repair] source not found: {src}\n")
        sys.exit(1)

    raw = json.loads(src.read_text(encoding="utf-8")).get("records", [])
    sys.stderr.write(f"[repair] loaded {len(raw)} raw records from {src}\n")

    if code_only:
        desc_vocab = None
        sys.stderr.write("[repair] mode: CODE-ONLY (no description features)\n")
    else:
        desc_vocab = build_desc_vocab(raw, top_k=args.top_k)
        sys.stderr.write(f"[repair] mode: description-inclusive (vocab={len(desc_vocab)} tokens)\n")

    repaired = re_tokenize(raw, desc_vocab, code_only=code_only)
    train, test = split_train_test(repaired)

    # Sanity: prove no leakage between train and test.
    train_hashes = {_record_hash(r) for r in train}
    leaked = sum(1 for r in test if _record_hash(r) in train_hashes)
    sys.stderr.write(f"[repair] leakage check: {leaked} test samples also in train\n")

    # Windows/DrvFS rejects truncating+rewriting a large existing file (EINVAL),
    # so unlink first.
    for p in (train_out, test_out):
        if p.exists():
            p.unlink()

    train_out.write_text(json.dumps(_pack(train), indent=2), encoding="utf-8")
    test_out.write_text(json.dumps(_pack(test), indent=2), encoding="utf-8")
    sys.stderr.write(
        f"[repair] wrote train={len(train)} -> {train_out}\n"
        f"[repair] wrote test ={len(test)} -> {test_out}\n"
    )


if __name__ == "__main__":
    main()
