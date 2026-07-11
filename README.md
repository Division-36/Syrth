# SYRTH: Scan Your Risk Trace History

## Overview

SYRTH is an AST-based vulnerability pattern classifier for Python source code. It parses code into security-relevant function traces, encodes them into token sequences, and classifies them into 5 CWE vulnerability categories using a trained neural network. The scanner includes built-in explainability: per-function breakdown, token importance, and pattern analysis.

---

## Vulnerability Classes

| Class | CWE ID | Name | Example Pattern |
|-------|--------|------|-----------------|
| 0 | CWE-89 | SQLi | `arg:input` → `sink:execute` |
| 1 | CWE-79 | XSS | `arg:input` → `sink:render` |
| 2 | CWE-22 | PathTraversal | `arg:filename` → `sink:open` |
| 3 | CWE-601 | OpenRedirect | `arg:url` → `sink:redirect` |
| 4 | CWE-94 | RCE | `arg:cmd` → `sink:eval` / `sink:os.system` |

**Dropped classes** (not detectable from AST traces): IDOR (CWE-284), SSRF (CWE-918), BrokenAuth (CWE-287). These are logic flaws requiring authorization context that static AST analysis cannot reliably detect.

---

## Installation

```bash
# Clone
git clone https://github.com/Division-36/Syrth.git
cd Syrth

# Install dependencies
pip install torch numpy scikit-learn joblib
```

### Requirements

- Python 3.8+
- GCC (required for `--mode fast` only)

---

## Usage

### Quick Start

```bash
# Scan a Python file
python syrth_scan.py --file views.py --mode dev

# JSON output with explainability
python syrth_scan.py --file views.py --mode dev --json

# Fast mode (C engine)
python syrth_scan.py --file views.py --mode fast
```

### Explainability Output

The scanner shows **why** it classified a vulnerability:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SYRTH: Scan Your Risk Trace History
  Source : views.py
  Mode   : DEV
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ► PathTraversal: 67%  [CWE-22]
    Path Traversal (CWE-22) — user input used in filesystem path

  Pattern Analysis:
    Moderate confidence classification as PathTraversal
    Function 'upload_file' (line 4) contains dangerous sink(s): os.path.join, open
      -> No authentication guard present

  Function Breakdown:
    🔴 upload_file (line 4): sinks=[os.path.join, open] ✗ no auth
       → Dangerous sinks: os.path.join, open
       → User input sources: request
    🟡 secure_view (line 12): sinks=[render] ✓ auth
       → Has authentication decorator

  Key Tokens:
    sink:open                           ████████████████████ (sink)
    call:os.path.join                   ████████████████████ (call)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Pipeline

```
Python Source File
       │
       ▼
 collect.py  ──── AST parsing, sink detection, token extraction
       │
       ▼
  Token Sequence  (def:name, arg:input, sink:execute, @decorator)
       │
       ▼
 syrth_scan.py ── Inference via PyTorch (dev) or C engine (fast)
       │
       ▼
  Classification + Explainability
```

---

## Training

### Dataset Generation

```bash
# Build synthetic code-derived dataset (recommended)
python _build_synthetic.py

# Or build from harvester templates
python harvester.py
```

### Model Training

```bash
python train_model.py --dataset _balanced_dataset.json
```

Produces:
- `syrth_model.joblib` — Python model bundle
- `syrth_engine.h` — Self-contained C header for fast mode

### Results

SYRTH is validated on **real GitHub advisory data** (OSV PyPI bulk corpus, 2,299
records, 5 CWE classes), with a strict leak-free train/test split (0 overlapping
records, no label leakage).

**Trained and tested on real advisories** (`repair_dataset.py` → `train_model.py`):

The train/test split is keyed on the stable advisory identity (`ghsa_id`) and
stratified per class, so the benchmark is reproducible and leak-free (0
overlapping records, label excluded from features).

| Metric | Value |
|---|---|
| Held-out test accuracy (advisory text) | **94.2%** (976 records, stable split) |
| SQLi | 89.2% |
| XSS | 97.1% |
| PathTraversal | 92.1% |
| OpenRedirect | 94.2% |
| RCE | 94.4% |
| Leakage | 0 records |
| Dev/Fast agreement | 100% |
| Training data | **16,940 real PyPI advisories** (OSV bulk feed, all packages) + 554 synthetic code templates, balanced to 5,669 records |

**Real scanned code** (719 real CVE code blocks run through the actual
`syrth_scan` pipeline): **69.1%** overall — SQLi 97%, XSS 69%, PathTraversal
70%, OpenRedirect 83%, RCE 64%. Advisory *text* is easier than *code*; this is
the honest floor for code scanning and is what we optimise for.

**Taint-confirmed, function-level scanning.** `syrth_scan.py` classifies each
function independently and only raises a **CONFIRMED** finding when untrusted
input actually reaches a dangerous sink (a `tainted:<sink>` token exists). Safe
sink usage — parameterised queries, escaped output, fixed commands — produces
no taint token and is reported as safe / review-only, which eliminates the
false positives that plagued the old file-level classifier. Taint propagates
through string concatenation and f-strings, so the common
`HttpResponse("..." + user_input)` / `f"..{x}.."` injection patterns are
caught.

**Code-only validation** (real code samples in `RLTESTS/`): **6/6 PASS**,
dev/fast C-engine agreement **100%**.

> ⚠ **Honesty note:** An earlier 99% figure was invalid — it came from a
> train/test split that reused identical records *and* leaked the label
> (`cwe:` token) into the features. Both issues are fixed. The headline
> hold-out number is on advisory *text*; the **real scanned-code** number
> (69.1%) is the honest measure of code-scanning quality and is lower because
> advisory snippets are often incomplete (no full taint path). On complete
> functions the taint gate makes detection precise.

The real-advisory model uses advisory description text (`txt:` features) as
honest, non-label signal. For pure source-code scanning (no description
available), train with `_build_synthetic.py` and validate via `RLTESTS/`.

---

## Architecture

```
SyrthEncoder
├── Embedding(vocab_size, 256, padding_idx=0)
├── Mean Pool (masked)
├── Dropout(0.2)
└── MLP Head
    ├── Linear(256 → 1024) + ReLU + Dropout(0.2)
    ├── Linear(1024 → 512)  + ReLU + Dropout(0.2)
    └── Linear(512 → 5)
```

Bag-of-Words is intentional: Transformers underperform on small, structured token sequences. Mean-pooled embeddings over security-semantic tokens generalise better.

---

## File Structure

```
Syrth/
├── harvester.py          # Dataset builder + synthetic variant generator
├── collect.py            # AST trace extractor
├── train_model.py        # Model training + C header export
├── syrth_scan.py         # Inference frontend (dev + fast + explainability)
├── _build_synthetic.py   # Code-derived dataset builder (recommended)
├── benchmark.py          # Performance evaluator
├── requirements.txt      # Python dependencies
├── Makefile              # Build commands
├── syrth_model.joblib    # Trained model bundle (generated)
├── syrth_engine.h        # C header (generated)
└── syrth_engine.so       # Shared library (auto-generated on first fast run)
```

---

## Design Decisions

### Why 5 classes, not 8?
IDOR, SSRF, and BrokenAuth are logic flaws requiring authorization context. Static AST analysis of function signatures and call patterns cannot reliably detect them. Training on undetectable classes hurts accuracy on detectable ones.

### Synthetic Code-Derived Training
The model trains on real Python vulnerable/patched pairs processed through the same AST pipeline used at scan time. This ensures training tokens match inference tokens exactly.

### Explainability via Embedding Analysis
Token importance is computed by projecting embeddings through the MLP layers and measuring alignment with the predicted class weights. This shows which tokens most influenced the classification.

---

## License

MIT
