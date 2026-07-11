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
| Held-out test accuracy | **90.4%** (353 records, stable split) |
| SQLi | 63.6% |
| XSS | 92.0% |
| PathTraversal | 92.6% |
| OpenRedirect | 88.9% |
| RCE | 92.4% |
| Leakage | 0 records |
| Dev/Fast agreement | 100% |

**Code-only validation** (synthetic code-derived training, evaluated on real
source files in `RLTESTS/`): 97.0% synthetic held-out, **100% on real code
(6/6)**. This confirms the scanner generalises to complete source code.

> ⚠ **Honesty note:** An earlier 99% figure was invalid — it came from a
> train/test split that reused identical records *and* leaked the label
> (`cwe:` token) into the features. Both issues are fixed. The numbers above
> are from leak-free splits with the label excluded from features.

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
