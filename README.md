# SYRTH: Scan Your Risk Trace History

## Overview

SYRTH is an AST-based vulnerability detection system for Python source code. It parses code into security-relevant function traces, encodes them into token sequences, and classifies them into 8 common CWE vulnerability categories using a trained neural network.

The system ships two inference backends: a Python/PyTorch development mode and a compiled C engine for production use.

---

## Architecture

### Pipeline

```
Python Source File
       │
       ▼
 collect.py  ──── AST parsing, sink detection, token extraction
       │
       ▼
  Token Sequence  (e.g. "@login_required", "def:view", "arg:user_input", "sink:execute")
       │
       ▼
 syrth_scan.py ── Inference via joblib (dev) or compiled C engine (fast)
       │
       ▼
  Prediction + CWE ID + Confidence Score
```

### Core Components

**`harvester.py`** — Dataset builder. Collects vulnerability samples from the OSV/GitHub Advisory Database and generates synthetic training examples. Supports CWE alias resolution for 8 target classes plus broader CWE mappings (e.g. CWE-943 → SQLi, CWE-798 → BrokenAuth). Requires the `requests` library for remote fetching.

**`collect.py`** — AST trace extractor. Performs a single-pass AST walk over Python source files, extracting per-function traces including decorator chains, argument names, internal call graph, and known sink hits. Outputs normalised token sequences in minified JSON to stdout. Supports both single-file scan mode and diff mode (vulnerable vs. patched).

**`train_model.py`** — Model trainer. Implements a Bag-of-Words + MLP architecture (`SyrthEncoder`): token embeddings are mean-pooled with padding mask, then passed through a 3-layer MLP head (`embed_dim → ffn_dim → ffn_dim/2 → num_classes`). Trained with 20-fold stratified cross-validation and ensemble voting across all folds. Exports to `.joblib` for Python inference and `.h` C header for the fast engine.

**`syrth_scan.py`** — Inference frontend. Accepts a Python file directly or a trace JSON piped from `collect.py`. Supports two modes: `dev` (loads `.joblib` bundle via PyTorch) and `fast` (compiles `syrth_engine.h` to a shared library via GCC and calls it through `ctypes`). Outputs human-readable results or structured JSON.

**`benchmark.py`** — Performance evaluator. Enforces strict train/test separation: 20% of real records are held out and never seen during training. Runs 500 Python inference passes and 5000 C engine passes, reporting latency percentiles, throughput, and per-class accuracy.

---

## Model Architecture

```
SyrthEncoder
├── Embedding(vocab_size, embed_dim=256, padding_idx=0)
├── Mean Pool (masked — padding tokens excluded)
├── Dropout(0.2)
└── MLP Head
    ├── Linear(256 → 1024) + ReLU + Dropout(0.2)
    ├── Linear(1024 → 512)  + ReLU + Dropout(0.2)
    └── Linear(512 → 8)
```

This Bag-of-Words approach is intentional: Transformers underperform on small, structured token sequences. Mean-pooled embeddings over security-semantic tokens (e.g. `sink:execute`, `@login_required`, `arg:user_input`) are sufficient and substantially faster.

---

## Vulnerability Classes

| Class | CWE ID | Name | Example Token Pattern |
|-------|--------|------|-----------------------|
| 0 | CWE-89 | SQLi | `arg:user_input` → `sink:execute` |
| 1 | CWE-79 | XSS | `arg:user_input` → `sink:render_to_string` |
| 2 | CWE-284 | IDOR | `arg:doc_id` → `sink:db.find` (no auth decorator) |
| 3 | CWE-918 | SSRF | `arg:url` → `sink:requests.get` |
| 4 | CWE-22 | PathTraversal | `arg:filename` → `sink:open` |
| 5 | CWE-601 | OpenRedirect | `arg:next` → `sink:redirect` |
| 6 | CWE-287 | BrokenAuth | `def:login` missing `@login_required` |
| 7 | CWE-94 | RCE | `arg:command` → `sink:os.system` / `sink:eval` |

CWE aliases are also resolved during dataset construction (e.g. CWE-798 and CWE-306 both map to BrokenAuth; CWE-78 and CWE-95 map to RCE).

---

## Installation

### Requirements

- Python 3.8+
- GCC (required for `--mode fast` only)

```bash
pip install torch numpy scikit-learn joblib matplotlib seaborn psutil requests
```

---

## Usage

### 1. Dataset Generation

```bash
# Synthetic samples only (no network required)
python harvester.py

# Pull from GitHub Advisory Database (requires GH_TOKEN environment variable)
python harvester.py --gh --gh-max-pages 100 --balance none

# Web framework packages only (Django, FastAPI, Flask, etc.)
python harvester.py --gh --gh-filtered --balance none

# Upsample minority classes to match the largest class
python harvester.py --gh --balance upsample --max-per-class 500
```

**Balancing strategies:**

| Strategy | Behaviour |
|----------|-----------|
| `none` (default) | Keep all data — maximises dataset size |
| `min` | Downsample all classes to the smallest class count |
| `upsample` | Replicate smaller classes to match the largest |
| `threshold` | Drop classes below `--min-per-class`, cap at `--max-per-class` |

**Key CLI options:**
- `--output / -o` — Output path (default: `_dataset.json`)
- `--gh` — Enable GitHub Advisory fetching
- `--gh-max-pages N` — Pages to fetch (100 advisories each)
- `--gh-severity` — Filter by severity: `CRITICAL`, `HIGH`, `MODERATE`, `LOW`
- `--gh-filtered` — Restrict to web framework packages
- `--no-synthetic` — Disable synthetic template generation
- `--balance` — Balancing strategy (see above)

### 2. Model Training

```bash
python train_model.py --dataset _dataset.json
```

This runs 20-fold stratified cross-validation, then produces:
- `syrth_model.joblib` — Python model bundle for dev mode
- `syrth_engine.h` — Self-contained C header for fast mode

Optional flags:
- `--no-export-joblib` — Skip joblib export
- `--no-export-c` — Skip C header export
- `--joblib-path PATH` / `--c-path PATH` — Override output paths

### 3. Scanning

```bash
# Scan a file directly (dev mode — uses joblib)
python syrth_scan.py --file views.py --mode dev

# Scan via collect.py pipeline
python collect.py --single-file views.py | python syrth_scan.py --mode dev

# Fast mode — compiles C engine on first run, caches .so for subsequent runs
python syrth_scan.py --file views.py --mode fast

# Diff mode — compare vulnerable vs patched version
python collect.py --diff --old-file vuln.py --new-file fixed.py \
    | python syrth_scan.py --mode dev

# Only report findings above 70% confidence
python syrth_scan.py --file views.py --mode dev --threshold 0.70

# Machine-readable JSON output
python syrth_scan.py --file views.py --mode dev --json
```

**Output (human-readable):**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SYRTH: Scan Your Risk Trace History
  Source : views.py
  Mode   : DEV
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ► SQLi: 89%  [CWE-89]
    SQL Injection (CWE-89) — user input reaches raw SQL execution

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 4. Benchmarking

```bash
# Run with the default dataset
python benchmark.py

# Use a custom test dataset
python benchmark.py --testing-dataset _dataset.json
```

**Outputs written to `benchmark/<dataset_name>/`:**
- `results.json` — Raw latency and accuracy data
- `metrics.json` — Processed metrics with class distribution
- `summary.txt` — Human-readable report
- `*.png` — Latency, accuracy, resource, and speedup charts

---

## Benchmark Results

Measured on `testingMassiveDataset` — 3,652 total records, 730 held out for testing (strict split, no synthetic data in test set).

### Accuracy

| Class | Accuracy |
|-------|----------|
| SQLi (CWE-89) | 96.0% |
| XSS (CWE-79) | 100.0% |
| IDOR (CWE-284) | 98.9% |
| SSRF (CWE-918) | 100.0% |
| PathTraversal (CWE-22) | 98.2% |
| OpenRedirect (CWE-601) | 100.0% |
| BrokenAuth (CWE-287) | 95.0% |
| RCE (CWE-94) | 100.0% |
| **Overall** | **99.0%** |

### Latency (500 Python runs / 5000 C runs)

| Metric | Python (dev) | C Engine (fast) |
|--------|-------------|-----------------|
| Mean | 391 µs | 178 µs |
| Median | 356 µs | 178 µs |
| P95 | 686 µs | 228 µs |
| P99 | 993 µs | 241 µs |
| Min | 298 µs | 159 µs |
| Max | 1,668 µs | 241 µs |
| Throughput | 2.6K samples/s | 5.6K samples/s |
| **Speedup** | baseline | **2.3× faster** |

### Resource Usage

| Metric | Python (dev) | C Engine (fast) |
|--------|-------------|-----------------|
| Peak RAM | 0.25 MB | 5.0 MB |
| Avg CPU | 64% | 96% |

> **Note:** The C engine trades higher RAM (it loads the full embedded weight arrays) for lower and more consistent latency. The Python engine has a lower memory footprint but higher latency variance (P99 is ~4× the median due to PyTorch overhead).

---

## Training Hyperparameters

| Parameter | Value |
|-----------|-------|
| Embedding dim | 256 |
| FFN hidden dim | 1024 |
| Dropout | 0.2 |
| Batch size | 64 |
| Learning rate | 5e-3 |
| Max epochs | 100 |
| Early stop patience | 18 |
| Label smoothing | 0.1 |
| Cross-validation folds | 20 |
| Max sequence length | 128 tokens |

---

## Design Decisions

### Data Leakage Prevention
The benchmark enforces a hard train/test boundary. The dataset is shuffled with a fixed seed (42), 20% is held out before any training occurs, and no synthetic records are included in the test set.

### Why Bag-of-Words, Not a Transformer?
SYRTH's token sequences are short (typically 5–30 tokens), structurally regular, and security-semantically dense. Transformers require far more data to learn useful attention patterns on such inputs. Mean-pooled embeddings over security-specific tokens (`sink:*`, `@decorator`, `arg:*`) generalise better on the available dataset sizes.

### C Engine Compilation
On first use, `syrth_scan.py --mode fast` compiles `syrth_engine.h` into a shared library (`syrth_engine.so`) using GCC `-O2`. The `.so` is cached and reused on subsequent runs unless the header is newer. The engine embeds all weights as static float arrays and requires no runtime dependencies beyond libc.

### Ensemble Voting
Training produces 20 models (one per fold). Ensemble probabilities are averaged across all models to determine the final prediction. The best single-fold model is exported to the `.joblib` and `.h` files for deployment.

---

## File Structure

```
Syrth/
├── harvester.py          # Dataset builder (OSV, GitHub Advisory, synthetic)
├── collect.py            # AST trace extractor
├── train_model.py        # Model training and export
├── syrth_scan.py         # Inference frontend (dev + fast modes)
├── benchmark.py          # Performance evaluator
├── _dataset.json         # Training dataset (generated)
├── syrth_model.joblib    # Trained model bundle (Python)
├── syrth_engine.h        # Compiled C header (production)
├── syrth_engine.so       # Compiled shared library (auto-generated on first fast run)
└── benchmark/
    └── <dataset_name>/
        ├── results.json
        ├── metrics.json
        ├── summary.txt
        └── *.png
```

---

## Troubleshooting

**Low accuracy on benchmark**
Ensure the benchmark dataset is distinct from the training dataset. Check that `--testing-dataset` points to a held-out set and not the training data used in `train_model.py`.

**C engine compilation fails**
Verify GCC is installed (`gcc --version`). The header must exist at the path passed to `--engine` (default: `syrth_engine.h`). Check GCC stderr output for specific errors.

**No tokens extracted**
If `collect.py` reports no functions found, the file may contain no top-level function definitions (e.g. it is a configuration or data file). SYRTH operates at the function level.

**Confidence below threshold**
The default threshold is 0.40. Lower it with `--threshold 0.20` to surface uncertain predictions for manual review. Dev mode also prints secondary class probabilities for findings above 5%.

---

## Contributing

### Adding a New Vulnerability Class
1. Add the CWE ID and label to `CWE_LABELS` and `CWE_NAMES` in `harvester.py`
2. Add synthetic templates to the relevant generation function
3. Update `CWE_DESCRIPTIONS` and `CWE_IDS` in `syrth_scan.py`
4. Update `CWE_NAMES` in `train_model.py`
5. Retrain the model

### Extending Sink Detection
Add sink names to `SINK_REGISTRY` in `collect.py`. Sinks are matched by exact name or suffix (e.g. `cursor.execute` matches the `execute` sink).