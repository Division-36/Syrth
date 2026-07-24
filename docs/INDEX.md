# SYRTH Documentation Index

SYRTH (**S**can **Y**our **R**isk **T**race **H**istory) is an AST-based
static scanner that detects taint-style vulnerabilities in Python source by
classifying whether untrusted input reaches a dangerous sink.

## Documentation Structure

### [README.md](../README.md)
Project overview, architecture, training/scanning pipeline, and honest
accuracy numbers.

### [API.md](API.md)
Core classes, command-line tools, token format, and model bundle layout.

### [INSTALLATION.md](INSTALLATION.md)
System requirements, virtual-environment setup, and verification steps.

### [EXAMPLES.md](EXAMPLES.md)
Scanning, CI integration, and reading the taint-confirmed JSON output.

### [CONTRIBUTING.md](CONTRIBUTING.md)
Development setup, project layout, and how to extend detection.

## Vulnerability Classes (5)

| ID | Class | CWE | Example sink |
|----|-------|-----|--------------|
| 0 | SQL Injection (SQLi) | CWE-89 | `cursor.execute` with string-built SQL |
| 1 | Cross-Site Scripting (XSS) | CWE-79 | `HttpResponse`/`render` with raw input |
| 2 | Path Traversal | CWE-22 | `open`/`os.path.join` with user path |
| 3 | Open Redirect | CWE-601 | `redirect`/`HttpResponseRedirect` with user URL |
| 4 | Remote Code Execution (RCE) | CWE-94 | `subprocess`/`eval`/`os.system` with input |

## Quick Start

```bash
# 1. Create a venv and install dependencies
python -m venv ~/syrth-venv
source ~/syrth-venv/bin/activate
pip install torch numpy scikit-learn joblib

# 2. Build the training dataset (OSV PyPI + synthetic, balanced to 5 classes)
python harvester.py
python _build_5class.py 3000 _full_dataset_5class.json

# 3. Repair / re-tokenise the dataset (leak-free, label excluded)
python repair_dataset.py --top-k 30000

# 4. Train (Python + C engine export)
python train_final_only.py

# 5. Scan a file (function-level, taint-confirmed)
python syrth_scan.py --file your_app.py --mode dev
```

## Key Features

### Taint-Confirmed Detection
SYRTH only reports a function as **CONFIRMED** when untrusted input actually
reaches a dangerous sink. Safe usage (parameterised queries, escaped output,
fixed commands) is reported as safe / review-only, which keeps false positives
low on real code.

### Two Engines
- **Python engine** (`syrth_scan.py --mode dev`) — easy to debug.
- **C engine** (`syrth_engine.h`, compiled to `.so`) — identical results,
  faster; `check_agree.py` verifies 100% agreement.

### Honest Evaluation
- Held-out (code-only, no description text): **70.8%** (277 records, leak-free).
- Real scanned CVE code: **86.8%** (719 blocks, via `_eval_code.py`).
- End-to-end real code: **6/6** (`RLTESTS/run_tests.py`).

## Performance Benchmarks

`python benchmark.py` measures latency/memory for both engines and writes
charts to `benchmark/`. Typical results:

| Metric | Python Engine | C Engine |
|--------|---------------|----------|
| Mean latency | ~500µs | ~20µs |
| Throughput | ~2K/s | ~50K/s |

## Project Layout

```
syrth/
├── docs/                 # This documentation
├── RLTESTS/              # Real-code end-to-end tests (6 files + runner)
├── collect.py            # AST token extraction + taint engine
├── syrth_scan.py         # Scanning CLI (per-function, taint-confirmed)
├── harvester.py          # OSV PyPI bulk feed + synthetic samples
├── _build_5class.py      # Balanced 5-class dataset builder
├── repair_dataset.py     # Leak-free re-tokeniser
├── train_model.py        # SyrthEncoder model + C export
├── train_final_only.py   # Training entrypoint used by the pipeline
├── eval_heldout.py       # Held-out text accuracy
├── check_agree.py        # Dev/prod agreement check
├── _eval_code.py         # Real-code (scanned) benchmark
├── benchmark.py          # Latency/memory benchmark
├── README.md
└── docs/CHANGELOG.md
```

## Common Tasks

| Task | Command |
|------|---------|
| Build dataset | `python _build_5class.py 3000 _full_dataset_5class.json` |
| Repair tokens | `python repair_dataset.py --top-k 30000` |
| Train | `python train_final_only.py` |
| Scan a file | `python syrth_scan.py --file app.py --mode dev` |
| Held-out accuracy | `python eval_heldout.py` |
| Dev/prod agreement | `python check_agree.py` |
| Real-code benchmark | `python _eval_code.py` |
| End-to-end tests | `python RLTESTS/run_tests.py` |

## External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE](https://cwe.mitre.org/)
- [OSV (Open Source Vulnerabilities)](https://osv.dev/)
- [PyTorch](https://pytorch.org/), [scikit-learn](https://scikit-learn.org/), [joblib](https://joblib.readthedocs.io/)
