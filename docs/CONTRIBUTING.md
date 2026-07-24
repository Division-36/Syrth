# Contributing to SYRTH

Thanks for your interest in SYRTH! This guide covers the development setup and
how the project is organised. SYRTH is pre-1.0, so the layout and CLI are still
stabilising — open an issue before large changes.

## Development Setup

```bash
# Clone
git clone https://github.com/Zierax/Syrth.git
cd Syrth

# venv
python -m venv ~/syrth-venv
source ~/syrth-venv/bin/activate        # Windows: syrth-venv\Scripts\activate
pip install torch numpy scikit-learn joblib

# Train a model so scans work
python harvester.py
python _build_5class.py 3000 _full_dataset_5class.json
python repair_dataset.py --top-k 30000
python train_final_only.py
```

## Project Structure

```
syrth/
├── docs/                 # Documentation (this folder)
├── RLTESTS/              # Real-code end-to-end tests (6 files + runner)
├── collect.py            # AST token extraction + taint engine
├── syrth_scan.py         # Scanning CLI (per-function, taint-confirmed)
├── harvester.py          # OSV PyPI bulk feed + synthetic samples
├── _build_5class.py      # Balanced 5-class dataset builder
├── repair_dataset.py     # Leak-free re-tokeniser / train-test split
├── train_model.py        # SyrthEncoder model definition + C export
├── train_final_only.py   # Training entrypoint used by the pipeline
├── eval_heldout.py       # Held-out advisory-text accuracy
├── check_agree.py        # Dev/prod (C engine) agreement check
├── _eval_code.py         # Real scanned-code benchmark
├── benchmark.py          # Latency/memory benchmark
└── README.md
```

There is **no** `tests/` or `examples/` directory yet — regression coverage
lives in `RLTESTS/` and the accuracy scripts. Add `pytest` suites when you add
features.

## Vulnerability Classes (5)

`SQLi (0)`, `XSS (1)`, `PathTraversal (2)`, `OpenRedirect (3)`, `RCE (4)`.
Class order is fixed in `train_model.py` (`cwe_names`) and the exported C
header — do not reorder.

## How Detection Works

1. `collect.py` parses each function with `ast`, emits structural tokens
   (`def:`, `arg:`, `sink:`) and tracks data flow from untrusted sources to
   sinks. A confirmed source→sink edge produces a `tainted:<sink>` token.
2. The model (`SyrthEncoder`) mean-pools the token embeddings and predicts a
   class — **but it does not see taint structure well** (mean-pool ignores
   order). So `syrth_scan.py` applies the real filter: a function is **CONFIRMED**
   only if it carries a `tainted:<sink>` token.
3. Safe sink usage (parameterised queries, escaped output, fixed commands)
   produces no `tainted:` token and is reported as review-only.

## Areas for Contribution

- **Raise RCE / PathTraversal recall** on scanned code (currently the weakest
  classes; most confusion is with SQLi on fragments).
- **More taint sources**: ORM query builders, template engines, framework
  request objects beyond `request.GET/POST/args`.
- **A sequence-aware model** that exploits `flow:` token ordering (the current
  mean-pool model intentionally ignores it for C-export simplicity).
- **CI helper** emitting SARIF from `syrth_scan.py` JSON output.
- **`pytest` suite** for `collect.py` taint logic and `syrth_scan.py` gating.

## Commit / PR Guidelines

- Keep the label (`cwe:`) **out** of model features — it is the ground truth,
  not a signal. `repair_dataset.py` enforces this; do not bypass it.
- After training changes, run the full validation set:
  ```bash
  python eval_heldout.py      # expect ~94% text accuracy
  python _eval_code.py        # expect ~69% on scanned code
  python check_agree.py       # expect 100% dev/prod agreement
  python RLTESTS/run_tests.py # expect 6/6
  ```
- Update `docs/CHANGELOG.md` and the relevant doc page with any behaviour
  change.
- Use clear commit titles; the repo convention is imperative ("add ...",
  "fix ...", "docs: ...").

## Release Process

1. Bump the version in `syrth_scan.py` / `train_model.py` and
   `docs/CHANGELOG.md`.
2. Confirm all four validation commands above pass.
3. Tag: `git tag -a vX.Y.Z -m "..."` (do not push tags without maintainer
   confirmation).
