# Changelog

All notable changes to SYRTH are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Version note: SYRTH is pre-1.0. The model is trained and validated on real
> data, but the public API and file layout are still stabilising.

## [Unreleased]

### Added
- **Taint-confirmed, function-level scanning.** `syrth_scan.py` now classifies
  each function independently and only raises a **CONFIRMED** finding when
  untrusted input is shown to reach a dangerous sink (a `tainted:<sink>` token
  exists). Safe sink usage (parameterised queries, escaped output, fixed
  commands) is reported as safe / review-only instead of a false positive.
- Taint tracking propagates through string concatenation (`BinOp`) and
  f-strings (`JoinedStr`), so `HttpResponse("..." + x)` and `f"..{x}.."`
  injection patterns are caught.
- `_eval_code.py`: real-code benchmark harness that scans 719 real CVE code
  blocks through the actual `syrth_scan` pipeline and reports per-class accuracy.
- `RLTESTS/`: six real Python source files (one per vulnerability class) plus
  `run_tests.py` for end-to-end verification.

### Changed
- `collect.py`: emits a `tainted:<sink>` token for every confirmed source→sink
  taint edge; source-token matching now resolves normalised forms such as
  `request.args.get` → `<REQUEST_INPUT>`; the `<FILE_PATH>` source pattern no
  longer matches ordinary `os.path.join` usage.
- `repair_dataset.py`: the re-tokeniser now accepts the `tainted` token prefix.
- Train/test split rebuilt from 16,940 real OSV PyPI advisories + 554 synthetic
  code templates, balanced to 5 classes (`_build_5class.py`,
  `_full_dataset_5class.json`).
- Documentation overhauled to match the real project (5 classes, not 8; no
  GitHub-advisory or ensemble-K-fold claims).
- `repair_dataset.py`: added `--code-only` flag (default `True`). Training now
  strips `txt:`, `txt2:`, `severity:`, and `framework:` tokens, keeping only
  AST-derived code features. Dataset rebuilt: 3,584 code-only records (2,085
  dropped, no parseable code tokens). `train_model.py`: ensemble path (K_FOLDS=20)
  deprecated; canonical entrypoint is `train_final_only.py`.
- **Honest metrics (code-only):** held-out 70.8% (277 records), real-code 86.8%
  (719 CVE blocks). No description text, no severity, no framework markers —
  exactly what the scanner sees at inference time.

### Fixed
- False positives on benign code: the old file-level classifier flagged any
  file containing a dangerous sink. The taint gate removes this.
- `_extract_per_function_patterns` now carries the `tokens` field so
  per-function prediction receives the real token sequence.
- Leakage and label-leak issues from earlier splits (the `cwe:` token was
  previously a feature) are excluded.

### Accuracy (this release)
- Held-out advisory text: **94.2%** (976 records, leak-free split).
- Real scanned CVE code: **69.1%** (719 blocks via `_eval_code.py`).
- End-to-end real code: **6/6** (`RLTESTS/run_tests.py`).
- Dev/prod (C engine) agreement: **100%**.

## [0.9.0] - v1-beta tag

### Added
- First internally-trainable 5-class pipeline: `harvester.py` (OSV PyPI bulk
  feed), `_build_5class.py`, `repair_dataset.py`, `train_final_only.py`,
  `syrth_scan.py`.
- C inference engine export (`syrth_engine.h` / compiled `.so`) with byte-for-byte
  agreement to the Python engine.
- `eval_heldout.py` and `check_agree.py` for validation.

### Known Issues
- Advisory *text* accuracy (94.2%) is much higher than scanned *code* accuracy
  (69.1%); many advisory snippets are incomplete and lack a full taint path.
- RCE and PathTraversal are the weakest classes and the most often confused
  with SQLi on fragments.

## Version History Summary

| Version | Status | Key Features |
|---------|--------|--------------|
| Unreleased | in development | Taint-confirmed function-level scanning |
| 0.9.0 | v1-beta | 5-class pipeline, Python + C engines |
| 0.8.0 | Alpha | SQLi-only proof of concept |

## Migration Guide

### From 0.8.0 (Alpha) to 0.9.0 / current

1. **Retrain with the new pipeline**
   ```bash
   python harvester.py
   python _build_5class.py 3000 _full_dataset_5class.json
   python repair_dataset.py --top-k 30000
   python train_final_only.py
   ```

2. **Run scans at function granularity**
   ```bash
   python syrth_scan.py --file app.py --mode dev
   ```
   Look for the `CONFIRMED` marker on functions with a real taint path; other
   findings are review-only.

## Roadmap

### Planned
- [ ] Raise RCE / PathTraversal recall on scanned code
- [ ] Richer taint sources (ORM builders, template engines)
- [ ] Optional richer model (sequence-aware) to exploit `flow:` ordering
- [ ] CI helper that emits SARIF from `syrth_scan.py` JSON output
