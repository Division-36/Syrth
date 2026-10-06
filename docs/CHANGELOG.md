# Changelog

## Unreleased

### Changed — the product definition

**SYRTH now reports a risk surface, not a verdict.** It answers "what is the
nearest vulnerability class to this code, and how likely is it", not "is this
vulnerable". Every sink contact is reported with a likelihood in `[0,1]` and the
reasons for it. Nothing is withheld for being unlikely.

This retires precision and recall as headline metrics: they describe a classifier,
and this is not one. The previous reporting policy hid low-likelihood results and
then the benchmark counted them as noise, which produced two artefacts that looked
like quality problems — "13.4% recall" and "46.7% false alarms on safe code" —
and were reporting artefacts.

- `--threshold` now marks a finding `below_threshold` and never deletes it. Only
  a suppression file or an inline ignore comment hides output, both deliberate.
- A function now has one nearest class **per sink it touches**. Previously a
  function with any confirmed flow had every other class it touched silently
  dropped.
- Text output, JSON and the `suppressed` bucket reflect the new semantics.

### Fixed

- **`alpha_rename` deleted real findings.** A statement-level `name = ...` was
  classified as a keyword argument, so the binding was excluded from renaming
  while its uses were renamed. The rewritten program was invalid and a confirmed
  CWE-94 flow vanished. A keyword argument must be preceded by `(` or `,` and
  followed by `=`.
- **`alpha_rename` changed the program under test.** `tokenize.untokenize` was
  called with two-tuples, which rebuilds spacing heuristically and truncated a
  backslash line continuation. Now five-tuples, preserving exact layout.
- **`RecursionError` escaped `scan_source`.** `_has_error_node`,
  `_collect_imports` and `_find_functions` recursed over tree depth, which grows
  with expression length. A 500-term operator chain or 600-level nesting crashed
  the analyser. The walks are now iterative with a FIFO order so
  `trace.functions` stays source-ordered, and `_binary` has a depth budget that
  reports truncation rather than crashing.
- **Mitigation ranking was dead code.** `MIN_TAINT_CONFIDENCE` (0.55) was applied
  after the mitigation factor and sat above the reporting threshold (0.5), so no
  mitigation could ever demote a finding. Guard deductions now apply after the
  floor.
- **Guard classification was inverted.** `if x not in ALLOWED: return` is an
  allowlist on the fall-through path, not a denylist.
- **Guard strength never applied.** It was written to one `TraceStep` field and
  read from another.
- **Regex guards never matched.** The string-literal extractor left the opening
  quote attached to the pattern, and the pattern reader took the `argument_list`
  wrapper instead of the string inside it.
- **A function with a confirmed flow lost every other touched class.** The
  pattern-risk pass skipped any function that had any trace. CWE-601 coverage went
  from 0/9 to 9/9 and rename invariance from 97.4% to 99.2%.
- **Findings for two classes on one line collapsed together.** The dedup key
  lacked the CWE.
- **Reported origins could duplicate** (`REQUEST/REQUEST`) when `PARAM` was
  refined to `REQUEST` while already present.
- **`benchmarks.revision_diff` had never executed.** It passed both
  `capture_output=True` and `stdout=` to `subprocess.run`, leaked an open handle
  that raised `PermissionError` on Windows and masked the real error, and shelled
  out to `tar`. Rewritten with `tarfile` and a path-escape guard.
- **`format_html` was registered as an XSS amplifier**, like `mark_safe`, so
  Django's recommended markup idiom was reported. It escapes its arguments and is
  a kill.
- **`interproc._compose` referenced an undefined name** in its fallback branch.
  Verified unreachable through the public API, so latent rather than live.
- **Packaging declared files that did not exist.** `py.typed` was declared but
  absent; MIT was declared with no `LICENSE`; the license classifier was
  deprecated. All three fixed; the build is now warning-free.
- **364 of 510 corpus records did not parse.** Extracted methods arrived
  indented, so they were `IndentationError` fragments. This drove measured recall
  to 9% by feeding the analyser nothing.

### Added

- `syrth/parser/guards.py` — guard recognition: terminating allowlist, denylist,
  equality and anchored-regex validation, graded so a guard lowers likelihood
  without clearing taint.
- `benchmarks/risk_metrics.py` — a harness that measures the risk model's actual
  claims (category coverage, rank agreement, rename invariance, kill rate,
  determinism) and derives ground truth from an **independent AST scan**, never
  from the corpus labels.
- `benchmarks/rltests.py` — a labelled regression gate over `RLTESTS/`.
- `syrth/py.typed`, `LICENSE`.
- Documentation set: `risk-model.md`, `usage.md`, `architecture.md`,
  `internals.md`, `api.md`, `configuration.md`, `benchmark.md`, `limitations.md`,
  `CONTRIBUTING.md`, and `archive/` for the withdrawn v1 documentation.

### Removed

- `syrth/explain/` and `syrth/vocabulary.py` — unreachable; only a legacy test
  imported them, and `explain/risk.py` referenced an undefined name.

### Measured

`[VERIFIED 2026-10-02]`, 498 records, `benchmarks/risk_metrics`:

| metric | value |
|---|---|
| category coverage | 90.5% (57/63) |
| rank agreement | 100% (22/22) |
| rename invariance | 99.2% (494/498) |
| patch kill rate | 85.5% (65/76) |
| determinism | 100% (498/498) |

---

## 3.0.0 - pipeline rewrite and withdrawal of v1 results

### Withdrawn

Every quantitative result from the v1 pipeline is withdrawn. The meta-learner
stage never executed (wrong bundle key, wrong feature width, both swallowed by a
bare `except Exception: pass`); its final step was a hard-coded RCE class index
rather than a learned decision; and it was trained and evaluated with the
ground-truth CWE description supplied as a feature. Additionally the train/test
split was not grouped, ensemble weights were fitted to held-out accuracy, and the
tint extractor seeded taint from a regex on identifier names.

Withdrawn figures: 70.8% held-out, 86.8% real-code, 94.2% advisory-text, 91.6%
and 93.4% record-level, and 100% dev/fast engine agreement. See
[`paper/WITHDRAWN.md`](../paper/WITHDRAWN.md) for the claim-by-claim audit.

### Added

* Trace certificates as the primary output: source, ordered propagation steps,
  sink and sink argument, with a structural identity that excludes line numbers.
* Rename invariance as a designed property — taint is seeded from parameter
  position, and the feature vector contains no identifier-derived field.
* Per-sink argument schemas, so `cursor.execute(sql, params)` is not a finding.
* Category-typed sanitisers with full/partial distinction, and taint amplifiers
  for assertions such as `mark_safe`.
* Interprocedural resolution with taint provenance: a helper called only with
  clean values produces nothing, and cross-function flows carry the whole chain.
* Revision diff with a truthful matcher, and mechanical patch verification
  requiring the flow to be gone, no new flow to appear, and the file to parse.
* SARIF 2.1.0 output with code-flows and stable trace-identity fingerprints.
* A benchmark harness that measures precision, selectivity, abstention rate,
  rename invariance and patch kill rate, with bootstrap confidence intervals,
  and that prints its own invariants (label ties, split leaks).

### Fixed

* **Node text was decoded from the wrong buffer.** tree-sitter reports byte
  offsets; the reader sliced the decoded `str`, silently corrupting every
  identifier, sink and call after the first multi-byte character in a file.
* f-strings, `.format()`, `%`-formatting, keyword arguments, splats,
  comprehensions, augmented assignment, attribute targets and module scope now
  propagate taint.
* Sink resolution no longer depends on `PYTHONHASHSEED`.
* The C engine export: leaves are detected by child pointers, the tree-to-class
  map is read from `tree_info` rather than inferred from the tree index, the
  per-class `base_score` vector is emitted, and `syrth_argmax_class` is
  forward-declared. The generated header now reproduces xgboost's own
  probabilities exactly.
* The test suite terminates: 441 tests in well under a minute, previously an
  indefinite hang.

### Changed

* Package metadata, entry point and dependency declarations now match the code.
  The default install has two dependencies and no PyTorch.
* `syrth_scan.py` is a compatibility shim that forwards to `syrth.scan`.


> ## ⚠ Withdrawn: this document describes the retired v1 pipeline
>
> The figures, dependency lists, API signatures and target tables below refer to
> the v1 implementation, which has been replaced. They are retained for
> provenance and **must not be used as current documentation or quoted as
> results**. The full audit explaining why — including a claim-by-claim table —
> is in [`paper/WITHDRAWN.md`](../paper/WITHDRAWN.md).
>
> Current documentation:
>
> * [`README.md`](../README.md) — what the tool does and claims today
> * [`architecture.md`](architecture.md) — the current design and why
> * [`docs/CHANGELOG.md`](CHANGELOG.md) — what changed, with the withdrawal recorded
>
> The current public API is `syrth.SyrthScanner`, `syrth.scan:main` and
> `syrth.patch`; it takes no PyTorch dependency. Install with
> `pip install -e .` (two dependencies) or `pip install -e ".[ml]"` to add the
> optional learned ranker.


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
- Held-out advisory text: **withdrawn** (see `paper/WITHDRAWN.md`).
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
