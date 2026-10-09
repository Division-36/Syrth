# File Map — SYRTH

`[FACT]` Verified 2026-10-02 against working tree at commit `3a38572` (dirty).
Generated artifacts, caches and vendored clones are omitted.

## Active product — `syrth/`

| Path | Purpose | Depends on | LOC |
|---|---|---|---|
| `syrth/__init__.py` | Public API, lazy exports, `__version__ = 3.0.0` | subpackages | 109 |
| `syrth/registry.py` | **Security model**: sinks, sources, sanitisers, CWEs | — (leaf) | 1298 |
| `syrth/parser/base.py` | Byte-safe primitives, `FileTrace`/`FunctionTrace` | registry | 357 |
| `syrth/parser/python.py` | Intraprocedural analysis, trace emission | registry, taint, trace | 1575 |
| `syrth/parser/guards.py` | Guard recognition | — | 291 |
| `syrth/taint/engine.py` | `TaintValue` algebra, merge semantics | registry, trace | 378 |
| `syrth/trace.py` | Trace certificate, schema 3, identity | — | 306 |
| `syrth/interproc.py` | Call graph, fixed point, cross-function traces | trace | 513 |
| `syrth/scan.py` | `SyrthScanner`, CLI, suppression | all above | 815 |
| `syrth/diff.py` | Revision diff, `patch_status` | trace, scan | 316 |
| `syrth/patch.py` | Patch backends + 3-condition verification | scan, trace | 637 |
| `syrth/sarif.py` | SARIF 2.1.0 | trace | 203 |
| `syrth/features/extractor.py` | 88-dim rename-invariant vector | parser.base | 473 |
| `syrth/classifier/rule.py` | Deterministic classifier | registry, trace | 217 |
| `syrth/classifier/xgboost.py` | Optional learned ranker, persistence | features, sklearn/xgb | 427 |
| `syrth/classifier/export.py` | C header export | xgboost | 433 |
| `syrth/train.py` | Grouped leak-free training | features, classifier | 395 |
| `syrth/py.typed` | PEP 561 marker | — | 0 |

## Tests — `tests/`

| Path | LOC | Area |
|---|---|---|
| `test_analysis_correctness.py` | 627 | taint, parsing, guards, propagation |
| `test_pipeline.py` | 468 | scanner, diff, interproc, SARIF, suppression |
| `test_patch_and_benchmarks.py` | 367 | patch verification, harness, renamer |
| `test_scan.py` | 320 | CLI, output shapes, exit codes |
| `test_parser.py` | 289 | byte safety, tokens, AST handling |
| `test_export.py` | 283 | C header structure + numeric agreement |
| `test_feature_extractor.py` | 234 | feature vector |
| `test_taint.py` | 198 | taint algebra |
| `test_guards.py` | 154 | guard demotion, regex safety, renamer soundness |
| `test_xgboost_classifier.py` | 141 | training, persistence, schema guards |

`[FACT]` No `tests/conftest.py`. Tests import `syrth` from the working tree.

## Benchmarks — `benchmarks/`

| Path | Purpose |
|---|---|
| `run_benchmarks.py` | Main harness: metrics, grouped split, `alpha_rename`, bootstrap CIs |
| `rltests.py` | Labelled `RLTESTS/` regression gate |
| `revision_diff.py` | Two-revision diff CLI |
| `datasets.py` | Corpus loaders (v1-era loaders) |
| `synthetic.py` | Synthetic sample generation |

## Documentation — `docs/`, `paper/`, `legacy/`

| Path | Purpose |
|---|---|
| `docs/measurements.md` | **Measured results, corpus provenance, and failure modes** |
| `docs/architecture.md` | Design and rationale |
| `docs/CHANGELOG.md` | Includes the 3.0.0 rewrite entry and withdrawals |
| `docs/API.md`, `EXAMPLES.md`, `INDEX.md`, `INSTALLATION.md`, `CONTRIBUTING.md` | **v1-era, carry withdrawal banners** |
| `docs/dependency_analysis.md`, `target_specs.md` | **v1-era plans, carry withdrawal banners** |
| `paper/main.tex`, `references.bib` | Revised paper (v1 methodology marked historical) |
| `paper/WITHDRAWN.md` | Claim-by-claim withdrawal of v1 results |
| `paper/main.pdf` | 367 KB compiled artefact |
| `legacy/README.md` | v1 provenance and migration notes |
| `RLTESTS/` | 7 files, 40 labelled functions |

## Configuration

| Path | Purpose |
|---|---|
| `pyproject.toml` | Package metadata, deps, extras, entry point, ruff + pytest config |
| `requirements.txt` | Runtime deps (tree-sitter pair) |
| `Makefile` | Targets: `install`, `install-dev`, `test`, `lint`, `typecheck`, `scan`, `diff`, `bench`, `train`, `build`, `clean` |
| `.gitignore` | Excludes generated corpora, models, engines, `experiments/scratch/` |
| `LICENSE` | MIT |

## Retired — do not treat as current

| Path | Status |
|---|---|
| `syrth_scan.py` | **Deprecation shim** forwarding to `syrth.scan` |
| `experiments/` | Scratch space and the record of the deleted v1 scripts |
| `experiments/scratch/` | Untracked local scratch; gitignored |
| `benchmark.py`, `collect.py`, `harvester.py`, `train_model.py`, `repair_dataset.py`, `eval_heldout.py`, `check_agree.py`, `train_final_only.py` | v1 root scripts, unmaintained |
| `*.joblib`, `syrth_codebert/`, `syrth_engine.{h,so}` | v1 model/header artefacts on disk, gitignored, **not loadable by v3** |
| `_*.json`, `testingMassiveDataset.json` | v1 generated datasets, gitignored |

## Absent

`[FACT]` No `.github/` — **there is no CI**. No `Dockerfile`. No `setup.py`.
No `package.json`/`Cargo.toml`/`go.mod` (pure Python project).