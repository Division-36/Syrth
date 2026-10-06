# Testing — SYRTH

## Framework and configuration

`[FACT]` pytest, configured in `pyproject.toml`:

```toml
testpaths = ["tests"]
addopts = "-q --tb=short --durations=10"
filterwarnings = ["error::DeprecationWarning:syrth.*"]
```

`[FACT]` 460 tests total across 10 files. Verified result:
**459 passed, 1 skipped**.

`[FACT]` `tests/*` is exempt from ruff `E402` (module-level import not at top of
file), because test files do path setup before importing `syrth`.

## Commands

```
python -m pytest tests -q                                   # project addopts
python -m pytest tests -q -o addopts=                       # raw summary line
python -m pytest tests/test_guards.py -q -o addopts=
python -m ruff check syrth tests benchmarks
```

## Test inventory

| File | Tests | Focus |
|---|---|---|
| `test_analysis_correctness.py` | 131 | taint propagation, parsing, byte safety, guards, malformed input |
| `test_patch_and_benchmarks.py` | 51 | patch verification, harness metrics, `alpha_rename` soundness |
| `test_parser.py` | 54 | tokens, byte offsets, AST shapes, unicode |
| `test_pipeline.py` | 54 | scanner, diff, interproc, SARIF, suppression |
| `test_scan.py` | 44 | CLI, output shapes, exit codes |
| `test_feature_extractor.py` | 36 | 88-dim vector, feature errors |
| `test_taint.py` | 38 | `TaintValue` merge semantics |
| `test_export.py` | 16 | C header structure, numeric agreement with xgboost |
| `test_xgboost_classifier.py` | 15 | training, persistence, schema guards |
| `test_guards.py` | 19 | guard demotion, regex safety, renamer soundness |

## Skip conditions

`[FACT]` `tests/test_export.py`:

- `pytest.importorskip("xgboost")`, `pytest.importorskip("sklearn")`
- `@pytest.mark.skipif(shutil.which("cc") is None and shutil.which("gcc") is None)`

`[FACT]` `tests/test_xgboost_classifier.py`: `importorskip` on `xgboost`,
`sklearn`.

`[FACT]` **The 1 observed skip is the C-compiler test.** The ML tests currently
run because xgboost and sklearn are installed in this environment. On a machine
without them, roughly 31 further tests would skip — which would materially weaken
the suite.

## What the suite verifies well

`[INFERENCE]` Structural and behavioural correctness is genuinely covered:
byte-safe spans, rename invariance of the feature vector, guard demotion,
interprocedural provenance, patch verification's three conditions, SARIF shape,
schema-version rejection, determinism across runs, and CLI exit codes.

## Coverage gaps

`[FACT]` **No test asserts detection recall or precision.** The suite proves the
engine behaves as designed; it does not prove the engine *detects* much. This is
the central gap — see `STATE/known_issues.md` KI-001.

`[FACT]` No CI. Nothing runs automatically on commit; a regression can land
silently.

`[FACT]` No corpus-based regression test. `benchmarks/rltests.py` exists and is
runnable, but is not wired into `pytest`.

`[FACT]` `make typecheck` cannot run — `mypy` is undeclared.

`[FACT]` No static type checking is enforced despite the package shipping
`py.typed` and being fully annotated.

`[FACT]` `paper/main.tex` is not compiled in any check.

## Required validation before reporting work done

```
python -m pytest tests -q -o addopts=      # expect 459 passed, 1 skipped
python -m ruff check syrth tests benchmarks # expect All checks passed
```

If either differs, report the actual output. Do not describe an unrun command as
passing.