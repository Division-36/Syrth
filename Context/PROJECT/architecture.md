# Architecture — SYRTH

All claims below are `[FACT]` from the working tree unless marked otherwise.

## Layering

```
source bytes
  ↓
syrth/parser/base.py        byte-safe token/span primitives, FileTrace/FunctionTrace
  ↓
syrth/parser/python.py      intraprocedural analysis, sink detection, trace emission
  │   └─ syrth/parser/guards.py   guard recognition (allowlist/denylist/equality/regex)
  ↓
syrth/taint/engine.py       TaintValue algebra: origins, neutralised, partial, guards
  ↓
syrth/registry.py           THE security model: sinks, sources, sanitisers, CWEs
  ↓
syrth/trace.py              trace certificate, schema v3, structural identity
  ↓
syrth/interproc.py          call graph, fixed-point taint, cross-function traces
  ↓
syrth/scan.py               SyrthScanner, CLI, findings, suppression
  ├─→ syrth/features/extractor.py   88-dim rename-invariant vector
  │      └─→ syrth/classifier/{rule,xgboost,export}.py
  ├─→ syrth/diff.py          revision comparison, patch_status
  ├─→ syrth/patch.py         patch backends + three-condition verification
  └─→ syrth/sarif.py         SARIF 2.1.0
```

`syrth/registry.py` is imported by every layer above it. It is a leaf with no
dependencies on the rest of the package.

## Component responsibilities

| Component | Responsibility | LOC |
|---|---|---|
| `parser/python.py` | Parse a file, propagate taint, emit intraprocedural traces | 1575 |
| `registry.py` | Canonical sink/source/sanitiser/CWE tables | 1298 |
| `scan.py` | `SyrthScanner`, CLI, suppression, findings aggregation | 815 |
| `patch.py` | Deterministic + command patch backends, verification | 637 |
| `interproc.py` | Cross-function reachability with provenance | 513 |
| `features/extractor.py` | Rename-invariant feature vector | 473 |
| `classifier/export.py` | C header export | 433 |
| `classifier/xgboost.py` | Optional learned ranker, persistence, SHAP | 427 |
| `train.py` | Grouped leak-free training entry point | 395 |
| `taint/engine.py` | Taint value semantics and merge rules | 378 |
| `parser/base.py` | Byte-safe primitives, trace containers | 357 |
| `diff.py` | Structural trace diff | 316 |
| `trace.py` | Trace schema and identity | 306 |
| `parser/guards.py` | Guard recognition | 291 |
| `classifier/rule.py` | Deterministic rule classifier | 217 |
| `sarif.py` | SARIF 2.1.0 output | 203 |

## Core data types

- **`TaintValue`** (`taint/engine.py`) — frozen dataclass. Fields: `origins`,
  `neutralised` (categories fully sanitised), `partial` (categories partially
  mitigated), `path` (ordered `TraceStep`s), `constant`, `kills`, `guards`.
  Merge semantics: `neutralised` **intersects**, `partial` **unions**, `guards`
  **unions**. A value is safe for a category only if *every* tainted operand was
  sanitised for it, so a sanitised value cannot launder an unsanitised one.

- **`Trace`** (`trace.py`) — the emitted certificate. Carries `steps`, `origins`,
  `kills`, `confidence`, `param_indices`, `trace_id`. Serialisable; schema
  version 3.

- **`CrossFunctionTrace`** (`interproc.py`) — a chain of function names plus the
  steps and provenance across them.

- **`Finding`** — produced by the scanner for reporting; aggregates a trace with
  severity.

## Critical invariants

1. **Taint is seeded by parameter position, never by identifier spelling.**
   `source_origin()` in the registry is documented as independent of what a name
   is *called*. `[FACT]` A framework request object is recognised by
   `REQUEST_OBJECT_NAMES`/prefixes, which refines the origin *label* only; it
   does not create the taint.

2. **The reporting threshold is `0.5`; `MIN_TAINT_CONFIDENCE` is `0.55`.**
   `[FACT]` Guard deductions are applied **after** the floor. Applying them
   before made the mitigation factor unable to cross the threshold, which
   silently disabled all mitigation ranking. This ordering is load-bearing.

3. **Node text comes from source bytes.** tree-sitter reports byte offsets; the
   reader slices `bytes`, not the decoded `str`. v1 sliced `str` and corrupted
   every identifier after the first multi-byte character in a file.

4. **Trace identity excludes line numbers.** A trace moved down the file keeps
   its identity so revision diffs do not report churn.

5. **A patch is accepted only when three conditions hold:** the targeted flow is
   gone, no new flow appeared, and the file still parses.

6. **No analysed code is ever executed.** The parser only reads.

## Extension points

- Adding a sink → `registry.py` only.
- Adding a guard shape → `parser/guards.py` only.
- Adding a feature → `features/extractor.py`, and bump `FEATURE_SCHEMA_VERSION`.
- Changing trace serialisation → bump `SCHEMA_VERSION` in `trace.py`.

## External integrations

- `tree-sitter` / `tree-sitter-python` — parsing.
- `xgboost`, `scikit-learn`, `numpy`, `joblib` — optional, behind the `ml` extra.
- `shap` — optional, behind the `explain` extra (used by `XGBoostClassifier.explain`).
- `git` — used by `benchmarks/revision_diff.py` only, not by the scanner.