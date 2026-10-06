# Technical Reference — SYRTH

## Confidence model

`[FACT]` From `syrth/parser/python.py`:

| Constant | Value | Role |
|---|---|---|
| `BASE_TAINT_CONFIDENCE` | 0.90 | confirmed source→sink, no mitigation |
| `PARTIAL_MITIGATION_FACTOR` | 0.65 | multiplicative, applied when `partial` holds |
| `STEP_DECAY` | 0.01 | per step beyond 3 |
| `MIN_TAINT_CONFIDENCE` | 0.55 | floor **for step decay only** |
| Reporting threshold | 0.50 | CLI default |
| `AMPLIFIER_CONFIDENCE` | 0.60 | `mark_safe`-style amplifiers |

`[FACT]` Guard deductions (`GUARD_STRENGTH` in `taint/engine.py`) are applied
**after** the floor:

| Guard | Deduction |
|---|---|
| `allowlist` | 0.45 |
| `denylist` | 0.25 |
| `equality` | 0.15 |

`[FACT]` A terminating allowlist guard constrains the categories in
`GUARD_REACHABLE_CATEGORIES` = EXEC, SQL, XSS, FILE, REDIRECT. An anchored
regex charset guard constrains **FILE only**, because excluding path separators
says nothing about command injection or HTML.

## Guard recognition

`[FACT]` `parser/guards.py` recognises, in `if <test>: <terminal body>` form:

- `x in ("a","b")` → **denylist** (fall-through avoids the set)
- `x not in ALLOWED` → **allowlist** (fall-through is inside the set)

  `[FACT]` Classification follows the *fall-through* semantics, not the operator.
  Inverting these downgrades the strong pattern to the weak one.
- `x == "c"` / `x != "c"` / `x.startswith(...)` / `x.endswith(...)` → equality
- `not re.match(r"...", x)` → regex guard, only when the pattern is anchored and
  excludes path separators.

`[FACT]` Regex safety rules (`_regex_is_path_safe`): rejects `.` (matches `/`),
`\D`/`\W`, unescaped `/`, and negated classes not naming both `/` and `\`.
Rejection is deliberately one-sided — declaring a hostile pattern safe would hide
a traversal, while refusing to bless a defensive one only costs a warning.

`[FACT]` The guard marker travels as a `TraceStep(kind="guard", edge=<strength>,
detail=<name>)`. It propagates because every value-rebuilding site copies `path`.

`[FACT]` `GUARD_REACHABLE_CATEGORIES` deliberately excludes DESER: a membership
check constrains *which values* reach a sink, but deserialisation danger does not
depend on value content.

## Feature vector

`[FACT]` `FEATURE_SCHEMA_VERSION = 3`, `NUM_FEATURES = 88`.

`[FACT]` Groups: structural 16, taint 12, scat 11, tainted 11, origins 9,
sanitiser 11, sink shape 10, context 8.

`[FACT]` `FeatureExtractor._set(vector, name, value)` raises
`FeatureExtractionError` for an unknown feature name.

## Label space

`[FACT]` `CWE_CLASSES` in `syrth.classifier` (exported from
`syrth/classifier/xgboost.py`; **not** defined in `syrth/registry.py` —
`registry.py` holds `CATEGORIES` and `CATEGORY_CWE`, the category→CWE mapping):

```
CWE-89, CWE-79, CWE-22, CWE-94, CWE-918, CWE-601,
CWE-502, CWE-327, CWE-798, CWE-434, CWE-611
```

`[FACT]` Model bundles refuse to load if `CWE_CLASSES`, `FEATURE_SCHEMA_VERSION`
or trace `SCHEMA_VERSION` disagree with the running package.

`[FACT]` Trace `SCHEMA_VERSION = 3`.

## API surface

`[FACT]` `SyrthScanner` public methods: `scan_source`, `scan_source_pair`,
`scan_file`, `scan_files`, `scan_paths`, `parse`, `suppress`, plus properties
`has_ml`, `model_label`.

`[FACT]` Lazy package exports (`syrth/__init__.py`): `SyrthScanner`,
`diff_sources`, `patch_status`.

`[FACT]` CLI (`syrth.scan:main`, also console script `syrth`): `--path`, `--file`,
`--stdin`, `--json`, `--sarif`, `--traces`, `--fix`, `--model`, `--threshold`,
`--fail-on`.

## Sanitiser semantics

`[FACT]` A `KillSpec` may be:
- **full** — the value is neutralised for the listed categories.
- **partial** (`full=False`) — recorded as partial, confidence multiplied by
  `PARTIAL_MITIGATION_FACTOR`.
- **producing** — an amplifier (`mark_safe`, `Markup`, `SafeString`); the
  assertion itself is the finding.

`[FACT]` `django.utils.html.format_html` is a **full XSS kill**, not an amplifier.
`[FACT]` Earlier in v3 development it was mis-registered as producing; that was
fixed. `format_html` escapes its substituted arguments.

## Benchmark harness

`[FACT]` `benchmarks/run_benchmarks.py`:

- `Record(source, label, group)`. `label` is a CWE string; **empty means safe**.
  `_metrics` partitions on truthiness, so an unsupported CWE still counts as a
  positive and its miss still costs recall.
- `split()` is group-disjoint and returns a leak count so callers can assert it
  is zero.
- `alpha_rename(source, seed)` renames only names the fragment itself binds
  (parameters, assignments, `def`/`class`, loop/with/comprehension targets,
  `except as`, walrus, `global`/`nonlocal`, import aliases). Module paths,
  attribute names, keyword-argument names, and **free names** are never renamed.
- It uses five-tuple `tokenize.untokenize` to preserve exact layout.

`[FACT]` `benchmarks/rltests.py` evaluates the 40 hand-written `RLTESTS/`
functions using their section markers as labels. It is a regression gate, not a
benchmark — the set was authored by this project and contains no real-world
negative class.

`[FACT]` `benchmarks/revision_diff.py` extracts revisions via `git archive` piped
through Python's `tarfile` (not an external `tar`), validating that each member
stays inside the destination.

## Serialisation formats

- Trace JSON: `trace.to_dict()` / `traces_from_json()`, schema-tagged.
- SARIF 2.1.0 with `codeFlows` and stable trace-identity fingerprints.
- Model bundle: `joblib`, carrying label space + both schema versions.

## Build output

`[FACT]` `python -m build --wheel` produces `dist/syrth-3.0.0-py3-none-any.whl`
containing 22 package modules plus `py.typed` and dist-info. `License-Expression:
MIT`. Build completes with no warnings.