# Internals

Implementation detail. Read [architecture.md](architecture.md) first.

## The registry is the security model

`syrth/registry.py` is a leaf with no internal dependencies. Everything else
consults it. Nothing outside it decides whether a call is dangerous.

| Table | Contents |
|---|---|
| `SINK_SPECS` | canonical sinks, their CWE, dangerous argument positions, safe positions, safe kwargs |
| `CATEGORIES`, `CATEGORY_CWE` | the closed category set and its CWE mapping |
| `_KILL_EXACT`, `_KILL_SUFFIX`, `_KILL_IMPORT` | sanitisers by exact name, suffix and import binding |
| `_SOURCE_CALLS`, `REQUEST_OBJECT_NAMES` | taint sources |
| `SECURITY_DECORATORS`, `RISK_AMPLIFYING_DECORATORS` | authentication decorators; `csrf_exempt` |
| `FRAMEWORK_MAP` | framework detection for origin refinement |

Adding a sink is a one-file change. Any code that decides "is this dangerous?"
outside the registry is a bug.

### Argument schemas

Sinks carry which argument positions are dangerous and which are safe. This is
what makes

```python
cursor.execute("SELECT * FROM t WHERE id=" + n)   # CWE-89
cursor.execute("SELECT * FROM t WHERE id=%s", (n,))   # not reported
```

behave correctly, and it is why a shared helper takes a `bindings` argument: the
resolver distinguishes `from pickle import loads` (dangerous) from
`from json import loads` (safe) by resolving the import rather than guessing.

## Taint algebra

`TaintValue` is a frozen dataclass.

| Field | Meaning |
|---|---|
| `origins` | taint sources that reached the value |
| `neutralised` | categories fully sanitised |
| `partial` | categories partially mitigated |
| `path` | ordered `TraceStep`s, source first |
| `constant` | compile-time constant |
| `kills` | sanitiser names seen |
| `guards` | guard descriptors constraining the value |

**Merge semantics.** `neutralised` **intersects**, `partial` and `guards`
**union**. A value is safe for a category only if *every* tainted operand was
sanitised for it — so a sanitised value cannot launder an unsanitised one.

### Taint is seeded by position, not spelling

Every parameter is a potential source regardless of its name. A framework request
object is recognised by name, but that only **refines the origin label**
(`PARAM` → `REQUEST`); it never creates taint. This is what makes the analysis
invariant under renaming.

`refine_origin` de-duplicates: when the origin set already contains `REQUEST`
alongside `PARAM`, refining `PARAM` → `REQUEST` would otherwise yield the same
origin twice.

## Confidence model

`syrth/parser/python.py`:

| Constant | Value | Role |
|---|---|---|
| `BASE_TAINT_CONFIDENCE` | 0.90 | confirmed source→sink, no mitigation |
| `PARTIAL_MITIGATION_FACTOR` | 0.65 | multiplicative, when `partial` holds |
| `STEP_DECAY` | 0.01 | per step beyond 3 |
| `MIN_TAINT_CONFIDENCE` | 0.55 | floor **for step decay only** |
| `CONFIDENCE_PATTERN_RISK` | 0.40 | ceiling on a sink contact with no flow |
| `MAX_EXPRESSION_DEPTH` | 150 | recursion budget for operator chains |

**Ordering is load-bearing.** Guard deductions are applied **after** the
confidence floor. Applying them before meant `MIN_TAINT_CONFIDENCE` (0.55) sat
above the reporting threshold (0.5) and no mitigation could ever demote a
finding — the entire mitigation ranking path was dead code. This was found by the
RLTESTS regression gate, not by reading the code.

### Guard strengths

`syrth/taint/engine.py`:

| Guard | Deduction | Recognised shape |
|---|---|---|
| `allowlist` | 0.45 | `if x not in ("a","b"): return` |
| `denylist` | 0.25 | `if x in BLOCKED: return` |
| `equality` | 0.15 | `if x == "c"`, `x.startswith(...)`, anchored regex |

Classification follows the **fall-through** semantics, not the operator's surface
form. `x not in ALLOWED` is an allowlist because the code after it only sees
allowlisted values. Getting this backwards downgrades the strong pattern to the
weak one.

A regex guard must be anchored and exclude path separators. The checker rejects
`.` (which matches `/`), `\D` and `\W`, and any negated character class not
naming both separators. Rejection is one-sided on purpose: declaring a hostile
pattern safe would hide a traversal, while refusing to bless a defensive one only
costs a warning.

## Guards travel with the value

`_apply_guards` appends a `TraceStep(kind="guard", edge=<strength>, detail=<name>)`
to the value's `path`. Every value-rebuilding site copies `path`, so the guard
reaches the sink even through expressions that rebuild the value from scratch.
Threading a field through every construction site would have been a larger change
with more places to get wrong.

## Interprocedural resolution

`CallGraph` propagates taint to a fixpoint, tracking for each tainted parameter
which **entry points** are responsible. A helper called only with clean values
produces nothing, and a helper called from ten places produces one trace per
responsible entry, not ten.

The fallback branch in `_compose` references `sink_summary`, not `summary`. It is
verified unreachable through the public API, so it is a latent defect fixed
defensively rather than a live bug.

## Bounded traversal

Three tree walks are iterative — `_has_error_node`, `_collect_imports`,
`_find_functions`. Recursing over tree depth overflowed the interpreter stack on
long operator chains, raising `RecursionError` out of `scan_source`. A static
analyser that crashes on minified or generated input is a denial of service on
its own primary function.

They use a **FIFO head index**, not a stack: `trace.functions` is source-ordered
and is part of the observable contract.

## Renaming, in the harness

`benchmarks/run_benchmarks.py` renames only names the fragment itself binds:
parameters, assignments, `def`/`class`, loop and `with` targets, comprehension
targets, `except ... as`, walrus targets, `global`/`nonlocal`, and import
aliases. Module paths, attribute names, keyword-argument names and **free names**
are never renamed — a free name in a fragment whose imports are not visible may be
a sink, and renaming it deletes the thing under test.

Two bugs here were found by the invariance metric itself:

- `tokenize.untokenize` was called with two-tuples, which rebuilds spacing
  heuristically and truncated a backslash line continuation, changing the program.
  Now five-tuples, preserving exact layout.
- A statement-level `name = ...` was classified as a keyword argument, so the
  assignment was excluded from renaming while every use was renamed. A keyword
  argument must be preceded by `(` or `,` **and** followed by `=`.

## Schemas

| Schema | Version | Enforced by |
|---|---|---|
| feature vector | 3 | bundles refused on mismatch |
| trace | 3 | `traces_from_json` refuses a foreign version |
| label space | 11 CWEs | bundles refused on mismatch |

## Optional C export

`classifier/export.py` emits a C header that reproduces xgboost's probabilities
exactly. Fixed during this cycle: leaf detection by child pointer, the
tree-to-class map from `tree_info` rather than the tree index, the per-class
`base_score` vector, a forward declaration, and a 4 MiB output guard. The header
is verified against live xgboost in `tests/test_export.py`, which **skips without
a C compiler** — so on a machine without one, that agreement is untested.