# SYRTH Architecture

How the current system is put together, and why. This document describes the
implementation as it exists; it does not carry forward the performance targets
from earlier drafts, because those were not met and no replacement measurement has
been completed. See `paper/WITHDRAWN.md` for the audit trail.

## The organising idea

The output of this tool is a **trace certificate**, not a class label. Every other
design decision follows from that choice.

A label is a point. A trace is a path with a source, ordered propagation steps, a
sink, and the argument position it reached. Three capabilities fall out of the
path having an identity:

1. **A finding is checkable.** A reviewer reads the path and sees the argument.
2. **A patch is verifiable.** Re-analyse after the patch and ask whether the
   specific flow is gone.
3. **Two revisions are comparable.** Match traces by structural identity, which
   excludes line numbers, and report what a change introduced, killed, or left.

```
source ──► PythonParser ──► FileTrace
                              │
                              ├─► FeatureExtractor ──► vector ──► XGBoost (optional)
                              │
                              └─► Trace set ──► CallGraph ──► ScanReport
                                                     │
                                                     ├─► SARIF 2.1.0 / JSON / text
                                                     └─► syrth.diff ──► patch verification
```

## Layers

### 1. Registry — `syrth/registry.py`

The single source of truth. Everything security-relevant is declared here and
nowhere else, which is what prevents the token stream and the feature vector from
disagreeing about what a sink is.

Three ideas carry the design.

**One canonical sink per operation.** `cursor.execute`, `conn.execute` and
`cur.executemany` all resolve to `SQL_EXECUTE`. The previous registry keyed sinks
by literal spelling, which created several distinct "sinks" for one operation and
made flow tokens disagree with feature flags.

**Deterministic resolution.** Call names are resolved by exact match, then by
import binding, then by a longest-suffix match over a **pre-sorted** candidate
list. The previous implementation iterated a `frozenset` and broke on the first
match; because string hashing is randomised per process, the same file produced
different tokens under different `PYTHONHASHSEED` values, and training and
inference built different vocabularies.

Short, ambiguous names (`load`, `loads`, `run`, `new`, `write`) are *only* sinks
when the program imported them from a module that makes them dangerous.
`from pickle import loads` is a sink; `from json import loads` is not. That is
handled by `Bindings`, populated during import traversal, not by guessing.

**Argument schemas.** Each `SinkSpec` declares which positional indices and
keyword names are dangerous and which are structurally safe:

| Sink | Dangerous | Structural kill |
|---|---|---|
| `SQL_EXECUTE` | position 0, kwargs `sql`/`query`/`statement` | position 1+, kwargs `parameters`/`params`/`args` |
| `XSS_TEMPLATE_NAME` | position 1 (the template), **not** position 0 (the request object) | positions 0, 2, 3 |
| `EXEC_COMMAND` | position 0, kwargs `args`/`command` | `env`, `cwd`, `input` |
| `DESER_UNSAFE` | position 0 | — |

This is what makes `cursor.execute(sql, params)` distinguishable from
`cursor.execute(f"...{x}")`. Without it, every argument is dangerous and safe code
is indistinguishable from unsafe code.

### 2. Taint — `syrth/taint/engine.py`

A `TaintValue` carries three independent things:

* `origins` — which taint origins reached the value (`PARAM`, `REQUEST`, `ENV`,
  `STDIN`, `CLI`, `FILE_READ`, `NET_READ`, `DB_READ`, `GLOBAL`)
* `neutralised` — categories a **full** sanitiser has rendered safe for this value
* `partial` — categories with only a **partial** mitigation

Origins are a set rather than a label, which is what allows kills to be
category-typed: `shlex.quote` adds `EXEC` to `neutralised`, so the sanitised value
can still be reported for SQL injection.

**Merge semantics are the load-bearing detail.** Only *tainted* operands
participate in the neutralisation intersection. An untainted literal beside a
sanitised value must not launder the sanitisation:

```python
os.system("ls " + shlex.quote(x))   # suppressed: only tainted operand is sanitised
execute("SELECT " + safe(x) + raw)  # reported:  one of two tainted operands is not
```

The parser delegates to the engine rather than reimplementing this rule. Two
copies of the merge rule is how the previous release ended up with a front end and
a library that disagreed about what sanitisation meant.

### 3. Parser — `syrth/parser/`

A tree-sitter front end. Two correctness requirements shape it.

**Decode spans from bytes.** tree-sitter reports node positions as byte offsets
into UTF-8. Slicing the decoded `str` with those offsets silently corrupts every
node after the first multi-byte character. The previous reader did exactly that,
which renamed every function, sink, argument and call in any file containing a
non-ASCII character — including all eight functions in the project's own flagship
test file. `_parse_source` therefore returns the tree *and* the exact bytes, so
the bug is structurally hard to reintroduce.

**Complete expression coverage.** Every Python expression form participates in
taint propagation: f-string `interpolation` nodes, `.format()`, `%`, implicit
literal concatenation, keyword arguments, splats, comprehensions (whose loop
variables are bound in a first pass, because tree-sitter emits the element
expression *before* the `for_in_clause` even though Python evaluates it last),
augmented assignment, attribute and subscript targets, `with` targets, walrus
bindings, and module scope.

The traversal reads node **positions**, not node types, to locate the two sides
of `for x in y` — both are usually bare identifiers, so matching by type is
wrong.

### 4. Interprocedural — `syrth/interproc.py`

A call graph with **provenance**, not just reachability.

Parameters are seeded symbolically (`PARAM#<index>`), so a function's summary
records exactly which of its parameters reach each sink. A fixed point then
propagates taint down call edges and records *which entry point* is responsible
for tainting each parameter.

Provenance is what makes the output honest. Without it, a helper that is never
called looks identical to a helper reached from every HTTP handler. With it:

* a helper called only with constant arguments produces nothing;
* a flow crossing `entry → build_query → execute` is reported with the whole
  chain, and a sanitiser applied inside the helper is shown to have killed the
  caller's flow.

The fixed point is monotone over finite sets, so it terminates; recursion is
handled by the iteration bound, which is asserted in the test suite.

### 5. Traces — `syrth/trace.py`

The certificate. `trace_id` is a hash of the flow's *structure* — function,
canonical sink, sink argument, origin set, and the full sequence of propagation
edges — deliberately excluding line numbers.

There is deliberately **no** looser fallback matching that ignores the
propagation edges. Such a fallback silently pairs two different flows: rewriting
`os.system("ls " + x)` into `eval(x)` produces two traces sharing function, sink,
argument and origins, and a loose matcher would report that substitution as "the
same flow, moved" — so a patch trading one code-execution injection for another
would be recorded as a fix.

### 6. Classification — `syrth/classifier/`

The rule path is not a weaker copy of the model. It reads the **confirmed traces**
and classifies the category of a flow that has already been proven, on an explicit
evidence ladder:

| Evidence | Confidence |
|---|---|
| confirmed source-to-sink flow | 0.90 |
| sanitiser assertion creating a sink | 0.60 |
| exactly one sink category reached, no flow | 0.40 |
| several categories reached | 0.25 |
| nothing | 0.00 |

The previous rule path returned a *vote share*, which reached `1.0` on a single
weak signal and made any reporting threshold meaningless.

The ML path (`XGBoostClassifier`) emits from the same closed label space, derived
from `CATEGORY_CWE` so the two cannot drift apart — the previous release had a
five-class rule path and a fifteen-class model path, so one report could contain
labels from two disjoint spaces.

**The model refines; it never decides.** A confirmed trace is reported whether or
not a model is loaded. A model bundle records the feature schema version and the
label space, and refuses to load against a mismatched build rather than silently
scoring a wrong-width vector. A prediction failure is recorded on that one
record and does not disable the model for the rest of the file.

### 7. Diff and patch — `syrth/diff.py`, `syrth/patch.py`

A patch is accepted only when three conditions hold:

1. the targeted flow is **gone** — not merely reshaped;
2. **no new** flow appeared anywhere in the file;
3. the file still **parses**.

Condition 2 is what makes automation safe: silencing one finding by introducing
another is a regression. Condition 1's "not merely reshaped" is what stops
`os.system(cmd)` → `eval(cmd)` from being recorded as a fix.

The deterministic backend applies the category-typed sanitiser for the categories
where that is a complete fix, and **declines** the rest with a recorded reason.
SQL is declined: converting a statement to a parameterised query requires
deriving placeholders from the original literal, which no mechanical rewrite can
do soundly. Emitting a plausible-looking but wrong query would be worse than
emitting nothing.

`CommandBackend` is the seam for an LLM or a human. SYRTH ships no model and does
not pretend to; whatever produces the rewrite is judged by the same three
mechanical criteria.

### 8. Output — `syrth/sarif.py`, `syrth/scan.py`

SARIF 2.1.0 with `codeFlows` carrying the trace path and a
`partialFingerprints` entry keyed on trace identity, so a consumer can track a
finding across revisions.

The text renderer is ASCII-only. The previous renderer used box-drawing
characters and raised `UnicodeEncodeError` under the default Windows console
codec, which is why the end-to-end harness had to capture stdout rather than read
it.

## Cross-cutting guarantees

**Determinism.** Canonical sink resolution never iterates a hash-ordered
collection. Directory walks sort at every level. Finding ordering is a total
function of a finding's own fields. Running under a different `PYTHONHASHSEED`
produces identical output.

**Degradation is explicit.** A missing model, a corrupt model bundle, a malformed
source file, an unreadable file, a broken suppression file and a broken external
patch backend each have a defined, tested behaviour. A missing model produces a
warning and a rules-only run; it never changes the finding set. A read failure is
recorded on the report rather than aborting a repository scan. A failed baseline
scan is surfaced in the diff, because a baseline that failed to scan must never be
reported as "the patch fixed everything".

**Boundaries are validated, not assumed.** A model bundle whose feature width,
schema version or label space differs from the running build raises
`SchemaMismatch`. A C export whose per-class tree count cannot be determined from
the model's `tree_info` raises rather than guessing class boundaries. An oversized
C header is refused with an actionable message rather than written.

## Schema versioning

| Artefact | Version | Enforcement |
|---|---|---|
| Feature vector | `FEATURE_SCHEMA_VERSION = 3` | bundles record it; `load_model` refuses a mismatch |
| Trace certificate | `SCHEMA_VERSION = 3` | `Trace.from_dict` refuses a mismatch |
| C header | embeds `SYRTH_FEATURE_SCHEMA_VERSION` | a consumer can check before scoring |

A silent mismatch is the failure mode that made the previous meta-learner dead
rather than loudly broken, so every cross-artefact boundary in the current system
is checked.

## What is deliberately not modelled

*   Path, field and alias sensitivity. A value assigned to an attribute propagates
    to every read of that attribute.
*   Class-qualified names. Two same-named methods in different classes are merged,
    and the report says so rather than guessing.
*   Flow sensitivity within a function. Both branches of a conditional are
    analysed and merged, which over-approximates reachability — sound for finding
    flows, and the reason a guard clause is a *partial* mitigation rather than a
    kill.
*   User-defined wrappers around library sinks beyond what the call graph
    resolves, and libraries that re-execute a string internally.
