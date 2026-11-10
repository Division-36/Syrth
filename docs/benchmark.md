# Benchmark

How SYRTH is measured, and what the current numbers are.

## Why the metrics are unusual

SYRTH is a risk-surface tool, not a classifier. It does not decide "vulnerable or
not", so it has no positive class, no negative class, and no decision threshold.
Precision and recall are not defined for it. See [risk-model.md](risk-model.md).

## What is measured

| metric | question it answers |
|---|---|
| **category coverage** | of the vulnerability classes whose sinks the source provably contains, how many were named? |
| **rank agreement** | when two findings in one function differ in evidence strength, is the better-evidenced one first? |
| **rename invariance** | does the reported class set survive renaming every local? |
| **kill rate** | does the category's own mitigation remove the confirmed flow? |
| **patch study** | applying the corpus's *real* fix commits: does the labelled flow's certificate survive, get removed, or get replaced? |
| **determinism** | does a repeat scan of identical input produce identical output? |

### Which command produces which number

Every figure quoted on this page comes from one of these commands, and the
result is published next to the documentation that quotes it.

| figure | command | published file |
|---|---|---|
| category coverage, rank agreement, rename invariance, kill rate, determinism | `python -m benchmarks.risk_metrics --dataset data/corpus.jsonl` | `data/risk_benchmark.json` |
| the Bandit, Semgrep and Ruff rows | `python -m benchmarks.competitors --dataset data/corpus.jsonl` | `data/competitor_benchmark.json` |
| certificate identity under renaming | `python -m benchmarks.identity --dataset data/corpus.jsonl` | `data/identity_rename.json` |
| the component ablation | `python -m benchmarks.ablation --dataset data/corpus.jsonl` | `data/ablation.json` |
| the real-commit patch study | `python -m benchmarks.patch_study --dataset data/corpus.jsonl` | `data/patch_study.json` |
| the whole-repository replay | `python -m benchmarks.whole_repo_study --dataset data/corpus.jsonl --repos experiments/scratch/repos` | `data/whole_repo_study.json` |

The whole-repository replay needs the repositories checked out under
`experiments/scratch/repos` and takes hours; the rest run in seconds. The
corpus itself is rebuilt from pinned coordinates by `python tools/build_corpus.py`
and is not committed, because it is third-party source under mixed licences;
`python tools/freeze_corpus.py` produces a checksummed archive of it.

`make verify-published` re-runs every command in the table and compares the
result with the published file, field by field. It exits non-zero when a
published number no longer matches its harness, and it names the fields it
does not compare rather than ignoring them quietly.

### How ground truth is derived

The harness runs its **own AST scan** over each record to determine which
vulnerability classes are actually present, then compares that against what SYRTH
reported. It **never reads the corpus labels**.

This matters because corpus labels have been unsound before. The superseded
corpus labelled every function a fix commit touched with that commit's CWE, which
produced a 1.7x inflation and counted defensive helpers as "vulnerable". A
harness that trusted those labels would inherit the defect and report it as an
analyser property. See [corpus_failure_diagnosis.md](corpus_failure_diagnosis.md).

`data/corpus.jsonl` does not repeat that mistake: a record is only accepted as
vulnerable when its own source demonstrably contains the class's sink, resolved
through `syrth.registry` so the corpus and the analyser agree on what a class
means. That is a deliberate trade -- see [limitations.md](limitations.md) for why
it makes the corpus narrower than the raw advisory count.

Two corpora are reported below. They are not interchangeable, and the difference
between them is the main methodological point on this page.

## Current results

### `data/corpus.jsonl` -- the built corpus (current)

`[VERIFIED 2026-10-04]` -- 350 records / 175 pairs / 24 advisories / 24
repositories / 7 CWE classes, built by `tools/build_corpus.py`:

```console
$ python -m benchmarks.risk_metrics --dataset data/corpus.jsonl
==================================================================
SYRTH risk-model benchmark
==================================================================
records with sinks found      : 100/350
category coverage             : 111/116 = 95.7%
rank agreement (better-evidence first): 22/22 = 100.0%
rename invariance             : 350/350 = 100.0%
patch kill rate (confirmed)   : 79/104 = 76.0%
determinism (repeat run)      : 350/350 = 100.0%

per class (covered/expected):
  CWE-22     41/44
  CWE-502    15/15
  CWE-601    17/17
  CWE-79     10/12
  CWE-89     4/4
  CWE-918    4/4
  CWE-94     20/20

by corpus evidence tier:
  direct-sink     = the labelled source itself calls the sink
  module-proximity= it produces a value for a sink elsewhere in the same module
  direct-sink       93/95 = 97.9%  (134 records)
  module-proximity  18/21 = 85.7%  (216 records)

WARN: 4.3% of the vulnerability classes present in the source were not named
```

#### The two evidence tiers

A record is only labelled vulnerable if the *patched function* is the one the fix
touched. Some fixes cannot be labelled at function granularity: Django's
`PostGISOperator.as_sql` **builds** the SQL and returns `(sql, params)`, and a
compiler elsewhere calls `cursor.execute`. The touched function never calls
`execute`.

Rejecting those loses CWE-89 entirely. Accepting them silently would overstate the
guarantee, because a same-module `execute` proves only that the module contains a
sink. So the corpus carries both, named per record, and the benchmark reports them
separately. `direct-sink` is a proof about the labelled source; `module-proximity`
names the module-level sink it relied on and is checkable against the recorded
repo, commit and file.

### Reading these numbers honestly

- **Coverage denominators are small: 111 and 116.** These are the classes an
  independent AST scan can prove are present, not every class the corpus could
  contain. A single missed record moves the figure by roughly 0.9 points.
- **Rank agreement is a consistency check, not a statistic.** 22/22 means that
  whenever two findings in one function differ in evidence strength, the
  better-evidenced one is reported first. It says nothing about how often the
  tool finds a real vulnerability.
- **Kill rate measures the corpus, not the tool.** 89/100 is the share of patched
  records where the class's own mitigation removed the confirmed flow. A patch
  that replaces a vulnerable call with a validation check leaves the sink call in
  place by design, so the record still reports. Those cases are the boundary
  described in [What the survivors are](#what-the-survivors-are-and-what-they-are-not).
- **Determinism and rename invariance are properties, not scores.** They show that
  the same input twice gives the same answer, and that renaming identifiers does
  not change the reported classes. Both are at 100%.


## The kill-rate question, adjudicated

`[VERIFIED 2026-10-04]` -- patch kill rate rose from **76.0% to 89.0%** with
category coverage unchanged at 95.7%. The rise came from three defects the corpus
exposed, each with a minimal reproduction.

Every one of those three is a *reporting* defect: a sanitiser that was not consulted,
an import that did not bind, an assertion about a literal. None of them required a
model. They were found because the corpus expected a sink to disappear, and it had
not.

### 1. A sanitiser was not applied when its argument was untracked

`syrth/parser/python.py` returned early from the sanitiser path when the argument
carried no taint, so the kill was never applied to the returned value. The
consequence was that `Markup(escape(x))` -- escaping before asserting safety, the
canonical correct pattern -- was reported as an XSS amplifier, because `escape`
had not been consulted at all. The early return also contradicted the comment
immediately below it, which says an untracked sanitiser is still worth recording.

### 2. A namespaced import did not bind its sanitiser

`from django.utils.html import escape` did not resolve to the `html.escape` kill.
Module matching compared the whole dotted path and the **root** package, so
`django.utils.html` was tested against `django` and matched nothing, while
`from html import escape` matched. `bind_import` now also compares the **last**
segment, which is what a re-exported helper actually is. The tradeoff is stated
in the docstring: a local package named `html` would now be treated as the
standard one, trading a possible missed finding for removing a class of false
amplifier reports.

### 3. An assertion about a literal was reported

`Markup("<li class=...>")` on a constant string is not an assertion anyone could
have got wrong -- no failure of taint tracking can make a literal unsafe. This put
a finding on Airflow's pagination helper, which builds static markup. An amplifier
is now suppressed when its argument is a literal. Interpolated strings are
deliberately excluded from "literal", so `Markup("<b>%s</b>" % value)` is still
reported.

### What the survivors are, and what they are not

56 patched functions still report their class. That number is the measurement. It is
**not** a false-positive count, and reading it as one is the error this section used
to make.

A finding that persists after a patch is one of three things:

- **the guard is a rule this analyser does not have.** `os.path.commonpath` with a
  raise, `Path.resolve()` with a containment raise, an application-specific
  validator. The report is a true observation of a sink contact; the mitigation is
  real and simply unrecognised. `syrth/containment.py` now models the exiting form
  of these, as *evidence* -- it lowers the finding's likelihood and names the guard
  line. It does not remove the finding.
- **the sink is reachable by design.** A policy gate that raises only when an
  operator has enabled the operation. The report is correct and the maintainers
  shipped it on purpose.
- **the diff does not contain enough to decide.** The patch touches a helper, or
  changes a boolean, and whether the reachable path narrowed cannot be read off the
  diff.

Distinguishing these requires reading the code, which `benchmarks/adjudicate.py`
exports for exactly that purpose. It does not require, and must not produce, a count
of how many findings were wrong.

### The boundary that remains

A guard whose safety depends on the *value* rather than on the shape of the call is
invisible to this architecture, and this was reproduced directly:

- a function whose only path to `torch.load` runs past an unconditional `raise`
  still reports CWE-502;
- an early `return None` does not lower CWE-22.

Modelling that needs path-sensitive reasoning, which is a different project from
this one. It is recorded as KI-014 and left open.
## Competitor comparison

Six instruments, one corpus, one ground truth.

Every tool runs over the same 350 records and is scored against the same
expectations, derived by an independent AST scan that shares no code with the
analyser. CWE attribution comes from each tool's own published metadata; a finding
with no CWE is counted as unmapped, never guessed into a class.

```console
$ python -m benchmarks.competitors --dataset data/corpus.jsonl
corpus : data/corpus.jsonl  (350 records, 175 pairs)
```

### The two axes

**Class coverage** asks whether a tool named the vulnerability class whose sink the
source provably contains. It needs a CWE per sink, so it cannot score an instrument
that publishes none.

**Sink coverage** asks the weaker and more portable question: did the tool look at
the same dangerous *call* this file provably contains. It needs only the call and
its line, which is what puts ruff -- whose rules carry no CWE at all -- in the same
table as everything else. Both axes come from the same AST walk and the same
tables, so they are comparable to each other.

### Head to head

| Tool | Class coverage | Sink coverage | Fix noticed | Still flagged | Time |
|---|---|---|---|---|---|
| **SYRTH v1-prod** | **111/116** (95.7%) | **199/217** (91.7%) | 8/74 | 66/74 | 3.5s |
| Bandit 1.9.4 | 23/116 (19.8%) | 11/217 (5.1%) | 8/60 | 52/60 | 19.6s |
| Semgrep 1.180.0 `p/security-audit` | 17/116 (14.7%) | 14/217 (6.5%) | 11/25 | 14/25 | 99.0s |
| Semgrep 1.180.0 `p/owasp-top-ten` | 0/116 (0.0%) | 0/217 (0.0%) | 1/3 | 2/3 | 24.0s |
| Semgrep 1.180.0 `p/python` | 0/116 (0.0%) | 0/217 (0.0%) | 1/3 | 2/3 | 19.5s |
| Ruff 0.16.10 `--select S` | 0/116 (0.0%) | 73/217 (33.6%) | 0/0 | 0/0 | 0.2s |

### Per class

`covered/expected` -- the denominator is what an independent AST scan proves is
present, not what each tool could in principle find.

| Class | syrth | bandit | semgrep | semgrep-owasp | semgrep-python | ruff |
|---|---|---|---|---|---|---|
| CWE-22 path traversal | 41/44 | 1/44 | 0/44 | 0/44 | 0/44 | 0/44 |
| CWE-502 deserialisation | 15/15 | 14/15 | 11/15 | 0/15 | 0/15 | 0/15 |
| CWE-601 open redirect | 17/17 | 0/17 | 0/17 | 0/17 | 0/17 | 0/17 |
| CWE-79 XSS | 10/12 | 8/12 | 6/12 | 0/12 | 0/12 | 0/12 |
| CWE-89 SQL injection | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| CWE-918 SSRF | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| CWE-94 code execution | 20/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |

### What each tool actually emits

| Tool | Unmapped findings | Classes modelled | Exit contract |
|---|---|---|---|
| SYRTH | 0 | 7 of 7 | always 0; a threshold marks, it never filters |
| Bandit | 0 | 3 of 7 | 1 when findings exist |
| Semgrep (security-audit) | 0 | 2 of 7 | 0 when findings exist |
| Semgrep (owasp-top-ten) | 0 | 0 of 7 | 0 when findings exist |
| Semgrep (python) | 0 | 0 of 7 | 0 when findings exist |
| Ruff | 111 | 0 of 7 | 1 when findings exist |

### Reading the table without fooling yourself

- **`0/116` is nearly always "does not model this class".** Bandit ships no
  open-redirect rule, so its `0/17` on CWE-601 is a rule-set difference. Semgrep's
  two extra configs name no class on this corpus at all -- `p/owasp-top-ten` does
  carry CWE metadata (it reports CWE-78 and CWE-327 where it fires), so the zero is
  about the corpus's classes, not about the extraction.
- **Ruff's `0/116` is a metadata gap, not an absence of findings.** Its 111 findings
  carry no CWE. It is in the table because excluding an instrument that finds real
  sinks would flatter everyone else, and on the axis it can be scored on it reaches
  **33.6%** -- second only to SYRTH, and 16x faster than Semgrep.
- **Bandit wins the one class both tools model well.** CWE-502 is 14/15 against
  SYRTH's 15/15. Quoting only the totals would hide that.
- **The mitigation columns are the interesting ones and they are unflattering.**
  Every tool misses most of the fixes it can see. Semgrep notices 11 of the 25 it
  detects; SYRTH notices 8 of the 74 it detects; Bandit 8 of 60. Read them with
  their denominators, because a bare percentage would credit the narrower field of
  view.
- **Ruff's `0/0` means "never fired on a pair", not "noticed every fix".** It is
  absent from that population rather than perfect in it.
- **The corpus is 350 snippets, not whole repositories.** The speed column is
  in-process scanning against tools paying interpreter and rule startup. It is not
  a throughput claim about real codebases.

### Three instrument bugs this comparison found

Recorded because each produced a number that looked like a result.

- **The first run reported `0%` for every tool.** `pair_id` joins its parts with
  `:`, illegal in a Windows path, so no `.py` file was written and the tools
  scanned an empty directory.
- **The mitigation columns reported `0/0`.** The harness keyed its pair lookup on
  `record_id`, which encodes the side of the pair, then searched with a bare
  `pair_id`. Nothing matched. In a table `0/0` is indistinguishable from a tool that
  never fires, which is why `assert_pairs_are_distinct` now refuses to report a
  rate over a corpus whose pairs have been altered or dropped.
- **ruff was reported unavailable.** `_parse_json_output` scanned for `{` only, and
  ruff emits a top-level array. Separately, ruff exits 1 when it finds violations,
  as every linter does; the harness now ignores the exit code and treats only an
  unparsable payload as a failure. A harness that assumes well-behaved output will
  report a working tool as broken.

### What this is not

It shows which classes each tool names, which sinks it looks at, and whether it
registers a fix. It does **not** show precision, recall or vulnerability
detection. The corpus has no reliable negative class, and each pair's patched side
still contains its sink call by design.

The machine-readable form is `data/competitor_benchmark.json`, and
`TestPublishedMeasurementsMatchTheDocs` asserts that its mitigation columns
partition their population -- a rate without a denominator is indistinguishable
from a tool that never fired.

## Component ablation

Coverage is a property of the whole pipeline, so it does not say which part of the
pipeline produced it. `benchmarks/ablation.py` disables one analysis decision at a
time and re-measures on the same 350 records:

```bash
python -m benchmarks.ablation --dataset data/corpus.jsonl --json data/ablation.json
```

| Variant | Coverage | Kill | Rename | Determinism |
| --- | --- | --- | --- | --- |
| full | 111/116 | 89/100 | 350/350 | 350/350 |
| no argument schemas | 111/116 | 81/102 | 350/350 | 350/350 |
| untyped sanitisers | 111/116 | 89/100 | 350/350 | 350/350 |
| no inline guards | 111/116 | 89/100 | 350/350 | 350/350 |
| no containment checks | 111/116 | 89/100 | 350/350 | 350/350 |
| no guards (both) | 111/116 | 89/100 | 350/350 | 350/350 |
| name-seeded sources | 111/116 | 39/47 | 350/350 | 350/350 |
| no call graph | 111/116 | 89/100 | 350/350 | 350/350 |

What this says, including the parts that are not flattering:

- **Coverage is insensitive to every ablation.** A class is named from the
  registry as soon as a sink contact is seen, whether or not a flow was confirmed.
  The 111/116 figure therefore measures the registry and the pattern path; it is
  not evidence that the taint engine found 111 flows.
- **The kill rate moves only when the number of confirmed flows changes.** With
  name-seeded sources, 47 flows are confirmed instead of 100, and the rate falls
  to 83%. Argument schemas add two confirmed flows (102 attempts, 81 kills).
- **Guard evidence, sanitiser typing and the call graph move no published
  number.** A guard changes confidence, and confidence is not one of the five
  metrics. An untyped sanitiser would only differ if one value reached two sinks
  of different categories, which the corpus does not exercise. The call graph
  produces 116 cross-function traces that the finding metrics never read.

That is a gap in the contract, not a defence of the tool: the layers that change
what a reviewer sees are currently unmeasured. Recording it here is the point of
running the ablation at all. The machine-readable form is `data/ablation.json`.

## Identity under renaming

`rename_invariance` in the table above counts the *class set*. The stronger
property, and the one the certificate depends on, is that `trace_id` survives a
rename. It does not, in three measurable cases, because the key includes the
origin set and the function name:

```bash
python -m benchmarks.identity --dataset data/corpus.jsonl
```

| Scope | Records | Class set stable | Identity stable | Origin set stable | Confirmed flows |
| --- | --- | --- | --- | --- | --- |
| parameters only | 312 | 312/312 | 296/312 (94.9%) | 304/312 | 237 -> 228 |
| functions only | 332 | 332/332 | 217/332 | 332/332 | 268 -> 268 |
| all identifiers | 350 | 350/350 | 233/350 | 304/350 | 274 -> 265 |

- **Parameters.** Renaming a parameter that was recognised as a framework request
  object changes its origin label from `REQUEST` to `PARAM`, and the label is part
  of the key: 8 records change origin set, 16 change identity. Nine confirmed flows
  disappear, the same direction as the ablation's `name-seeded sources` row --
  source recognition still consults names even though taint seeding does not.
- **Functions.** Identity changes for 115 of 332 records by design: the function
  scopes the flow, so renaming the function renames the scope. The class set and
  the origin set are unaffected.
- **Everything.** `alpha_rename` does both at once, which is why the published
  class-set figure is 350/350 while the identity figure is 233/350.

The fix is to normalise origin labels to externality classes before hashing
(`request` and `x` both map to "external"), which would make identity stable under
parameter renaming without losing the distinction between external and internal
flows. It is not implemented; the measurement exists so the claim is not made
faster than the code. Machine-readable: `data/identity_rename.json`.

## Real-commit patch study

The kill rate above is a *kill model* number: the category's own sanitiser is
applied mechanically, and the tool is asked whether the flow disappears. It says
nothing about what a real developer's patch does. The corpus can answer the
stronger question directly, because every accepted record carries the real patched
counterpart of the same function from the same fix commit:

```bash
python -m benchmarks.patch_study --dataset data/corpus.jsonl
```

175 pairs, and both sides parse in all 175. The vulnerable side traces the
labelled class in 54 of them (53 direct-sink, 1 module-proximity). The three
outcomes are a partition of those 54 -- every traced pair lands exactly once:

| Outcome | Pairs | Meaning |
| --- | --- | --- |
| certificate persists | 46/54 | at least one labelled certificate holds unchanged after the fix (`trace_id` identical) |
| flow removed | 7/54 | every labelled trace gone, and no new flow of that class appeared |
| flow traded | 1/54 | every labelled trace gone, but a new flow of the same class took its place |

Three of the 46 persisted-then-changed pairs lost one labelled trace and gained a
new one beside a survivor; the other 43 held their labelled traces untouched.
Discounting those overlaps for the killed-side view: 11 of the 54 pairs saw at
least one labelled trace die at any depth, and the diff killed traces of *any*
class in 13 of the 175 pairs.

- **Why persistence dominates is the certificate's point, not its failure.** A
  fix that adds a guard leaves the identical certificate standing by design --
  guards lower confidence, they never delete it -- and that is exactly what a
  patch verifier should demand rather than accept the fix on faith. The 7
  removals are the fixes that actually changed the sink argument or the path
  inside the function. The single module-proximity pair persists by construction:
  the danger sits outside the extracted function.
- **A rename can masquerade as removal.** The diff keys on `trace_id`, and the
  identity section above shows that key is name-sensitive: a patch that renames a
  recognised parameter reads as a removal plus an introduction of the same class.
  The removal and traded counts carry that caveat; they are upper bounds on what
  the fix really changed.
- **Fixes can add flows.** 10 of the 175 pairs introduced at least one new trace
  of some class after the fix (11 flows: CWE-22 x6, CWE-79 x3, CWE-94 x2). On
  this scale a regression is rare but not zero, and it is published rather than
  hidden.

Honest limitation: the diff sees only the extracted function, so a fix that
removes the danger in a helper or a caller reads as persistence here. The
measurement was sized to stay supplementary to the kill model, not to replace it.
Machine-readable: `data/patch_study.json`.

## Whole-repository patch study

The diff above sees only the extracted function. The whole-repository harness
replays both revisions of every fix commit over the full trees:

```bash
python -m benchmarks.whole_repo_study --dataset data/corpus.jsonl \
    --repos experiments/scratch/repos \
    --json data/whole_repo_study.json
```

It checks out `<commit>~1` and `<commit>` as Git worktrees, scans each with the
interprocedural call graph, and classifies the labelled flow: the labelled CWE in
the labelled function and file. Build, cache, VCS, and virtual-environment
directories are pruned; test and example code is not. The partition is over
intraprocedural certificates, matching the function-level study. Cross-function
certificates whose sink is the labelled function in the labelled file are counted
separately and never enter the partition. Results are checkpointed after each
commit, so a killed run resumes without rescanning finished commits.

All 88 fix commits across 24 repositories were scanned: 175/175 pairs,
`missing_pairs=0`, 15,478 s of scanner time. The largest revision is salt's, at
3,795 files, 46,269 functions, and 535,936 certificates. The labelled class
traces on the vulnerable side in 57 pairs:

| Outcome | Pairs | Meaning |
| --- | --- | --- |
| certificate persists | 50/57 | at least one labelled intraprocedural certificate holds unchanged after the fix (`trace_id` identical) |
| flow removed | 6/57 | every labelled intraprocedural trace is gone, and no new flow of that class appeared in the labelled function |
| flow traded | 1/57 | every labelled intraprocedural trace is gone, but a new flow of the same class took its place in the labelled function |

The whole-repository set is a superset of the function-level set: all 54 pairs
traced by the snippet study are also traced here, and 3 more trace only when the
full module supplies a helper or module-level binding (two Django CWE-79 pairs,
one Keras CWE-22 pair; all three persist). Per-pair outcomes agree in 53 of the
54 shared pairs. The exception is a Django CWE-79 pair whose snippet trace does
not survive while a repository-scope trace does; the two studies score different
certificate sets, so this is a context effect, not a contradiction. The partition
is the same shape at both scopes; the whole-repository denominator is 57, not 54.

**Cross-function certificates.** In 23 of the 57 traced pairs at least one
cross-function certificate reaches the labelled sink from a caller: 4,275
certificates, of which 4,268 keep the same identity after the fix and 7 are
killed. A single salt helper (`clean_join`, `salt/utils/verify.py`) accounts for
4,114 of the 4,275 because it is called from thousands of entry points; the pair
count is the meaningful denominator, and the certificate total is reported only
with that concentration stated. One pair has cross-function certificates but no
intraprocedural trace (`cross_only_pairs=1`); it is excluded from the partition.
Cross-function certificates answer whether the sink remains reachable, not
whether the fix changed the flow the advisory was about.

**Flows introduced anywhere in the tree.** 26 of 88 fix commits introduced at
least one new certificate of some class anywhere in the scanned tree: CWE-22
569, CWE-94 71, CWE-89 51, CWE-918 49, CWE-79 39, CWE-502 12, CWE-611 10. This is
a repository-wide count, not an attribution: a fix commit can add unrelated code,
and a new flow in a new module or a test is not a regression caused by the patch.
The labelled-flow partition is the unit the fix is about.

Machine-readable: `data/whole_repo_study.json`. Each row records the pair, the
labelled function and file, the intraprocedural target/survival/kill counts,
cross-function counts, the patched-file check, and the repo-wide introduced
count; the top level records the partition and the by-class, by-repository, and
by-tier splits.

---
