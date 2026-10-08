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
| **determinism** | does a repeat scan of identical input produce identical output? |

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

### `data/cve_pairs.jsonl` -- the superseded corpus

`[VERIFIED 2026-10-02]` -- 498 records. Retained for history; **not a valid
measurement target**, for the reasons in
[corpus_failure_diagnosis.md](corpus_failure_diagnosis.md).

```console
$ python -m benchmarks.risk_metrics --dataset data/cve_pairs.jsonl
==================================================================
SYRTH risk-model benchmark
==================================================================
records with sinks found      : 52/498
category coverage             : 57/63 = 90.5%
rank agreement (better-evidence first): 22/22 = 100.0%
rename invariance             : 494/498 = 99.2%
patch kill rate (confirmed)   : 65/76 = 85.5%
determinism (repeat run)      : 498/498 = 100.0%

per class (covered/expected):
  CWE-22     26/26
  CWE-601    9/9
  CWE-79     20/26
  CWE-918    2/2
```

### Reading these numbers honestly

- **Coverage denominators are small: 57 and 63.** These are the classes an
  independent AST scan can prove are present, not every class the corpus could
  contain. A single missed record moves the figure by roughly 1.8 points.
- **Rank agreement is 2/2 on the built corpus.** That is a consistency check on
  two cases, not a statistical claim. The 22/22 on the superseded corpus is the
  larger sample.
- **Rename invariance is 100% on the built corpus and 99.2% on the old one.** The
  four records that changed class set under renaming are all in the superseded
  corpus, which has no provenance to explain them.
- **Kill rate fell to 80.7% from 85.5%** on the built corpus. The built corpus
  contains harder cases -- keras' `ShardedH5IOStore`, notebook's redirect guard --
  where the patch adds a validation check rather than removing the sink call, so
  the sink survives by design. This is a real difference in difficulty, not a
  regression in the analyser.
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

`[VERIFIED 2026-10-05]` -- Bandit 1.9.4, Semgrep 1.179.0, on the same 350 records
(175 pairs), against the same independent ground truth. Four instruments, because a
rule set is part of what a tool ships: Semgrep's `p/security-audit` and
`p/owasp-top-ten` are different rule sets and are measured separately.

```console
$ python -m benchmarks.competitors --dataset data/corpus.jsonl
tool              coverage          fix noticed  still flagged  seconds
-----------------------------------------------------------------------
syrth              111/116  95.7%          8/74          66/74     5.11
bandit              23/116  19.8%          8/60          52/60    12.22
semgrep             17/116  14.7%         11/25          14/25    23.45
semgrep-owasp        0/116   0.0%          1/3            2/3     35.95

per class (covered/expected):
  CWE-22   syrth 41/44   bandit 1/44   semgrep 0/44   semgrep-owasp 0/44
  CWE-502  syrth 15/15   bandit 14/15  semgrep 11/15  semgrep-owasp 0/15
  CWE-601  syrth 17/17   bandit 0/17   semgrep 0/17   semgrep-owasp 0/17
  CWE-79   syrth 10/12   bandit 8/12   semgrep 6/12   semgrep-owasp 0/12
  CWE-89   syrth 4/4     bandit 0/4    semgrep 0/4     semgrep-owasp 0/4
  CWE-918  syrth 4/4     bandit 0/4    semgrep 0/4     semgrep-owasp 0/4
  CWE-94   syrth 20/20   bandit 0/20   semgrep 0/20   semgrep-owasp 0/20

classes each tool models at all (names anywhere on this corpus):
  syrth      7 of 7: CWE-22, CWE-502, CWE-601, CWE-79, CWE-89, CWE-918, CWE-94
  bandit     3 of 7: CWE-22, CWE-502, CWE-79
  semgrep    2 of 7: CWE-502, CWE-79
  semgrep-owasp 0 of 7: none
```

### The mitigation columns are the interesting ones

Coverage rewards breadth. It says nothing about whether a tool registers a fix, so
every tool is also measured on the question `docs/risk-model.md` already defines for
this project: does the mitigation remove the flow it claims to?

A pair counts for a tool when that tool named the class on the vulnerable side. It
then counts as **noticed** if the class is gone from the patched side, and **still
flagged** if the tool reports it anyway. No negative class is needed, because this
compares a tool against itself across a known change rather than against anyone's
judgement of vulnerability.

Read the columns with their denominators. Semgrep's `11/25` is over the 25 pairs it
can see, and its `14/25` is that same population it did not register. SYRTH's
`8/74` is over 74. Comparing bare percentages would credit Semgrep's narrow field of
view. `semgrep-owasp` at `1/3` is three pairs and should not be read as a rate at all.

**Every tool misses most fixes it can see.** That is the honest headline. SYRTH still
flags 66 of the 74 patches it detects, and the 89% kill rate quoted elsewhere is not
this measurement. The distance between them is the size of the remaining KI-014
boundary.

### Reading this honestly

- **The gap is mostly rule coverage, not detection skill.** Bandit ships no
  open-redirect rule, so its `0/17` on CWE-601 means "does not model this class".
  Where both tools do have a rule, the comparison is close and Bandit wins one:
  on CWE-502 it is **14/15 against SYRTH's 15/15**.
- **This is not precision or recall.** The corpus has no reliable negative class,
  and each pair's patched side still contains its sink call by design, so nothing
  here measures false positives.
- **SYRTH is faster here** (5.1 s against 12.2 s, 23.5 s and 36.0 s for 350
  snippets), but that is in-process scanning against tools paying interpreter and
  rule startup, and it does not include Semgrep's two configurations being the same
  rule set twice. It is not a throughput claim about whole repositories.
- **The instrument was wrong twice.** The first run reported **0% for every tool**:
  `pair_id` joins its parts with `:`, illegal in a Windows path, so no `.py` file was
  written and the tools scanned an empty directory. The mitigation columns reported
  **0/0** for the same reason -- the harness keyed its pair lookup on `record_id`,
  which encodes the side, and then searched with a bare `pair_id`, so no pair matched
  and the rate was empty. In a table `0/0` is indistinguishable from a tool that
  never fires. Both were caught by asserting the population is non-empty, and both
  are pinned in `tests/test_competitors.py`.

CWE attribution is each tool's own metadata -- Bandit's `issue_cwe.id`, Semgrep's
`extra.metadata.cwe` -- and a finding with no CWE is counted as unmapped rather than
mapped by hand. `unmapped` is 0 for all four, so no finding was discarded for
lacking a class. That is also why `semgrep-owasp` scores 0/116: it named nothing
with CWE metadata on this corpus, which is a statement about its metadata, not
evidence that it found nothing.

## What the benchmark has caught

All three defects below were found by this harness, not by inspection.

### A function with any confirmed flow lost every other class

`_weak_findings` opened with `if function.traces: continue`. A function with a
confirmed CWE-22 flow *and* an `HttpResponseRedirect` reported CWE-22 and nothing
for the redirect — the second nearest vulnerability class was silently dropped.

Under the risk model a function has one class per sink, so the skip was simply
wrong. Removing it moved CWE-601 from **0/9 to 9/9** and rename invariance from
**97.4% to 99.2%**.

### The expectation scan manufactured phantom gaps

The first `expected_classes` matched bare method names, so `get`, `post`,
`request`, `parse`, `run`, `load` and `compile` counted as SSRF and
command-execution sinks. That produced a **64-record phantom SSRF expectation**
on a corpus containing no SSRF, and a coverage figure of 30.3% that mostly
measured the harness.

Matching qualified paths (`requests.get`, `subprocess.run`) plus an unambiguous
bare-name set removed the phantoms: CWE-918 went from **2/64 to 2/2** and overall
coverage from **30.3% to 90.5%** with no analyser change for that part.

Both figures were measuring different things. The first one was wrong.

### The harness could not see deserialisation at all

The expectation scan's deserialisation table was ``{Unpickler, loads}``. It had no
entry for ``pickle.load`` or ``torch.load``, so on the built corpus it reported
**CWE-502 0/4** -- and SYRTH had in fact named every one of those records
correctly. The metric was not measuring the analyser, it was measuring the
harness.

The bare name ``loads`` cannot simply be added back: after ``from pickle import
loads`` it is unsafe deserialisation, and after ``from json import loads`` it is a
safe decoder. Naming the sinks by module (``pickle.loads``, ``torch.load``,
``dill.load``, and so on) is unambiguous and stays independent of
``syrth.registry``. Category coverage moved **87.9% to 94.7%** and CWE-502
**0/4 to 3/3**, with no change to the analyser.

This is the failure mode to watch for in any label-free benchmark: the
instrument is code too, and it can be wrong in the direction that flatters or
condemns the thing it measures.
## The smoke set

```bash
python -m benchmarks.rltests
```

`RLTESTS/` holds 40 hand-written functions with section markers as labels. It is
a **regression gate, not a benchmark**: every vulnerable example there was
written to be findable, so the set has no real-world negative class and cannot
produce a meaningful coverage figure. It is useful only for detecting regressions
between code changes.

## What is not measured

- **No accuracy figure.** No claim is made, so none is published.
- **No claim of superiority.** The competitor table above measures rule coverage
  for 11 classes. Bandit covers CWE-502 as well as SYRTH does and is a mature,
  widely adopted tool; this project's advantage on this corpus is breadth of
  class coverage, not depth on any single class.
- **No performance measurement.** Throughput and memory are uncharacterised.
- **No fuzzing campaign.**
- **No trained model is shipped or measured.** The optional XGBoost ranker is
  implemented and tested for numerical agreement with live xgboost, but no
  production bundle exists.
- **No corpus for 4 of the 11 supported classes.** `data/corpus.jsonl` covers
  CWE-22, 79, 89, 94, 502, 601 and 918. CWE-327, 434, 611, 798 have no records,
  so no statement about them is supported by evidence. The cause is harvesting
  breadth, not labelling: a class is only recorded when a harvested advisory names
  it *and* the patched function is tied to its sink.
