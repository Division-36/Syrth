# The risk model

This is the document to read before quoting any number from this project.

## What SYRTH answers

> **What is the nearest vulnerability class to this code, and how likely is it?**

## What SYRTH does not answer

> **Is this code vulnerable?**

SYRTH is not a classifier. It does not divide code into "vulnerable" and "safe",
and it produces no accuracy score. If you are looking for a verdict, this is the
wrong tool, and a number claiming to give you one is not measuring this.

## Why this distinction is not a philosophical preference

The previous version of this project was a classifier: it applied a confidence
threshold, put anything below it in a "suppressed" bucket, and reported
precision and recall. That produced two artefacts that looked like quality
problems and were reporting artefacts:

- **"13.4% recall"** — mostly because the benchmark corpus was mislabelled, but
  also because a low-likelihood risk was recorded as *no answer at all*.
- **"46.7% false alarms on safe code"** — these were *correct* observations of a
  sink being touched, suppressed into invisibility, and then counted as noise.

A suppressed 0.12 risk is an answer. Silence is not. See
[corpus_failure_diagnosis.md](corpus_failure_diagnosis.md) for the full
investigation.

## What a report looks like

Every report has:

| Field | Meaning |
|---|---|
| `cwe` / `category` | the vulnerability class, derived from the sink table |
| `confidence` | likelihood in `[0, 1]` |
| `detector` | `taint` for a confirmed flow, `pattern` for a sink contact |
| `reasons` | why this likelihood, in words |
| `steps` | the ordered evidence chain, source to sink |
| `origins` | where the untrusted data entered |
| `kills` / `partial` | sanitisers and guards seen on the path |

### The three cases

```python
import subprocess

def raw(request):
    subprocess.run(request.GET['c'], shell=True)
    # -> CWE-94, confidence 0.89, CRITICAL
    #    confirmed flow: REQUEST -> subprocess.run

def guarded(request):
    c = request.GET['c']
    if c not in ('ls', 'pwd'):
        return 'no'
    subprocess.run(c, shell=True)
    # -> CWE-94, confidence 0.12, LOW
    #    same sink, but an allowlist guard constrains the value

def literal():
    subprocess.run('ls')
    # -> CWE-94, confidence 0.40, LOW
    #    detector="pattern": the sink is touched, no taint confirmed
```

All three are reported. The tool is answering "where should I look", not "pass or
fail".

## One class per sink

A function has one nearest vulnerability class **per sink it touches**, not one
overall. A function that calls `os.system` *and* `HttpResponseRedirect` produces a
CWE-94 risk and a CWE-601 risk. An earlier version suppressed the second one
whenever the function had any confirmed flow at all, which was wrong under this
model.

## Ordering

Findings are sorted by severity, then likelihood, then location. The ordering is
a total function of the finding's own fields, so output does not depend on
discovery order. Measured rank agreement — "when two findings in the same
function differ in evidence strength, is the better-evidenced one first" — is
**100% (22/22)**.

## The threshold does not delete

`--threshold` marks a finding `below_threshold` so a consumer can filter. It
never removes it from the report. The only things that suppress output are an
explicit suppression file and an inline ignore comment — decisions you make, not
decisions the analyser makes on your behalf.

```bash
# everything, ranked
syrth --file app.py

# only what the tool considers likely, for triage
syrth --file app.py --json | jq '.findings[] | select(.below_threshold | not)'
```

## Why precision and recall do not apply

They are metrics for a decision procedure with a positive and a negative class.
SYRTH makes no decision and has no negative class: every sink contact is reported
regardless of outcome. The measurements that *are* defined are:

| metric | what it answers |
|---|---|
| **category coverage** | of the vulnerability classes whose sinks the source provably contains, how many were named |
| **rank agreement** | is the better-evidenced finding ranked first |
| **rename invariance** | does the reported class set survive renaming |
| **kill rate** | does the category's own mitigation remove the confirmed flow |
| **determinism** | does a repeat scan of identical input agree exactly |

The harness derives expected classes from the source with an **independent AST
scan** and never reads the corpus labels, which is why its numbers remain
meaningful while the corpus labels are known to be unsound.

## What you still have to do

The tool reduces a large codebase to a ranked list. It does not decide what to
fix. A 0.89 CWE-94 and a 0.12 CWE-601 are both worth reading; they are not
equally worth reading, and neither is a proof of anything.

Every report states its evidence. If the evidence does not convince you, the
report is not convincing you, and that is the correct behaviour: the tool shows
its work so you can disagree with it.