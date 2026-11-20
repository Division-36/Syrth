# Where to start

Read these in order. Each builds on the one before it; none assumes you have read the code.

| If you want… | Read | Time |
|---|---|---|
| a working example in 30 seconds | [quick example](#quick-example) below | 30 s |
| what the tool claims, and what it refuses to claim | [risk-model.md](risk-model.md) | 5 min |
| a hands-on scan, with real output and every flag | [usage.md](usage.md) | 5 min |
| what the current numbers are, with their denominators | [benchmark.md](benchmark.md) — the first two sections are enough | 5 min |
| how the analyser is put together | [architecture.md](architecture.md) | 10 min |
| the exact limits, stated plainly | [limitations.md](limitations.md) | 5 min |
| answers to the questions people ask most | [FAQ](#faq) below | 3 min |
| how to reproduce every published number | [benchmark.md#which-command-produces-which-number](benchmark.md#which-command-produces-which-number) and `make verify-published` | — |

## Quick example

A file with a dangerous call:

```python
# app.py
import os

def handler(request):
    return os.system(request.GET["cmd"])
```

Scan it:

```console
$ syrth --file app.py
========================================================================
SYRTH - Scan Your Risk Trace History
target : app.py
model  : rule
scanned: 1 file(s), 1 function(s), 1 trace(s)
cross-function flows resolved: 1
========================================================================
[CRITICAL] CWE-94 (EXEC) confidence 0.89
  app.py:4 in handler()
  sink: os.system -> EXEC_COMMAND via pos:0
  origin: REQUEST
  >> L3     param             request
     L4     attr              request.GET
     L4     arg               request.GET["cmd"]
  << L4     os.system         request.GET["cmd"]
------------------------------------------------------------------------
```

The finding says *which class is nearest* and *how likely*, with the path that
supports it. It does not say "vulnerable" or "safe": see
[risk-model.md](risk-model.md) for why that is a design decision, not a missing
feature. For installation and the full CLI, see [usage.md](usage.md).

## FAQ

**Why no accuracy, precision or recall?** Those need a positive class, a
negative class and a verdict. SYRTH reports a risk on every sink contact; a
suppressed low risk is still an answer. See [risk-model.md](risk-model.md).

**Does a low-confidence finding get hidden?** No. `--threshold` marks a finding
as low-evidence; it never deletes it. Every sink contact is reported.

**Does it patch code?** It can propose a mechanical patch to the sink argument
and verify it against three conditions. It cannot refactor, and it declines SQL
rewrites. See [limitations.md#patching](limitations.md#patching).

**Why does a fix sometimes leave the finding in place?** A guard lowers the
confidence but leaves the certificate standing, by design. That is what a patch
verifier checks: the flow must be gone, not merely hidden. See
[benchmark.md#real-commit-patch-study](benchmark.md#real-commit-patch-study).

**Can I trust the numbers?** Each is published as `n/N` next to the command
that reproduces it; `make verify-published` re-derives every one and exits non-zero
if a published file has drifted. The whole-repository replay takes hours, so CI
checks its invariants instead of re-running it. See
[benchmark.md#which-command-produces-which-number](benchmark.md#which-command-produces-which-number).

**Which tool is "best"?** The comparison measures which classes each tool names
and where its findings land, not detection quality. There is no negative class,
and a tool with no rule for a class cannot be scored as if it had missed one.
See [benchmark.md#what-this-is-not](benchmark.md#what-this-is-not).

## How the documentation is organised

The pages fall into four layers, the same split that large tool projects use:

| Layer | What it answers | Pages |
|---|---|---|
| **Tutorial** | show me a working scan in 30 seconds | [quick example](#quick-example), [usage.md](usage.md) |
| **How-to** | how do I do a specific thing? | [usage.md](usage.md), [configuration.md](configuration.md), [api.md](api.md) |
| **Reference** | what exactly are the flags, rules and numbers? | [configuration.md](configuration.md), [benchmark.md](benchmark.md), [architecture.md](architecture.md) |
| **Explanation** | why is it designed this way? | [risk-model.md](risk-model.md), [internals.md](internals.md), [the audits](#provenance-and-audits) |

You can read top to bottom or drop into the layer you need. The FAQ above answers
the questions that come up most often.

## The one-paragraph version

SYRTH reads Python source and reports, for every dangerous operation your code
touches, **which vulnerability class is nearest** and **how likely** it is. It
does not decide whether code is safe: a function calling `os.system("ls")` gets a
CWE-94 risk at low likelihood, and that risk is printed. Nothing is hidden for
being unlikely. The output is a *trace certificate* — a source-to-sink path with
a structural identity — so a reviewer can read the path, a later revision can be
compared by matching identities, and a patch can be refused when the flow it was
meant to remove still holds.

## What is measured, in one table

| Question | Number | Where the detail is |
|---|---|---|
| Does it name the class whose sink the source proves is present? | 111/116 (95.7%) | [benchmark.md#current-results](benchmark.md#current-results) |
| Does it look at the same dangerous call? | 199/217 (91.7%) | [benchmark.md#competitor-comparison](benchmark.md#competitor-comparison) |
| Is repeat output identical, and stable under renaming? | 350/350, 350/350 | [benchmark.md#current-results](benchmark.md#current-results) |
| Does its own mitigation remove a confirmed flow? | 89/100 | [benchmark.md#the-kill-rate-question-adjudicated](benchmark.md#the-kill-rate-question-adjudicated) |
| What happens to the certificate under a real fix? | 46/54 persist, 7 removed, 1 traded | [benchmark.md#real-commit-patch-study](benchmark.md#real-commit-patch-study) |
| What happens at repository scale? | 57 traced: 50 persist, 6 removed, 1 traded | [benchmark.md#whole-repository-patch-study](benchmark.md#whole-repository-patch-study) |
| Does a machine's patch pass the certificate? | 31/57 verified kills, 21 guard-only refusals | [benchmark.md#certificate-verified-patch-repair](benchmark.md#certificate-verified-patch-repair) |
| Where do other tools' findings land on whole trees? | [benchmark.md#cross-tool-comparison-on-full-worktrees](benchmark.md#cross-tool-comparison-on-full-worktrees) | co-location, not precision |

Every number is `n/N` with its denominator. **None of these is an accuracy
figure**, and the project publishes no precision or recall: there is no reliable
negative class, and a non-verdict tool has no positive class either. See
[risk-model.md](risk-model.md) for why that is a property of the question, not an
omission.

## Project process

| Document | What it answers |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute; required validation |
| [CHANGELOG.md](CHANGELOG.md) | What changed and why |

## Provenance and audits

| Document | What it answers |
|---|---|
| [withdrawn-v1.md](withdrawn-v1.md) | Which v1 results were withdrawn, and why |
| [corpus_failure_diagnosis.md](corpus_failure_diagnosis.md) | Why the first corpus produced meaningless numbers |
| [LICENSE.md](LICENSE.md) | MIT licence |

## Status

680 tests; how many pass depends on the environment: the export test skips
without a C compiler (`gcc` on Linux runs it instead), and the measurement-table
and freeze tests skip without `data/corpus.jsonl`, which CI does not generate.
`ruff check syrth tests benchmarks tools` is clean. CI runs the suite on Ubuntu,
Windows and macOS at Python 3.10 and 3.12.

Current measured figures, reproduced by
`python -m benchmarks.risk_metrics` on `data/corpus.jsonl`:

| metric | value |
|---|---|
| category coverage | 95.7% (111/116) |
| rank agreement | 100% (22/22) |
| rename invariance | 100% (350/350) |
| patch kill rate | 89.0% (89/100) |
| determinism | 100% (350/350) |
| certificate identity under renaming | parameters-only 296/312, functions-only 217/332 |
| real-fix patch study (175 pairs) | 54 traced: 46 persist, 7 removed, 1 traded |
| whole-repository replay (88 fix commits, 24 repositories) | 57 traced: 50 persist, 6 removed, 1 traded |
| cross-function certificates to the same sink | 23 pairs; 4,268 of 4,275 keep their identity |

Every number here is produced by a named harness and published next to the
documentation that quotes it; [benchmark.md](benchmark.md) lists the command and
the file behind each one, and `make verify-published` re-derives them all and
compares them with what is published.

There is **no published accuracy figure**, because no accuracy claim is made. See
[risk-model.md](risk-model.md) for why precision and recall do not apply here.
