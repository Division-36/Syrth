# Where to start

Read these in order. Each builds on the one before it; none assumes you have read the code.

| If you want… | Read |
|---|---|
| what the tool claims, and what it refuses to claim | [risk-model.md](risk-model.md) — 5 minutes |
| a hands-on scan, with real output | [usage.md](usage.md) — 5 minutes |
| what the current numbers are, with their denominators | [benchmark.md](benchmark.md) — the first two sections are enough |
| how the analyser is put together | [architecture.md](architecture.md) — 10 minutes |
| the exact limits, stated plainly | [limitations.md](limitations.md) |
| how to reproduce every published number | [benchmark.md#which-command-produces-which-number](benchmark.md#which-command-produces-which-number) and `make verify-published` |

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

669 tests; how many pass depends on the environment: the export test skips
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
