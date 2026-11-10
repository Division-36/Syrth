# SYRTH documentation

Everything here describes the current implementation. Documents for the retired v1
pipeline are not kept; [`withdrawn-v1.md`](withdrawn-v1.md) records what that
pipeline claimed and why every quantitative result was withdrawn.

## Start here

| Document | What it answers |
|---|---|
| [architecture.md](architecture.md) | How the analyser is built, and why each layer exists |
| [usage.md](usage.md) | How to install and run it, with real output |
| [risk-model.md](risk-model.md) | **What the tool actually claims.** Read this before quoting any number |
| [configuration.md](configuration.md) | Every flag, suppression and setting |
| [api.md](api.md) | The public Python API |

## Reference

| Document | What it answers |
|---|---|
| [internals.md](internals.md) | Registry, taint algebra, confidence model, schemas |
| [benchmark.md](benchmark.md) | How the tool is measured, and the current numbers |
| [limitations.md](limitations.md) | What it cannot do, stated plainly |

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

## The one-paragraph version

SYRTH analyses Python and reports, for every dangerous operation your code
touches, **which vulnerability class is nearest** and **how likely** it is. It is
not a classifier and does not decide whether code is safe: a function calling
`os.system("ls")` gets a CWE-94 risk at low likelihood, and that risk is printed.
Nothing is hidden for being unlikely. See [risk-model.md](risk-model.md).

## Status

627 tests; how many pass depends on the environment: the export test skips
without a C compiler (`gcc` on Linux runs it instead), and the measurement-table
and freeze tests skip without `data/corpus.jsonl`, which CI does not generate.
`ruff check syrth tests benchmarks tools` is clean. CI runs the suite on Ubuntu,
Windows and macOS at Python 3.10 and 3.12.

Current measured figures, reproduced by
`python -m benchmarks.run_benchmarks` on `data/corpus.jsonl`:

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
the file behind each one.

There is **no published accuracy figure**, because no accuracy claim is made. See
[risk-model.md](risk-model.md) for why precision and recall do not apply here.
