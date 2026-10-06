# SYRTH documentation

Everything here describes **v3**, the current implementation. Documents for the
retired v1 pipeline are in [`archive/`](archive/), kept for provenance and marked
as withdrawn.

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
| [architecture.md](architecture.md) | Components, data flow, invariants |
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
| [WITHDRAWN.md](../paper/WITHDRAWN.md) | Which v1 results were withdrawn and why |
| [corpus_failure_diagnosis.md](corpus_failure_diagnosis.md) | Why the first corpus produced meaningless numbers |
| [measurements.md](measurements.md) | The classifier-era measurements, retained for contrast |
| [LICENSE.md](LICENSE.md) | MIT licence |

## The one-paragraph version

SYRTH analyses Python and reports, for every dangerous operation your code
touches, **which vulnerability class is nearest** and **how likely** it is. It is
not a classifier and does not decide whether code is safe: a function calling
`os.system("ls")` gets a CWE-94 risk at low likelihood, and that risk is printed.
Nothing is hidden for being unlikely. See [risk-model.md](risk-model.md).

## Status

`[VERIFIED 2026-10-02]` 533 tests: 504 pass, 1 skipped (no C compiler on the build
machine); `ruff check syrth tests benchmarks` is clean; the wheel builds without
warnings.

Current measured figures, reproduced by
`python -m benchmarks.risk_metrics --dataset data/cve_pairs.jsonl`:

| metric | value |
|---|---|
| category coverage | 90.5% (57/63) |
| rank agreement | 100% (22/22) |
| rename invariance | 99.2% (494/498) |
| patch kill rate | 85.5% (65/76) |
| determinism | 100% (498/498) |

`rename invariance` is not 100%. See [limitations.md](limitations.md).

There is **no published accuracy figure**, because no accuracy claim is made. See
[risk-model.md](risk-model.md) for why precision and recall do not apply here.