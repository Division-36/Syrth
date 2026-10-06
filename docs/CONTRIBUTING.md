# Contributing to SYRTH

## Before you start

Read [`docs/risk-model.md`](risk-model.md). It is the contract: SYRTH
reports the nearest vulnerability class with a likelihood and its evidence. It
does not decide whether code is safe. Most review comments on this project are
about that distinction.

## Setup

```bash
pip install -e ".[dev,benchmark]"
python -m pytest tests -q -o addopts=
python -m ruff check syrth tests benchmarks
```

Required before every hand-off:

```bash
python -m pytest tests -q -o addopts=      # expect: 627 passed, 1 skipped
python -m ruff check syrth tests benchmarks # expect: All checks passed!
```

The skip is the C-export test, which needs a C compiler. On a machine without one
it is legitimately skipped — say so rather than reporting a clean run.

Do not claim a command passed unless you ran it and read the output.

## Where things live

| Path | Role |
|---|---|
| `syrth/registry.py` | **the security model** — sinks, sources, sanitisers, CWEs. A leaf |
| `syrth/parser/` | parsing, propagation, guard recognition |
| `syrth/taint/engine.py` | taint algebra and merge semantics |
| `syrth/scan.py` | scanner and CLI |
| `syrth/patch.py` | patch backends and verification |
| `benchmarks/` | the harness |
| `tests/` | 628 tests |

## House rules

**The registry is the only place a sink may be declared.** If you find yourself
deciding whether a call is dangerous anywhere else, that is the bug.

**A change needs a test that fails without it.** Verify by reverting the fix and
watch the test go red. A test that passes either way is not a regression test.

**Never evaluate, exec, or unpickle analysed code.** The analyser reads untrusted
source. If you add code that runs it, that is a security regression.

**Do not suppress.** `--threshold` marks a finding; it never removes one. The
only things that hide output are a suppression file and an inline ignore
comment, both of which are deliberate human decisions. A change that reintroduces
silent filtering is a change to the product's contract and needs discussion.

**Explain the why.** This codebase documents non-obvious safety decisions in prose
— why confidence is ordered a certain way, why a guard is evidence and not proof,
why a patch declines SQL. Match that. A comment that restates the code is noise.

## Adding things

**A sink:** add to `syrth/registry.py` with its dangerous argument positions. Add
a test asserting a flow is reported *and* that a safe argument shape is not.

**A guard shape:** add to `syrth/parser/guards.py`. If the shape constrains only
a component of a value (`parsed.netloc`), do **not** add it — see
[`docs/limitations.md`](limitations.md).

**A feature:** add to `features/extractor.py` and bump `FEATURE_SCHEMA_VERSION`.
Old model bundles will then be refused rather than silently misread.

**A serialisation field:** bump the relevant schema version.

## Testing style

Tests group a behaviour area in a class. Name the invariant, not the function.

```python
class TestReportPolicy:
    def test_a_low_likelihood_flow_is_still_reported(self):
        report = SyrthScanner(threshold=0.95).scan_source(VULNERABLE, "app.py")
        assert report.findings
        assert report.findings[0].below_threshold is True
```

When you change reporting semantics, some existing assertions encode the old
semantics and will fail. Decide deliberately whether each one is now wrong
(update it) or still right (fix the code) — do not mechanically rewrite failures
to green.

## Honesty requirements

- No accuracy claim without a reproducible measurement. The tool currently makes
  none.
- When you cite a number, say what produced it and over what data.
- If a metric measures the harness rather than the analyser, say so. Two such
  cases were found and documented in [`docs/benchmark.md`](benchmark.md).
- Prefer `[VERIFIED]` / `[UNVERIFIED]` over confident prose when uncertain.

## Pull requests

1. Tests pass, lint clean.
2. New behaviour has a test that fails without it.
3. `docs/` updated if you changed a documented behaviour.
4. `docs/CHANGELOG.md` gains an entry.
5. `Context/STATE/known_issues.md` updated if you fixed or found something.

## Known gaps worth attacking

`[`docs/limitations.md`](limitations.md)` lists them. The highest-value
ones:

- **Rename invariance is 99.2%, not 100%.** Four records change their reported
  class set under renaming. The project's core claim is that this does not happen.
- **CWE-79 misses 6 of 26** in the measured set. Not yet investigated per case.
- **26.7% of confirmed flows survive a recognised sanitiser**, so a correct patch
  can still be reported as vulnerable.
- **No CI.** Nothing runs automatically; a regression can land silently.