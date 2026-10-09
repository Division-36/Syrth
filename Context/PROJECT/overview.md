# Project Overview — SYRTH

## Mission

Static analysis for Python that reports **why** a flow is dangerous, and proves
that its own remediation worked. Two properties are treated as the product, not
as features:

1. **Rename invariance** — the verdict must not depend on what a variable is
   called.
2. **Mechanical verification** — a proposed fix is only accepted if the targeted
   flow is gone, no new flow appeared, and the file still parses.

`[FACT]` The package description is "Alpha-renaming-invariant, fix-verifying
static analysis for Python" (`pyproject.toml`).

## Problem being solved

Conventional SAST tools emit `user_input` reaches `execute` without explaining
how, and their findings cannot be checked. SYRTH emits a **trace certificate**:
ordered steps from source through each propagation to a specific sink argument,
plus the CWEs that flow actually reaches.

## Core philosophy

- One security model, one place. `syrth/registry.py` defines sinks, sources,
  sanitisers and CWEs; parsers consult it.
- Evidence over speculation. A flow is reported when a taint path is confirmed,
  and confidence records how much mitigation stands in the way.
- Refuse to overstate. No accuracy or SOTA figure is published without a
  reproducible measurement. All v1 figures were formally withdrawn
  (`paper/WITHDRAWN.md`).

## Current maturity

`[FACT]` `pyproject.toml` declares `Development Status :: 4 - Beta`.

`[FACT]` Working tree state as of 2026-10-02: 459 tests pass, 1 skipped (no C
compiler), `ruff` clean over `syrth tests benchmarks`, wheel builds.

`[INFERENCE]` The *machinery* is mature — parsing, propagation, tracing, guards,
interprocedural resolution, patch verification, SARIF, and a test suite of 460
cases are all working and covered.

`[FACT]` The *detection quality* is not established. See
`STATE/known_issues.md` KI-001…KI-004. No trustworthy recall figure exists.

## Major capabilities

- Byte-safe tree-sitter parsing with spans resolved against the source **bytes**
  (a defect in v1 corrupted every identifier after the first multi-byte char).
- Taint propagation through assignment, attribute, subscript, call, f-string,
  `.format()`, `%`, comprehensions, `for`/`with`, augmented assignment, keyword
  arguments and module scope.
- **Guards** (`syrth/parser/guards.py`): terminating allowlist, denylist,
  equality and anchored-regex validation demote a flow below the reporting
  threshold instead of clearing it.
- Interprocedural resolution with taint provenance, so a helper only ever called
  with clean values produces nothing.
- Revision diff keyed on a line-independent structural trace identity.
- Deterministic patch backend plus an external command backend, both gated on
  three-condition verification.
- SARIF 2.1.0 with code flows.
- Optional XGBoost ranker and a C header exporter whose output was validated
  against live xgboost probabilities.

## Major limitations

`[FACT]` Flow-insensitive and path-insensitive inside a function: both branches
of a conditional are analysed, and a guard is treated as a *partial* mitigation
rather than a proof.

`[FACT]` No path, field or alias sensitivity; an attribute write propagates to
every read.

`[FACT]` Class-qualified names are merged — same-named methods in different
classes are not distinguished.

`[FACT]` The deterministic patch backend declines SQL, because deriving
placeholders from a literal cannot be done soundly.

`[FACT]` Libraries are modelled by name; a library that re-executes a string
internally is invisible.

## Historical context

v1 (the scripts now deleted, recorded in `legacy/` and `experiments/`) was a five-model ensemble plus a
stacking meta-learner that supplied the ground-truth CWE description as a
feature. It was audited, found to have a dead meta-learning stage with a
hardcoded RCE class index, and retired. Its figures are withdrawn. The v1 tree is
retained **only** as audit provenance — see `legacy/README.md`.