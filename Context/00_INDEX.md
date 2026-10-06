# Context Index

Context Version: 1.0.0
Last Verified: 2026-10-02
Repository Commit: `3a38572` (branch `main`)
Working Tree: **DIRTY — 52 changed/untracked paths, nothing committed since `3a38572`.**

> **CRITICAL READ FIRST.** The working tree is the source of truth. `3a38572`
> is the last *commit*, and it is v1-era. All v3 work described below exists
> only as uncommitted files. Nothing in `Context/` describing v3 has been
> committed, and `git diff` against `3a38572` is the real change history.

## Project

- **Name:** SYRTH
- **Type:** Python static analysis (security / taint)
- **Primary Stack:** Python ≥3.10, tree-sitter, xgboost (optional), ruff, pytest
- **Package:** `syrth` v3.0.0, entry point `syrth = syrth.scan:main`
- **License:** MIT

## Context Modules

| File | Purpose | Priority | Freshness |
|---|---|---|---|
| `00_SCHEMA.md` | Rules of this context system itself | LOW | 2026-10-02 |
| `SYSTEM/agent_rules.md` | Operating rules for agents on this repo | HIGH | 2026-10-02 |
| `SYSTEM/safety_constraints.md` | Destructive/irreversible operation limits | HIGH | 2026-10-02 |
| `SYSTEM/workflow.md` | BOOT→LOAD→VERIFY→PLAN→EXECUTE→VALIDATE→SYNC→RECORD | MED | 2026-10-02 |
| `PROJECT/overview.md` | Mission, philosophy, maturity, capabilities | HIGH | 2026-10-02 |
| `PROJECT/architecture.md` | Components, data flow, invariants | HIGH | 2026-10-02 |
| `PROJECT/technical_reference.md` | Algorithms, schemas, thresholds, formats | HIGH | 2026-10-02 |
| `PROJECT/file_map.md` | Verified repository structure | MED | 2026-10-02 |
| `OPERATIONS/commands.md` | Install/build/test/lint/benchmark commands | HIGH | 2026-10-02 |
| `OPERATIONS/environment.md` | Runtime, tooling, network, limits | MED | 2026-10-02 |
| `OPERATIONS/testing.md` | Framework, layout, coverage gaps | HIGH | 2026-10-02 |
| `STATE/current_state.md` | What is true *right now* | **HIGHEST** | 2026-10-02 |
| `STATE/known_issues.md` | Open defects with reproduction + evidence | **HIGHEST** | 2026-10-02 |
| `STATE/decisions.md` | Decisions with rejected alternatives | HIGH | 2026-10-02 |
| `USER/preferences.md` | Explicitly stated user preferences | MED | 2026-10-02 |
| `HISTORY/changelog.md` | Append-only meaningful change log | MED | 2026-10-02 |

## Task Routing

### Working on the taint engine / detection quality
Load: `STATE/known_issues.md` → `PROJECT/architecture.md` → `PROJECT/technical_reference.md` → `OPERATIONS/testing.md`

### Reproducing or trusting a benchmark number
Load: `STATE/current_state.md` → `OPERATIONS/commands.md` → `PROJECT/technical_reference.md` (measurement section) → `HISTORY/changelog.md`
**Read the benchmark-integrity issues in `STATE/known_issues.md` first.** Measured numbers have been wrong three times.

### Changing the parser / grammar handling
Load: `PROJECT/architecture.md` → `PROJECT/technical_reference.md` → `OPERATIONS/testing.md`

### Packaging / release / dependency changes
Load: `PROJECT/technical_reference.md` → `OPERATIONS/commands.md` → `OPERATIONS/environment.md`

### Working with the v1 legacy tree
Load: `PROJECT/file_map.md` → `STATE/decisions.md`
v1 is retained for audit only. It is not maintained and must not be used as a
source of truth for current behaviour.

## Unresolved Issues

1. **Detection quality is unquantified.** No trustworthy recall figure exists. See
   `STATE/known_issues.md` KI-001 … KI-004.
2. **Rebuild-vs-repair is undecided.** The user raised a full rebuild; no
   architecture decision has been recorded. See `STATE/current_state.md`.
3. **The corpus label strategy is unsound.** See KI-002. This blocks any
   accuracy claim.

## Known Context Limitations

- No CI configuration exists (`.github/` absent), so no automated gate exists.
- `data/` is generated and gitignored; the corpus must be rebuilt to reproduce
  benchmarks. Rebuild procedure is **not yet scripted** into the repo.
- Model bundles (`*.joblib`, `syrth_codebert/`) are v1 artifacts present on disk,
  gitignored, and **not** loadable by v3. Do not treat them as current.
- Context was bootstrapped from the working tree, which is uncommitted. After the
  first v3 commit, re-verify and update `Repository Commit` here.