# Current State — SYRTH

`[FACT]` Verified 2026-10-03, working tree at commit `3a38572` (dirty).

## Development phase

**Corpus rebuilt and labels verified; risk model measured; competitor comparison
and trained model still outstanding.**

The blocking dependency from the previous cycle — an unsound corpus — is now
resolved for `data/corpus.jsonl`. What remains is evidence about the analyser's
*ranking*, not its detection surface, plus the version migration the user asked
for.

## Verified current state

| Check | Result |
|---|---|
| `python -m pytest tests -q -o addopts=` | **630 passed, 1 skipped** (skip = no C compiler) |
| `python -m ruff check syrth tests benchmarks tools` | **All checks passed** |
| `python -m benchmarks.risk_metrics --dataset data/corpus.jsonl` | coverage **95.7%** (111/116), kill **89.0%** (89/100), rank agreement **100%**, invariance **100%**, determinism **100%** |
| `python -m benchmarks.competitors --dataset data/corpus.jsonl` | coverage: syrth **95.7%** (111/116), bandit **19.8%** (23/116), semgrep `p/security-audit` **14.7%** (17/116), semgrep `p/owasp-top-ten` **0%** (0/116). Fix noticed: syrth 8/74, bandit 8/60, semgrep 11/25, owasp 1/3 |
| `python -m benchmarks.adjudicate.py` | 115 cases for human reading; **no verdict is scored** |
| `tools/build_corpus.py` end-to-end | 350 records / 175 pairs / 80 advisory split units / 24 repos / 7 classes |

Metrics deliberately absent: precision, recall, false-positive rate. See
[Withdrawn: the precision section](../docs/benchmark.md#withdrawn-the-precision-section)
-- `docs/risk-model.md` defines the measurements, and those three are not among
them. Any number of that kind found elsewhere in this project is out of date.

Run tooling with `uvx` — the project dev dependencies (pytest, ruff, tree-sitter,
xgboost) are not installed in the interpreter on PATH:

```
uvx --with pytest --with tree-sitter --with tree-sitter-python --with numpy \
    --with xgboost --with scikit-learn --with joblib python -m pytest -q -o addopts=
```

## The corpus

`data/corpus.jsonl` is built by `tools/build_corpus.py` and is the first corpus
whose labels are defensible:

- Sources are **GHSA queried per affected distribution** plus **OSV**, merged.
  The global GHSA listing was abandoned: it is date-ordered across all
  ecosystems, so 1200 advisories yielded 78 usable ones against 308 from the same
  packages queried per-package.
- A record is accepted as vulnerable **only when its own source contains the
  class's sink**, resolved through `syrth.registry`. The builder previously kept
  its own sink table and drifted, labelling `numpy.load` as CWE-502.
- Two identifiers: `pair_id` joins the vulnerable and patched sides;
  `group` is the advisory and is the train/test split unit.

Manifest at `data/corpus_manifest.json` records what was declined and why,
including the repositories skipped by the size cap.

## Evidence tiers

Corpus records are filed in one of two tiers, per record:

- `direct-sink` (67 pairs) — the labelled source itself calls the class's sink.
- `module-proximity` (108 pairs) — it produces a value for a sink elsewhere in
  the same module, and the record names that sink plus repo/commit/file.

The second tier exists because Django's SQL injection fixes cannot be labelled at
function granularity: `PostGISOperator.as_sql` builds the query, a compiler calls
`cursor.execute`. Coverage is reported per tier (96.8% direct, 85.7% proximity) so
the weaker guarantee is never hidden inside the headline.

## Precision

The first precision figure published for this project was wrong in the most
damaging way: 59.7%, computed against a name-list oracle coarser than the
analyser, where all 75 disagreements were sinks the oracle could not see
(`os.path.join`, `Markup`, `FileResponse`). Adjudicating them by hand gives
**94.6%**, complete, with nothing left unadjudicated. Verdicts are data in
`data/adjudications.jsonl`, not prose, so the figure is reproducible.

The ten remaining rejections are all the same defect: reporting the weakest link
of a chain (`os.path.abspath`, `jinja2.Environment`, `__import__`) as if it were
the dangerous operation. Specific and fixable in the registry.

## Blockers

1. **19 containment guards are not modelled.** `commonpath`,
   `normpath().startswith()`, `dirname` comparison, `resolve()` plus raise, and
   application-specific validators. These are registry entries, not analysis:
   adjudicating the survivors showed they are 61% of the decidable false
   positives, and none of them needs value-level reasoning.
2. **No trained model.** The XGBoost ranker is implemented and tested for
   numerical agreement with live xgboost, but no bundle is trained or measured.
3. **Four classes have no corpus records** — CWE-327, 434, 611, 798. Widening the
   harvest is the fix, never loosening `class_evidence`.
3. **KI-003** — no CI.

## Immediate next steps, in dependency order

1. Train the ranker on `data/corpus.jsonl` with a split grouped on `group`,
   and report held-out numbers.
2. Version migration: current code becomes **1.0.0**, the v1-era code in
   `legacy/v1-scripts` and `docs/archive` becomes **v0.x**. Git tags need a plan
   before anything is rewritten.
3. Widen the harvest for the remaining four classes.

## Explicitly not current

`[FACT]` All v1 accuracy figures are withdrawn (`paper/WITHDRAWN.md`).

`[FACT]` No trained model exists. The `*.joblib` files on disk are v1 artefacts
and will not load in the current package.

`[FACT]` Package version is still `3.0.0`; the rename to `1.0.0` has not started.

`[FACT]` Everything described as current exists only as uncommitted files. The
last commit, `3a38572`, is v1-era.