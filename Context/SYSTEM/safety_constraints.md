# Safety Constraints — SYRTH

## Destructive operations — require explicit confirmation

- Deleting or rewriting anything under `Context/HISTORY/`.
- `git reset`, `git checkout --`, `git clean`, force-push, history rewrite.
- Removing the `data/` corpus once a real corpus exists.
- Deleting `legacy/`, `experiments/`, or `paper/` — these are audit provenance.
- Broad refactors that delete working code, including "start over" style changes.

## Irreversible / expensive operations — require confirmation

- Full rebuilds of the analysis core. Confirm scope first: a rebuild and a
  targeted repair are very different efforts, and the project has already
  changed direction once.
- Re-harvesting the corpus. It clones ten repositories and makes many `git show`
  calls; the clone cache makes a re-run minutes, not hours, but confirm before
  discarding an existing corpus.

## Secrets

Never write credentials, API keys, tokens, or `.env` contents into `Context/`.
Environment variables may be referenced **by name only**.

## Generated artifacts

These are large and gitignored. Treat deleting them as low-risk but note it:

| Path | Size observed |
|---|---|
| `syrth_codebert/` | ~476 MB (`model.safetensors`) |
| `syrth_ensemble.joblib` | ~24 MB |
| `syrth_model.joblib` | ~6 MB |
| `syrth_engine.so` | ~6.6 MB |
| `_full_dataset*.json` etc. | several MB each |
| `testingMassiveDataset.json` | ~1.1 MB |

## Data-loss risks

- `harvester.py` writes JSON datasets to the repo root and can overwrite existing
  dataset files. Confirm output paths before running.
- `syrth.patch` **rewrites source files** when invoked with `--fix`. Its
  verification requires the file to still parse and the flow to be gone, but it
  is still an in-place mutation of user code. Prefer running it against a scratch
  copy first.
- `benchmarks.revision_diff.materialise` writes a `git archive` extraction tree to
  a destination directory. Do not point it at the repository root.

## Security boundaries in this project

- SYRTH analyses untrusted source. The parser must never execute analysed code.
  Any change that introduces `eval`, `exec`, `pickle` of analysed input, or
  subprocess execution of analysed content is a security regression.
- Archive extraction validates member paths against the destination root; do not
  weaken this to "make it work".
- The C export (`syrth/classifier/export.py`) emits a header compiled and loaded
  by the test suite. Treat its output as untrusted input when testing.
- Parsed corpora and model bundles are untrusted input. Validate before load.

## Confirmation points

Stop and ask before: changing the public API, changing the trace or feature
schema versions, removing a category or CWE from the label space, changing the
reporting threshold's meaning, or any action that would make previously
published numbers unreproducible.