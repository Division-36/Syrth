# Experiments

Local scratch space, and nothing tracked.

> **Anything that used to live here is either gone or withdrawn.** The v1 pipeline
> scripts that were kept here for provenance have been deleted; see
> [`../paper/WITHDRAWN.md`](../paper/WITHDRAWN.md) for the audit of what they got
> wrong, which cites each one by commit so the claims stay checkable without the
> files in the tree.

## What is here

| Path | Contents |
|---|---|
| `scratch/` | One-off local analysis, never tracked: CodeBERT training and evaluation, bundle inspection, threshold experiments, ad-hoc dataset shaping. Roughly 360 MB, mostly third-party checkouts. |
| `../legacy/` | Two READMEs that record what the retired pipeline was and why it is gone. No code. |

The v1 scripts (`_train_meta_v*.py`, `_eval_*.py`, `_analyze_*.py`, `_rules.py`)
were deleted rather than kept. They could not be run -- their inputs were the
model bundles and datasets that were never committed, so a clone could never
execute them -- and leaving runnable-looking tooling behind a "do not quote"
warning invites someone to try. `paper/WITHDRAWN.md` carries the verifiable claims
with a commit reference for each, which is the part that has value.

## Not in version control

`scratch/` is gitignored. It holds a corpus checkout and v1 benchmark output that
no review benefits from. If you need to reproduce the corpus, run
`python tools/build_corpus.py`; the advisory list it works from is public.