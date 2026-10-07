# Legacy — the retired v1 pipeline

Nothing in this directory is maintained, installed, or tested. It is retained as
audit provenance: `paper/WITHDRAWN.md` explains which published results were
withdrawn and why, and this directory is where the code that produced them can
still be read.

## Why it is kept

The v1 withdrawal claims specific things — that the meta-learner never executed,
that the label space leaked the target, that the split was not grouped. Those are
verifiable claims about specific code. Deleting the code would make them
unverifiable and would destroy the record of what was replaced.

## Layout

| Path | Contents |
|---|---|
| `v1-scripts/` | the v1 entry-point scripts: harvester, dataset builder, trainer, evaluators |
| `../experiments/v1/` | v1 analysis scripts that were moved out of the repository root |
| `../experiments/scratch/` | local scratch, gitignored |
| `../syrth_scan.py` | a **live** deprecation shim — forwards to `syrth.scan` and is tested |

`syrth_scan.py` is the one exception: it is still runnable and still tested. It
is not v1 code, it is a compatibility entry point that routes old command lines
to the current scanner and prints a deprecation notice.

## What v1 was

A five-model ensemble with a stacking meta-learner, fed advisory text including
the ground-truth CWE description as a feature. It reported accuracy figures that
could not be reproduced from the code and data in the repository.

## What replaced it

`syrth/` — a risk-surface analyser that reports the nearest vulnerability class
with a likelihood and its evidence. See [`../docs/risk-model.md`](../docs/risk-model.md).

## Do not

- Do not run these scripts expecting them to work. They depend on datasets that
  are not committed and on libraries the project no longer uses.
- Do not copy security decisions from here. The sink tables, sanitisers and label
  space all changed.
- Do not quote any figure that appears in these files or in the v1 sections of
  `docs/CHANGELOG.md`. They are historical records, not results.

## Import path note

These scripts reference each other and the repository root by relative path, which
no longer resolves after the move. That breakage is expected and is not a
regression: the directory is archival.