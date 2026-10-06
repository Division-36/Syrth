# Archived documentation

These documents describe the **retired v1 pipeline**. They are kept for
provenance and are **not** current documentation.

Do not follow instructions in these files. They reference interfaces that no
longer exist:

| they mention | current reality |
|---|---|
| `syrth_scan.py --mode dev\|fast` | `syrth_scan.py` is a deprecation shim; the flag is gone |
| PyTorch, CodeBERT | no PyTorch anywhere; default install is two dependencies |
| 5-class and 15-class label sets | the label space is 11 CWEs |
| `_build_5class.py`, `_full_dataset_5class.json` | v1 scripts, archived under `experiments/v1/` |
| meta-learner, stacking ensemble | retired; the meta-learner never executed correctly |
| accuracy figures (70.8%, 86.8%, …) | **withdrawn** — see [`../../paper/WITHDRAWN.md`](../../paper/WITHDRAWN.md) |

Current documentation is in [`../README.md`](../README.md):

- [risk-model.md](../risk-model.md) — what the tool claims
- [usage.md](../usage.md) — how to run it
- [architecture.md](../architecture.md) — how it is built
- [limitations.md](../limitations.md) — what it cannot do

## Files

| File | Formerly |
|---|---|
| `API.md` | v1 Python API, torch-based |
| `EXAMPLES.md` | v1 CLI examples with `--mode dev` |
| `INDEX.md` | v1 documentation index |
| `INSTALLATION.md` | v1 install with PyTorch and CUDA |
| `CONTRIBUTING.md` | v1 contribution guide |
| `dependency_analysis.md` | v1 dependency size analysis (~200 MB PyTorch) |
| `target_specs.md` | v1 targets, including numbers that were never met |
