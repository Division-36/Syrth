# Experiments

Historical and exploratory scripts, kept for provenance and out of the root so
the repository stays reviewable.

> **Their numbers are not reproducible and must not be quoted.** These scripts
> belong to the retired v1 pipeline. See `../../paper/WITHDRAWN.md` for the audit
> that explains why, and `../../legacy/README.md` for what replaced what.

## Layout

| Directory | Contents |
|---|---|
| `v1/` | Scripts tracked in git history that implement or evaluate the v1 pipeline: hyper-parameter searches (`_train_meta_v2` … `_train_meta_v11`), evaluation drivers (`_eval_code.py`, `_eval_record_level.py`, `_eval_meta_v2.py`), diagnostics (`_analyze_*.py`, `_check_*.py`, `_debug_*.py`), and the v1 rule classifier (`_rules.py`). |
| `scratch/` | One-off local analysis that was never tracked: CodeBERT training and evaluation, bundle inspection, threshold experiments, and ad-hoc dataset shaping. |

Nothing here is imported by the `syrth` package, and nothing here is covered by
the test suite.

## Why they are kept

Deleting them would have removed the evidence for the withdrawal. Anyone auditing
`paper/WITHDRAWN.md` needs to be able to check the specific defects it names:

* `_rules.py` — the five-class rule classifier and the import-token branch that
  never fired, because the v1 token extractor put imports in a separate JSON
  field rather than in the token stream.
* `_train_meta_v11.py` — the training loop that injected the ground-truth CWE
  description as a second training row's `source_code`.
* `_eval_meta_v2.py` — the evaluation path that passed the advisory description
  into the feature extractor at inference time.
* `_train_ensemble.py` — the code that set ensemble weights to held-out accuracy.
* `_eval_ensemble.py` — the results table that printed `"89.2"` and `"87.2"` as
  string literals rather than computing them.

## Known defects in this code, for reference

Documented in full in `../../paper/WITHDRAWN.md`. In summary:

* ensemble weights were fitted to held-out accuracy;
* the meta-learner read a bundle key the artefacts do not contain, and was handed
  a 20-element vector by a model fitted on 53 — both errors swallowed;
* one baseline defaulted to a fixed class rather than abstaining;
* one ablation removed `tainted:*` tokens while retaining `flow:*` tokens, so it
  removed no information;
* several per-class table values were hard-coded string literals.

## Do not run these expecting the numbers in any document

They depend on model bundles that are gitignored and were never committed
(`syrth_model.joblib`, `syrth_engine.h`), and on corpora that are gitignored
(`_full_dataset*.json`, `_balanced*.json`). A clean clone cannot reproduce them,
which is the point.
