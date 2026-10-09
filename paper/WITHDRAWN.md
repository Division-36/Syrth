# Withdrawal notice for the SYRTH v1 results

**Status: all quantitative results in `main.tex` are withdrawn.** The qualitative
sections (problem statement, related work, discussion of why static analysis
fails) remain. No accuracy figure is claimed in its place, because no figure has
been measured on a leak-free corpus with the corrected pipeline yet.

This document records exactly what was claimed, what was found, and why each claim
is withdrawn. It is the artefact a reviewer, a maintainer, or a prospective user
should read before trusting anything this project has previously said about its
own accuracy.

---

## 1. Why the results were withdrawn

The v1 pipeline had defects that made its headline numbers unreproducible from
the code and data in the repository. Three of them are load-bearing.

### 1.1 The meta-learner never executed

`syrth_scan.py` (v1) read `meta_bundle["meta_model"]`, but every trained bundle
stores the key `"meta_models"` (a list). The lookup raised `KeyError` inside:

```python
try:
    meta_model = meta_bundle["meta_model"]
except Exception:
    pass
```

and was then passed a 20-element feature vector to a `LogisticRegression` fitted
on 53 features, which raised:

```
ValueError: X has 20 features, but LogisticRegression is expecting 53 features
```

also swallowed. The consequence is visible inside the repository's own
`ablation_results.json`: the row labelled **"1. Full System (Baseline)"** and the
row labelled **"4. Ensemble Only (No Meta-Learner)"** are identical in accuracy,
precision, recall, F1, per-class accuracy and confusion matrix. They differ only
in `time_seconds`. The ablation table did not measure the full system, because
there was no full system to measure.

### 1.2 A hard-coded class index stood in for meta-learning

The final step of the meta-learner stage swapped probability mass between the
predicted class and a literal RCE index:

```python
rce_i = 4
if meta_pred != rce_i:
    meta_probs[meta_pred] = meta_probs[rce_i]
    meta_probs[rce_i] = orig
```

If neither class is the argmax the swap is a no-op, so the meta-learner's opinion
was discarded. If the prediction *was* RCE, the answer was unconditionally moved
away from RCE. RCE was the largest class in the test set, so one integer
determined a large share of the output while presenting as learned behaviour.

### 1.3 The meta-learner was trained and evaluated on the label

Training appended a second row per record whose `source_code` field was the
ground-truth CWE description text, then regexed it for sink keywords:

```python
desc_text = CWE_DESCRIPTIONS.get(label, "")
X_all.append(extract_meta_features_full(tokens, src))
X_all.append(extract_meta_features_full(tokens, desc_text))
y_all.append(label)
```

Evaluation passed the advisory description into the feature extractor
(`context = full_desc or src`). Any accuracy attributed to the meta-learner
measures the label, not the code.

---

## 2. Claim-by-claim

| Claim | Where | Verdict |
|---|---|---|
| 70.8% held-out accuracy | abstract, §Introduction, `README.md` | **Withdrawn.** Re-running the committed `eval_heldout.py` gives 70.0% (194/277); the README's per-class table matches no run in the repository. Depends on `syrth_model.joblib`, which is gitignored and was never committed. |
| 86.8% on real CVE code blocks | abstract, §Results, `README.md` | **Withdrawn.** Re-running gives 87.2%. The corpus it evaluates contains 58.8% training records, so it is a training-set score. The README also describes this figure as "the honest production metric". |
| 69.0% on a "strictly held-out" test set | abstract, §Results | **Withdrawn as a held-out result.** The split was a seeded random shuffle within each class, not grouped. `ghsa_id` is unique per record (5669/5669), so "keying on advisory identity" grouped on nothing. 177 of 277 test records share a token 3-gram with a training record. |
| "Leakage: 0 records" | `README.md` | **Withdrawn.** The check tested exact `(tokens, label)` equality only. 36 identical token sequences appear on both sides of the split carrying *different* labels — which caps achievable accuracy and means the test set contains feature vectors already seen in training under a different answer. |
| "Dev/Fast agreement 100%" | `README.md` | **Withdrawn as unverifiable.** Dev mode defaulted to a five-model ensemble; fast mode read a C header exported from a *different*, single model. The only recorded run (`__run.log`) reports 23.4% agreement. |
| "Statistically significant improvements" | abstract, §Introduction | **Withdrawn.** No statistical test existed anywhere in the codebase, and no confidence intervals were computed. `benchmark.py` printed the phrase unconditionally. |
| "Taint propagates through f-strings" | abstract, `collect.py` docstring, `README.md` | **Withdrawn as a capability claim.** It was false. tree-sitter models an f-string as a `string` node whose children are `interpolation` nodes, and the analysis had no case for `interpolation`. Every f-string was treated as a constant, so every f-string injection was missed. |
| "Taint-confirmed gating reduces false positives" | abstract, `README.md` | **Withdrawn as stated.** There was no distinction between safe and unsafe sink usage. `execute(sql, params)` appeared safe only because `ast.Tuple` was not handled — an accident, not a design. `authenticate(username=..., password=...)` produced `tainted:authenticate`. |
| 91.6% / 93.4% record-level | git history | **Withdrawn.** Produced by a script that iterated the full corpus including training records, passed the advisory description into the features, and selected the best aggregation method post-hoc over five candidates. |
| 93.8% | requested figure | **Withdrawn as unsubstantiated.** The string does not appear in any file, log, or commit message. |

---

## 3. Additional defects found during the audit

These did not affect a headline number directly but invalidated the evidence
behind them.

*   **Nondeterministic token generation.** `collect.py` resolved sinks by
    iterating a `frozenset` and breaking on the first match. `str` hashing is
    randomised per process, so the same file produced `sink:cursor.execute` under
    one `PYTHONHASHSEED` and `sink:execute` under another. Training and inference
    built different vocabularies.
*   **The scanner crashed on Windows.** The report used box-drawing characters and
    raised `UnicodeEncodeError` under the default `cp1252` console codec, which is
    why the end-to-end test harness had to capture stdout instead of reading it.
*   **The test suite did not terminate.** `tests/test_export.py` regenerated a
    22 MB C header five times and regex-parsed it back, taking minutes per run.
*   **Test-set accuracy was used as a hyperparameter.** Ensemble weights were set
    to held-out accuracy, so the held-out set was no longer held out.
*   **`make train` and `make dataset` could not work.** `train_model.py` raises
    `SystemExit("DEPRECATED")` on import; `repair_dataset.py` accepts no
    positional arguments.
*   **The default model was unreproducible.** `syrth_model.joblib` and
    `syrth_engine.h` are gitignored and were never committed, so both the default
    dev path and the entire fast path could not be reconstructed from a clone.

### Where each cited defect can be read

The v1 scripts are no longer tracked: their figures are withdrawn and keeping dead
tooling that looks runnable invites someone to run it. Every claim above is
nonetheless checkable, because each names a file that git still holds in history.

```console
$ git show 66ad8a5:legacy/v1-scripts/collect.py    # nondeterministic sink resolution
$ git show 66ad8a5:syrth_scan.py                   # the missing bundle key
$ git show 66ad8a5:legacy/v1-scripts/benchmark.py  # the unconditional "significant" phrase
$ git show 66ad8a5:legacy/v1-scripts/eval_heldout.py   # re-running the 70.8% claim
$ git show 66ad8a5:legacy/v1-scripts/train_model.py | head -20  # SystemExit on import
$ git show 66ad8a5:legacy/v1-scripts/repair_dataset.py     # takes no positional args
```

`66ad8a5` is the commit immediately before the deletion, and each path is verified
to resolve there. The scripts were at the repository root under the same names one
commit earlier still.

`syrth_scan.py` survives in the current tree as a 94-line shim that forwards to
the v3 CLI and prints the retirement notice; the file cited above is its
predecessor. The model bundles the default path loaded (`syrth_model.joblib`,
`syrth_ensemble*.joblib`, `syrth_meta*.joblib`) and the training datasets were
never committed and are not recoverable from any clone, which is the sixth defect
above and is the reason the published accuracies cannot be re-derived even in
principle.

---

## 4. What replaced it

The pipeline was rewritten rather than patched. The corrections that matter for
anyone assessing the current code:

*   The node-text reader decoded from the **encoded bytes** rather than slicing
    the decoded string with tree-sitter's byte offsets. The previous reader
    silently corrupted every identifier, sink, argument and call name after the
    first multi-byte character in a file — which silently renamed all eight
    functions in the project's own flagship test file.
*   Taint is seeded from **parameter position**, not from a regex on the parameter
    name, so verdicts are invariant under consistent renaming. This is measured
    by `benchmarks.run_benchmarks`.
*   f-strings, `.format()`, `%`-formatting, keyword arguments, comprehensions,
    augmented assignment, attribute targets and module scope are all analysed.
*   Sanitisers are modelled as **category-typed kills**, and sinks carry **argument
    schemas** so `cursor.execute(sql, params)` is not a finding.
*   The rule classifier and the ML classifier emit from **one closed label space**.
*   The ML classifier can only refine the probability of a confirmed flow. It can
    neither create nor delete a finding, and a model failure does not change the
    output.

## 5. What is needed before a number can be claimed again

1. A labelled corpus with stable group identifiers, committed to the repository,
   large enough that a bootstrap interval is narrower than the effect being
   claimed.
2. `python -m benchmarks.run_benchmarks` run on it, reporting precision,
   selectivity, `rename_invariance` and `patch_kill_rate` with confidence
   intervals.
3. Competitor baselines **executed by the same harness** on the same corpus.
   Quoted baseline numbers are not acceptable.
4. A patch-verification measurement: the fraction of confirmed flows that a
   categorically correct sanitiser removes.

Until those exist, this project makes claims about *what it does* — invariance,
proof-carrying output, mechanical patch verification — and none about how often
it is right relative to any other tool.
