# Withdrawn v1 results

**Status: every quantitative result produced by the v1 pipeline is withdrawn.**
The qualitative work (the problem statement, the related-work survey, and the
discussion of why static analysis fails) is unchanged by the withdrawal. No
accuracy figure is claimed in its place, because none has been measured on a
leak-free corpus with the corrected pipeline.

This document records what was claimed, what the audit found, and why each claim
is withdrawn. It is the artefact to read before trusting anything this project has
previously said about its own accuracy.

## 1. Why the results were withdrawn

The v1 pipeline had defects that made its headline numbers unreproducible from the
code and data in the repository. Three of them are load-bearing.

### 1.1 The meta-learner never executed

`syrth_scan.py` (v1) read `meta_bundle["meta_model"]`, but every trained bundle
stored the key `"meta_models"` (a list). The lookup raised `KeyError` inside:

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

also swallowed. The consequence was visible inside the repository's own
`ablation_results.json`: the row labelled **"1. Full System (Baseline)"** and the
row labelled **"4. Ensemble Only (No Meta-Learner)"** were identical in accuracy,
precision, recall, F1, per-class accuracy and confusion matrix. They differed only
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

If neither class was the argmax the swap was a no-op, so the meta-learner's opinion
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
measured the label, not the code.

## 2. Claim by claim

| Claim | Where it appeared | Verdict |
|---|---|---|
| 70.8% held-out accuracy | abstract, introduction, `README.md` | **Withdrawn.** Re-running the v1 `eval_heldout.py` at audit time gave 70.0% (194/277). The README's per-class table matched no run in the repository. The result depended on `syrth_model.joblib`, which was never committed. |
| 86.8% on real CVE code blocks | abstract, results, `README.md` | **Withdrawn.** Re-running gave 87.2%. The corpus it evaluated contained 58.8% training records, so it was a training-set score. The README described this figure as "the honest production metric". |
| 69.0% on a "strictly held-out" test set | abstract, results | **Withdrawn as a held-out result.** The split was a seeded random shuffle within each class, not grouped. `ghsa_id` was unique per record (5669/5669), so keying on advisory identity grouped on nothing. 177 of 277 test records shared a token 3-gram with a training record. |
| "Leakage: 0 records" | `README.md` | **Withdrawn.** The check tested exact `(tokens, label)` equality only. 36 identical token sequences appeared on both sides of the split carrying *different* labels, which caps achievable accuracy and means the test set contained feature vectors already seen in training under a different answer. |
| "Dev/Fast agreement 100%" | `README.md` | **Withdrawn as unverifiable.** Dev mode defaulted to a five-model ensemble; fast mode read a C header exported from a *different*, single model. The only recorded run (`__run.log`) reported 23.4% agreement. |
| "Statistically significant improvements" | abstract, introduction | **Withdrawn.** No statistical test existed anywhere in the codebase, and no confidence intervals were computed. `benchmark.py` printed the phrase unconditionally. |
| "Taint propagates through f-strings" | abstract, `collect.py` docstring, `README.md` | **Withdrawn as a capability claim.** It was false. tree-sitter models an f-string as a `string` node whose children are `interpolation` nodes, and the analysis had no case for `interpolation`. Every f-string was treated as a constant, so every f-string injection was missed. |
| "Taint-confirmed gating reduces false positives" | abstract, `README.md` | **Withdrawn as stated.** There was no distinction between safe and unsafe sink usage. `execute(sql, params)` appeared safe only because `ast.Tuple` was not handled, an accident rather than a design. `authenticate(username=..., password=...)` produced `tainted:authenticate`. |
| 91.6% / 93.4% record-level | git history | **Withdrawn.** Produced by a script that iterated the full corpus including training records, passed the advisory description into the features, and selected the best aggregation method post-hoc over five candidates. |
| 93.8% | requested figure | **Withdrawn as unsubstantiated.** The string does not appear in any file, log, or commit message. |

## 3. Additional defects found during the audit

These did not affect a headline number directly but invalidated the evidence
behind them.

* **Nondeterministic token generation.** `collect.py` resolved sinks by iterating
  a `frozenset` and breaking on the first match. `str` hashing is randomised per
  process, so the same file produced `sink:cursor.execute` under one
  `PYTHONHASHSEED` and `sink:execute` under another. Training and inference built
  different vocabularies.
* **The scanner crashed on Windows.** The report used box-drawing characters and
  raised `UnicodeEncodeError` under the default `cp1252` console codec, which is
  why the end-to-end test harness had to capture stdout instead of reading it.
* **The test suite did not terminate.** `tests/test_export.py` regenerated a
  22 MB C header five times and regex-parsed it back, taking minutes per run.
* **Test-set accuracy was used as a hyperparameter.** Ensemble weights were set to
  held-out accuracy, so the held-out set was no longer held out.
* **`make train` and `make dataset` could not work.** `train_model.py` raised
  `SystemExit("DEPRECATED")` on import; `repair_dataset.py` accepted no positional
  arguments.
* **The default model was unreproducible.** `syrth_model.joblib` and
  `syrth_engine.h` were never committed, so neither the default dev path nor the
  fast path could be reconstructed from a clone.

### Why the v1 code is not published

The v1 pipeline was removed from this repository rather than kept as runnable
history. Publishing dead tooling that still looks executable invites someone to run
it and believe its output, which is the failure this document exists to prevent.

The audit above is therefore a record of the withdrawal, not a script you can
replay. It quotes the code that caused each defect and names the file it lived in,
so the reasoning can be checked against the quoted behaviour. The scripts
themselves are not part of any public release of SYRTH. Anyone who needs them for a
formal audit should contact the maintainers rather than treat this repository as
their source.

`syrth_scan.py` survives in the current tree as a compatibility shim that forwards
to the current CLI and prints the retirement notice.

## 4. What replaced it

The pipeline was rewritten rather than patched. The corrections that matter for
anyone assessing the current code:

* The node-text reader decodes from the **encoded bytes** rather than slicing the
  decoded string with tree-sitter's byte offsets. The previous reader silently
  corrupted every identifier, sink, argument and call name after the first
  multi-byte character in a file.
* Taint is seeded from **parameter position**, not from a regex on the parameter
  name, so verdicts are invariant under consistent renaming. This is measured by
  `benchmarks.run_benchmarks`.
* f-strings, `.format()`, `%`-formatting, keyword arguments, comprehensions,
  augmented assignment, attribute targets and module scope are all analysed.
* Sanitisers are modelled as **category-typed kills**, and sinks carry **argument
  schemas** so `cursor.execute(sql, params)` is not a finding.
* The rule classifier and the ML classifier emit from **one closed label space**.
* The ML classifier can only refine the probability of a confirmed flow. It can
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

Until those exist, this project makes claims about *what it does* (invariance,
proof-carrying output, mechanical patch verification) and none about how often it
is right relative to any other tool.
