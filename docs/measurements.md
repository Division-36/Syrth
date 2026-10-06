# Measured results

Everything here was produced by a command in this repository. Nothing is
estimated, and nothing that could not be reproduced is quoted.

## Where the data comes from

`data/cve_pairs.jsonl` — 498 records, 249 vulnerable/safe pairs, built by
`experiments/scratch` tooling from the commit history of five real projects:
django, urllib3, werkzeug, sqlalchemy and requests.

Each pair is a real security fix. The **pre-fix** function is labelled with the
advisory's CWE; the **post-fix** function is labelled safe. Fix commits come from
the OSV API; the code comes from `git show <sha>^:<path>` and `git show
<sha>:<path>`, so ground truth is a real commit, not a synthetic example.

Each record carries the file's imports and module-level constants, because a
function extracted in isolation is not the program it came from.

## Results

Measured on the held-out split of 124 records (62 unsafe, 62 safe) on 2026-10-02.
Of 62 unsafe records 5 were detected; of 62 safe records 10 were reported.

| metric | value | 95% CI |
|---|---|---|
| precision | **26.3%** | [7.1%, 50.0%] |
| recall | **8.1%** | [1.8%, 15.9%] |
| F1 | 12.4% | |
| selective precision @0.9 | 0.0% | |
| coverage on unsafe records | 14.5% | |
| abstention on safe records | 83.9% | |
| false-positive rate on safe records | 16.1% | |
| rename invariance | **91.1%** | |
| patch kill rate | 73.3% | |

Reproduce with:

```
python -m benchmarks.run_benchmarks --dataset data/cve_pairs.jsonl
```

## What these numbers say

**The tool misses about 92% of real vulnerabilities.** Recall of 8.1% is the
headline defect. The synthetic smoke set in `RLTESTS/` reports 96% recall,
because those examples were written to be found; real fixed CVEs are not.

**Precision is 26.3%, so roughly three in four findings are wrong.** Confidence
at the 0.9 level is worthless as a filter: selective precision at that threshold
is 0.0%, meaning no flow the analyser reports with full confidence against real
code was the labelled vulnerability.

**Rename invariance is 91.1%, not 100%.** This is a documented guarantee, and it
currently fails on 8.9% of records. The metric itself was understated until the
harness bugs below were fixed, so earlier figures were measuring the harness.

**26.7% of confirmed flows survive a correct sanitiser.** The kill model does not
understand those categories, so a patch that genuinely fixes the bug can be
reported as still vulnerable.

## Failures found while measuring

The first three runs reported numbers that were wrong because of harness and
corpus bugs, not analyser behaviour. Each is now covered by a test.

* **`alpha_rename` used two-tuple `untokenize`.** That rebuilds spacing
  heuristically and silently truncated a backslash line continuation, changing
  the program. It made the invariance metric measure the renamer's corruption.
  Fixed by passing five-tuples so exact layout is preserved.
* **`renameable_names` renamed free names.** In a fragment whose imports are not
  visible, a sink like `render_to_response` looks locally defined, so the renamer
  renamed it and removed the very flow under test. Fixed by renaming only names
  the fragment itself binds.
* **364 of 510 corpus records did not parse.** Extracted methods arrived
  indented, so they were `IndentationError` fragments and produced no findings.
  Measured recall was 9% partly because the scanner was being fed nothing.
  Fixed by dedenting the function separately from its module context and
  validating the parse when building the corpus.
* **Guard recognition could not change any verdict.** `MIN_TAINT_CONFIDENCE`
  (0.55) sat above the reporting threshold (0.5), so the partial-mitigation
  factor could never demote a finding. `in` and `not in` were also classified
  backwards, the strength was written to one `TraceStep` field and read from
  another, and the string-literal extractor left the opening quote attached to
  every regex.

## Limits of this measurement

* **One corpus, one source.** 93% of records are django. A different mix of
  projects could move every number.
* **Noisy labels.** The patched function is assumed safe for the advisory's CWE.
  A fix commit can address several issues, and a rewrite can add a new one, so
  some "safe" records are not safe and some "vulnerable" fragments were already
  partly mitigated in their own revision.
* **Unsupported classes count as misses.** CWE-400 and CWE-200 appear in the
  corpus but not in the classifier's label space. They are left in and scored as
  failures rather than dropped, because removing them would flatter recall.
* **Small test split.** 124 records, so the confidence intervals are wide. The
  recall interval spans 1.8% to 15.9%; the point estimate should not be read to
  one decimal place.
* **No competitor baseline.** Bandit or Semgrep on the same corpus would say
  whether 8.1% is bad in absolute terms. It has not been run.
* **No learned model is quoted.** These figures are the deterministic rule and
  taint path. No trained bundle is shipped or measured.

## Smoke set

`benchmarks/rltests.py` evaluates the 40 hand-written functions in `RLTESTS/`
using their section markers as labels. It is a regression gate, not a benchmark:
the set was authored by this project and every vulnerable example was written to
be findable. Current result: recall 96.0%, false alarms 46.7% (down from 53.3%
after guard support), abstention 53.3%.
