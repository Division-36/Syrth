# Pre-registration: cross-tool path comparison on full repositories

**Status:** registered before the first repository scan.
**Registered:** 2026-11-17.
**Paper:** the second SYRTH paper, experiment 2. Experiment 1 (certificate-
verified repair) is registered separately in `paper2-preregistration.md`.

This document fixes the population, the measures and the analysis before the
cross-tool scan is run, so that the "we compared against other tools" claim
cannot be re-scoped after the numbers are known.

## 1. The question

The first paper compares four instruments on 350 extracted snippets. That
comparison has a known limitation: it does not measure what happens when each
tool is pointed at a whole repository, where imports, call graphs and thousands
of unrelated files change both the findings and the cost. This experiment asks
what each tool actually reports on the same full trees at the same fix commits,
and whether the certificates agree with them on the file and function that
matter.

## 2. Population and denominators

* **Repositories:** the 24 repositories in the corpus, at the vulnerable
  revision of one fix commit each. One commit per repository, chosen as the
  first commit in `data/corpus.jsonl` order, so the choice is mechanical and
  recorded.
* **Instruments:** SYRTH (with the call graph), Bandit 1.9.4, Semgrep 1.185.0
  (`p/security-audit`), Ruff 0.15.15 (`--select S`).
* **Denominator:** the number of findings each tool reports on the same tree.
  The comparison is a *co-location* measurement, not precision or recall: the
  corpus has no reliable negative class, and a different tool's finding is not
  ground truth.

## 3. Measures

For each tool and each repository:

| measure | definition |
|---|---|
| `findings` | the number of findings the tool reports on the tree |
| `files_touched` | the number of distinct files with at least one finding |
| `functions_touched` | the number of distinct (file, function) pairs with a finding |
| `labelled_file_hit` | whether the tool reported anything in the labelled file of this commit's pairs |
| `labelled_function_hit` | whether the tool reported anything in the labelled function of this commit's pairs |
| `certificate_co_location` | of the tool's findings, how many land in a file+function where SYRTH emitted a certificate |
| `bytes_scanned` | the size of the scanned tree, for the cost column |

The unit is the tool's finding; every rate is reported as `n/N` with its
denominator. No rate is a detection-quality claim.

## 4. What is not measured

* No accuracy, precision or recall: there is no negative class.
* No "SYRTH finds more" claim: the tools model different classes, and a
  missing rule is not a missed finding.
* No runtime superiority claim: the timings are wall-clock on one machine,
  stated with that machine's conditions, not a throughput benchmark.

## 5. Analysis

Counts and co-location rates per tool, with their denominators, plus the
median and interquartile range of findings per repository. The analysis is
descriptive: no hypothesis test is used to rank tools, because the
instruments are not interchangeable.

## 6. Stopping rules

The scan runs over all 24 repositories and all four instruments. If one tool
is unavailable on a repository, that repository-tool cell is reported as
unavailable with the reason, and the remaining cells are still reported. The
run is not stopped early for a convenient result.

## 7. Deviations

| date | deviation | decided |
|---|---|---|
| — | none yet | — |
