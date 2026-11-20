# Cross-tool comparison on full repositories — results

**Pre-registration:** [tool-comparison-preregistration.md](tool-comparison-preregistration.md),
registered before the first repository scan. The analysis follows it.

The first paper compares instruments on 350 extracted snippets. This experiment
points them at the same whole worktrees: the vulnerable revision of one fix
commit per repository, in corpus order, across all 24 repositories. The
comparison is **co-location**, not precision or recall — the corpus has no
reliable negative class, and a different tool's finding is not ground truth.

```bash
make tool-comparison    # or: python -m benchmarks.tool_comparison --json data/tool_comparison.json
```

Bandit, Semgrep and Ruff report a file and a line but not the enclosing
function. The harness derives the function from the source at the reported
line, so the co-location denominator is the number of findings with a
recoverable function, not all findings. Both counts are published.

## Tools

Bandit 1.9.4, Semgrep 1.185.0 (`p/security-audit`), Ruff 0.15.15
(`--select S`), SYRTH with the call graph (this tree).

## Results

| Instrument | Findings, all 24 trees | Functions with a name | Co-located with a certificate | Labelled file hit |
|---|---|---|---|---|
| SYRTH | 579,497 | 8,075 | 8,075/8,075 | 23/24 |
| Bandit 1.9.4 | 103,575 | 44,208 | 2,203/44,208 (5.0%) | 17/24 |
| Semgrep 1.185.0 | 1,205 | 500 | 241/500 (48.2%) | 11/24 |
| Ruff 0.15.15 | 61,339 | 26,602 | 1,837/26,602 (6.9%) | 17/24 |

Every rate is `n/N`: the numerator is the number of findings whose derived
(file, function) matches a file+function where SYRTH emitted a certificate,
and the denominator is the number of findings with a recoverable function.
SYRTH's own 8,075/8,075 is a sanity check, not a result: every function it
reports is by construction a function where it emitted a certificate.

## Reading the table

* **Semgrep has the highest co-location share (241/500), Ruff and Bandit the
  lowest.** Semgrep emits far fewer findings, so the same absolute number of
  overlaps is a larger share of a smaller denominator. A bare percentage
  would flatter the narrower instrument, which is why both counts are shown.
* **SYRTH's labelled-file hit is 23/24**, Bandit's and Ruff's 17/24, Semgrep's
  11/24: on most repositories at least one other tool also reports something
  in the file the advisory was about, but Semgrep does so less often.
* **This is not a statement that one tool is better.** The instruments model
  different classes and emit findings at different granularity. A co-located
  finding is evidence that two tools looked at the same place, nothing more.
* **Cost is reported, not claimed as an advantage.** On this machine the four
  instruments took 1,027 s (SYRTH), 488 s (Bandit), 744 s (Semgrep) and 9 s
  (Ruff) over the same 24 trees. These are wall-clock numbers on one machine,
  not a throughput benchmark.

## What this does not show

No accuracy, precision or recall figure is reported. No claim is made that
SYRTH finds more vulnerabilities: the tools' rule sets differ, and a class a
tool does not model cannot be found by it. The co-location rate measures
agreement on location, not correctness.
