# Expanded tool comparison (v1.1, post-registration)

Date: 2026-11-24. This experiment was **not** pre-registered. It is an
exploratory extension of the registered cross-tool study, reported separately
and never pooled with Studies 3 and 4 or with the v1 capability table.

## Why it exists

The registered comparison scanned 24 whole worktrees with four instruments,
and the capability table used the frozen v1 corpus because Bandit and Semgrep
were unavailable in the expansion environment. Both tools are now installed
(Bandit 1.9.4, Semgrep 1.185.0), so the comparison can be re-run on the
expanded corpus with more instruments and more repositories.

## Populations

- **Snippet layer:** 700 records / 350 pairs. The v1.1 corpus has 738 records,
  but 19 expansion pairs change only module-level code: the vulnerable and
  patched *function bodies* are identical. The mitigation column would compare
  a snippet with itself, so those pairs are removed by
  `tools/filter_comparable.py`. The independent AST ground truth then yields
  320 provable class instances and 648 sink contacts.
- **Whole-tree layer:** 43 repositories, one fix commit each, at the vulnerable
  revision. All 43 clones were already present locally; no new cloning was
  done.

## Instruments

Nine snippet instruments: SYRTH, Bandit, Semgrep with six rule sets
(`p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/flask`, `p/django`,
`p/fastapi`), and Ruff with `--select S`. A rule set is part of the instrument:
collapsing the Semgrep configurations would hide which rules produced a count.

Four whole-tree instruments: SYRTH with the call graph, Bandit, Semgrep with
`p/security-audit`, and Ruff with `--select S`.

## Snippet results

Every cell carries its denominator. Class and sink coverage are against the
same independent AST scan; the fix column counts pairs where the tool named
the class before the fix.

| Instrument | Classes named | Sinks flagged | Fix noticed |
|---|---|---|---|
| SYRTH | 309/320 | 605/648 | 20/202 |
| Bandit 1.9.4 | 38/320 | 17/648 | 13/121 |
| Semgrep security-audit | 31/320 | 86/648 | 11/42 |
| Semgrep owasp-top-ten | 4/320 | 4/648 | 3/11 |
| Semgrep python | 4/320 | 4/648 | 3/11 |
| Semgrep flask | 4/320 | 4/648 | 2/4 |
| Semgrep django | 2/320 | 0/648 | 0/1 |
| Semgrep fastapi | 0/320 | 0/648 | 0/0 |
| Ruff `--select S` | 0/320 | 97/648 | 0/0 |

Ruff publishes no CWE metadata, so its 221 findings are recorded as unmapped
and it is scored only on the sink axis. A zero with a zero denominator is an
absence of measurement, not a perfect score.

## Whole-tree results

Co-location means the tool reported in a file/function where SYRTH emitted a
certificate. It is not precision or recall.

| Instrument | Findings | Co-located | Labelled file | Labelled function |
|---|---|---|---|---|
| SYRTH | 603,797 | 10,596/10,596 | 39/43 | 21/43 |
| Bandit | 148,840 | 2,825/63,224 | 30/43 | 9/43 |
| Semgrep | 1,608 | 350/658 | 16/43 | 4/43 |
| Ruff | 101,861 | 2,197/43,961 | 29/43 | 9/43 |

The matched capability profile in `data/tool_capability-v1.1.json` reports the
absolute margins over the next-best instrument on the same populations:
sink coverage 605/648 vs 97/648 (+508), class coverage 309/320 vs 38/320
(+271), and labelled function 21/43 vs 9/43 (+12). These are counts on a fixed
population, not accuracy differences.

## Reproduction

```console
python tools/filter_comparable.py --dataset data/corpus-v1.1.jsonl \
    --out data/corpus-v1.1-compare.jsonl
python -m benchmarks.competitors --dataset data/corpus-v1.1-compare.jsonl \
    --json data/competitor_benchmark-v1.1.json
python -m benchmarks.tool_comparison --dataset data/corpus-v1.1.jsonl \
    --repos experiments/scratch/repos --json data/tool_comparison-v1.1.json
python -m benchmarks.tool_capability_study \
    --competitors data/competitor_benchmark-v1.1.json \
    --trees data/tool_comparison-v1.1.json \
    --json data/tool_capability-v1.1.json
make verify-published
```

Bandit and Semgrep must be on `PATH` (or in `~/.local/bin`); the whole-tree
run took about 2,600 seconds of tool time on one machine and checkpoints after
each repository.

## What this does not show

The comparison is post-registration and exploratory. The rule sets are not
independent samples of the same tool, the 19 excluded pairs are absent from
every column, and co-location is not correctness. No precision, recall,
accuracy or state-of-the-art claim is made.
