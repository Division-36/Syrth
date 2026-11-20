# Certificate-verified patch repair — results

**Pre-registration:** [patch-verification-preregistration.md](patch-verification-preregistration.md),
registered before the first attempt. The analysis below follows it, with the
deviations recorded in the registration document.

This experiment asks the question the first paper leaves open: when a model
proposes a fix, does certificate-based verification change the verdict? The
model saw only the vulnerable source and the certificate — never the patched
side of the corpus, the advisory identifier or the commit hash. The guard in
`benchmarks/llm_patch` enforces this mechanically.

```bash
python -m benchmarks.patch_verification prepare --dataset data/corpus.jsonl \
    --json data/patch_prompts.jsonl
python -m benchmarks.patch_verification collect \
    --manifest experiments/scratch/patch-verification/manifest.json \
    --answers-dir experiments/scratch/llm-patch \
    --json data/patch_responses.jsonl
python -m benchmarks.patch_verification verify --dataset data/corpus.jsonl \
    --responses data/patch_responses.jsonl --json data/patch_verification.json
```

The second step separates generation from verification: the responses are
files, one per pair, and the generator is a subagent configuration of an LLM
reached through the agent harness. The generator is **not a fixed public
checkpoint**, so the responses — not the model — are the artefact of record.
They embed the corpus's third-party source and are therefore not committed;
they travel in the frozen archive beside the corpus. `data/patch_verification.json`
contains the results derived from them, without the source.

## Population

175 pairs are in the corpus. The primary population is the **57 pairs with a
confirmed labelled flow** — 54 from the function-level patch study and 3 that
are confirmed only when the module is scanned whole. Every one of the 57 was
attempted; none was skipped, and no attempt failed to produce a file.

## Primary endpoint

A verified kill means the returned file parses, the labelled flow is gone, and
no new flow of any class appeared. The certificate, not the diff, decides.

| Outcome | Count | Share of 57 | 95% Wilson interval |
|---|---|---|---|
| certificate-verified kill | 31/57 | 54.4% | [41.6%, 66.6%] |
| guard-only: the fix parses but the flow still holds | 21/57 | 36.8% | [25.5%, 49.8%] |
| the labelled flow was replaced by another one | 6/57 | 10.5% | — |
| a new flow of any class appeared | 6/57 | 10.5% | [4.9%, 21.1%] |

All 57 returned files parse and preserve the labelled function.

**This is the experiment's finding for the first claim.** 21 of 57 proposed
fixes are syntactically fine and leave the targeted flow standing: a
file-level check, a parse check, or a "no test failed" check would accept
them. A certificate check refuses them. The remaining 31 are the fixes for
which the flow really went away, and the 6 new-flow cases are fixes that
would have been approved on a weaker check but introduce a fresh flow.

## The confound the registration named

The corpus and the upstream fixes are public, so a model with pretraining
knowledge may reproduce a known fix from memory. The prompt does not show the
fix, but memory might. The registration therefore required the similarity
between each proposed change and the real upstream change to be reported:

* median token-level Jaccard similarity of the changed lines: **0.321**;
* range 0.005–1.000;
* **23 of 57** attempts are above 0.5.

The high-similarity tail is real, but it is not the majority: most proposed
changes are not copies of the upstream fix. The 31 verified kills must still
be read as "the model repaired the flow under these conditions", not as
"the model discovered a novel fix".

## By class

| Class | Attempts | Verified kill | Guard-only | Other |
|---|---|---|---|---|
| CWE-22 | 29 | 17 | 10 | 2 |
| CWE-79 | 11 | 4 | 5 | 2 |
| CWE-94 | 6 | 5 | 1 | 0 |
| CWE-502 | 6 | 3 | 3 | 0 |
| CWE-601 | 4 | 2 | 2 | 0 |
| CWE-89 | 1 | 0 | 0 | 1 |

## What this does not show

No accuracy, precision or recall figure is reported. The corpus has no
reliable negative class, and this experiment measures certificate behaviour,
not detection quality. The generator is one agent configuration at one point
in time; there is no comparison between models and no claim that one model is
better than another. The second attempt planned as a robustness check in the
registration was not run, which is recorded as a deviation there.
