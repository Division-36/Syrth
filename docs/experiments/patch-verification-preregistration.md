# Pre-registration: certificate-verified patch verification

**Status:** registered before any fix attempt was run.
**Registered:** 2026-11-11, in the commit that adds this document (the tag
`v1.1-measurement` is the state of the tree the experiment was designed
against).
**Paper:** the second SYRTH paper (a statistical study; the first paper defines
the certificate and is not modified by this experiment).

This document fixes the questions, the population, the measures and the
analysis before any patch is generated. Deviations from it are recorded here
with the date and the reason, before the affected numbers are read.

---

## 1. Why this experiment exists

The first paper argues that the unit of output for a static analyser should be
a *trace certificate*: a source-to-sink path whose identity is computed from
the flow's structure, so that two revisions can be compared and a patch can be
accepted only when the targeted flow is gone, no new flow appeared, and the
file still parses.

That argument is currently supported by observation, not by experiment. The
whole-repository replay shows what real fixes do to certificates (most persist,
because most fixes add a guard rather than change the sink argument). What it
does not show is what happens when a machine proposes the fix, and whether
certificate-based verification changes the outcome.

This experiment asks that question with a machine as the patch author.

## 2. Questions and hypotheses

* **H1 (verification changes the verdict).** A share of the proposed patches
  pass a naive check (the file still parses and no test fails) while a
  certificate-based check refuses them, because the targeted flow still holds.
  *Directional, not directional in magnitude: the experiment measures the
  share, and the share may be zero.*
* **H2 (the flow goes).** Certificate-verified kills occur for a substantial
  share of the confirmed flows.
* **H3 (fixes introduce flows).** Some proposed patches remove the targeted
  flow and introduce a new flow of the same class in the same function.

Each hypothesis is reported with the number of attempts behind it. A
hypothesis that is not supported is reported as not supported.

## 3. Population and denominators

* **Corpus:** the 175 vulnerable/patched pairs in `data/corpus.jsonl`, built
  from real fix commits in 24 repositories.
* **Primary population:** the 57 pairs in which the labelled class is a
  *confirmed* flow in the labelled function — 54 at function scope (the
  function-level patch study) and 3 more that are confirmed only when the
  whole module is scanned. Every denominator below is over these 57 pairs
  unless it says otherwise.
* **Attempt:** one proposed patch per pair. An attempt exists as soon as a
  response has been recorded, whether or not the response parses.
* **A missing attempt is not a failure.** If a response cannot be obtained,
  the pair is reported as "no attempt" with its own denominator, and the
  primary rate is reported over the pairs that were attempted. The count of
  pairs without an attempt is published.

## 4. What the model is shown, and what it is not shown

The prompt contains, verbatim:

* the vulnerable source of the labelled function, with the module's imports;
* the certificate: the vulnerability class, the sink call the class is about,
  and the parameter that carries the flow.

The prompt **must not** contain, in whole or in part:

* the patched side of the corpus record (the real upstream fix);
* the advisory identifier or the commit hash, anywhere in the prompt;
* the repository name, in the prompt's instructions.

The repository name may appear *inside the vulnerable source*, because the
source is the code under test and its own imports name the project — a
Django module says "django". Removing it would mean editing the code the
model is asked to fix, so it stays, and it is part of the memorisation
confound below.

The harness enforces this mechanically: it builds the prompt from the
vulnerable record and the certificate only, and refuses to write a prompt
that contains a line of the patched side that the vulnerable side does not
already have. Lines are compared whole, after whitespace normalisation, so
that indentation cannot hide a shared line and a shared line is not mistaken
for the fix.

**Known confound, stated in advance:** the corpus is public, the repositories
are famous, and the upstream fixes are public. A model with pretraining
knowledge may reproduce an upstream fix from memory without ever seeing it.
The prompt does not show the fix; the model's memory might. This experiment
therefore also reports, for every attempt, the similarity between the proposed
change and the real upstream change, so that the share of attempts that
reproduce the upstream fix is visible rather than assumed absent. A result
whose mean similarity is high must be read as "the model reproduced a known
fix", not as "the model fixed a vulnerability".

## 5. The model

* The generator is an agent configuration: a large language model reached
  through an agent harness, identified in the results file by model
  identifier, provider, run date and the harness commit.
* It is **not a fixed public checkpoint** and is not seed-controlled. The
  experiment therefore reports what was produced, publishes the raw
  responses, and treats the published responses — not the model — as the
  artefact of record. Verification can be re-run from the published
  responses without the model.
  The responses embed the corpus's third-party source, so they are not
  committed to the repository: they travel in the frozen, checksummed archive
  beside the corpus, and the repository publishes the results derived from
  them.
* One attempt per pair is the primary analysis. A second attempt per pair is
  a robustness check on self-consistency; it is reported separately and does
  not enter the primary rate. If it is not run, that is recorded here as a
  deviation.

## 6. Measures

For each attempt:

| measure | definition |
|---|---|
| `parsed` | the returned source parses and the labelled function is present |
| `flow_gone` | the vulnerable side's labelled flow has no counterpart in the returned source: no trace of the labelled class remains in the labelled function |
| `flow_replaced` | a trace of the labelled class exists in the returned source that does not exist in the vulnerable side |
| `new_flow` | any trace of any class in the returned source that does not exist in the vulnerable side |
| `sink_call_present` | the sink call the advisory is about is still present in the returned source |
| `guard_only` | the labelled flow persists, the sink call is still present, and the returned source differs from the vulnerable source |
| `lines_changed` | the number of lines that differ between the vulnerable and the returned source |
| `reference_similarity` | the token-level Jaccard similarity between the proposed change and the real upstream change, computed on the changed lines only |

The certificate is the arbiter: `flow_gone` is decided by re-scanning the
returned source with the same analyser and comparing certificates, never by
reading the diff.

## 7. Endpoints

* **Primary:** the certificate-verified kill rate — attempts that are parsed,
  have `flow_gone` and have no `new_flow` — over the pairs attempted.
* **Secondary:** the parse rate; the share of attempts refused by the
  certificate while still parsing; the guard-only share; the new-flow share;
  the distribution of the reference similarity; and, when the second attempt
  is run, the self-consistency rate.

Every rate is published as `n/N` with its denominator, and every proportion
is reported with a 95% Wilson interval, which behaves at the small sample
sizes here. **No precision, recall, accuracy or state-of-the-art claim is
made**: the corpus has no reliable negative class, and the experiment measures
certificate behaviour, not detection quality.

## 8. Analysis plan

* Proportions: Wilson score intervals at 95%.
* Continuous measures (lines changed, similarity): median and interquartile
  range.
* No hypothesis test is used to claim a difference from another tool; the
  experiment has no control group, and a significance test would invite exactly
  the claim this project does not make.
* The analysis is run once, on the recorded attempts. Any further exploration
  is reported as an exploration and labelled as such.

## 9. Stopping rules

The experiment runs over the whole primary population. It is not stopped early
for a favourable result, and it is not repeated until a favourable result
appears.

## 10. What a negative result means

If the certificate-verified kill rate is low, or if most refusals are
guard-only fixes, that is the finding: the certificate refuses patches that
parse and that a file-level check would accept, and the fix itself is hard.
Both outcomes are publishable, and the pre-registration exists so that
neither can be re-scoped after the fact.

## 11. Deviations

Any departure from this document is recorded here, with the date, the reason,
and whether it was decided before or after the affected numbers were read.

| date | deviation | decided |
|---|---|---|
| 2026-11-11 | The rule "the prompt must not contain the repository name" was narrowed to "the prompt's instructions must not contain it". The vulnerable source of several pairs names its own project (`django`, `keras`), and removing the name would mean editing the code the model is asked to fix. The advisory identifier and the commit hash are still excluded from the whole prompt, and a line of the patched side is still excluded from the whole prompt. The guard compares whole lines after whitespace normalisation, so indentation cannot hide a shared line and a shared line is not mistaken for the fix. | before any attempt was run |
| 2026-11-17 | The second attempt per pair (the robustness check on self-consistency) was not run. The generator was reached through a free-tier agent harness whose daily quota was exhausted partway through the run; all 57 pairs received one attempt, and the second-attempt rate is therefore not reported. | before the analysis was read |
| 2026-11-17 | The generator is identified in the results as model `minimax-m3.1-flash-free`, provider `opencode`, reached through one subagent harness; the recorded date and harness commit are per response. The generator is not a fixed public checkpoint, so the raw responses are published in the frozen archive rather than the repository, and the results file is the repository artefact. | before the analysis was read |
