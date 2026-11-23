# Corpus v1.1 frame (pre-registered)

Date: 2026-11-23. Written before the expansion produced any records.

v1.1 is the frozen v1 corpus **plus** this expansion. It is not a replacement
for v1, and it is not a new version of the analyser: the package list, the
registry and the tool version are unchanged. The version number marks the
release of the corpus, because v1 is frozen and cannot be edited.

## Why the frame had to widen

The v1 corpus (2026-10-04) asked GHSA about a hand-written list of 192 PyPI
distributions. That list was chosen for security relevance, but it capped the
corpus at 59 candidate repositories, and the later failed pilot could add only
eight new vulnerable groups. Doubling `--max-repos` could not help: there were
no more repositories to select. The frame, not the harvest parameters, was the
limit.

## Frame source

`experiments/scratch/osv/pypi-all.zip`, downloaded from
`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` on
2026-11-22.

- sha256: `88f6042e2648caaa8a961ca8b4a79bae7a9aa5797064e1814b9279e516624db6`
- 27,069 OSV PyPI entries
- 2,199 entries carry at least one in-scope CWE
- 1,320 of those carry at least one GitHub commit reference
- 526 distinct GitHub repositories own those commits

The dump is the whole PyPI ecosystem rather than a package list, so the frame is
a property of the data: **every OSV PyPI advisory with an in-scope CWE and a
GitHub fix commit**. No package was added or removed after seeing a yield.

## Inclusion rule

An advisory enters the frame when:

1. its CWE set intersects the registry's class set
   (`CWE-22/79/89/94/327/434/502/601/611/798/918`);
2. at least one reference is a GitHub commit URL;
3. a PyPI package name is present; and
4. the commit URL names a GitHub repository.

The repository is the `owner/name` in the first commit reference. It is not
looked up through PyPI metadata, so a renamed distribution cannot change
attribution.

## Sampling rule

1. Count in-scope advisories per repository.
2. Keep repositories with **at least 3** advisories (117 repositories).
3. Drop repositories whose full clone exceeds **900 MB** (10 repositories;
   recorded in the manifest, not silently omitted).
4. Rank the remainder by `advisories / sqrt(clone MB)` and take the top N.

The pilot uses **N = 30**. If the gate below is not met, N increases to 60 and
then 100 **within the same ordered frame**. No repository outside the ordering
is added, and no threshold is changed after seeing a yield.

Clone sizes come from the GitHub API and are cached in
`experiments/scratch/repo-sizes.json`; the selected names are recorded in the
cached manifest. The size cache was local to the harvest host, so a reader can
reconstruct the selection from the manifest only if they re-fetch sizes.

## Extraction rule

- Inspect **all** fix commits for each advisory, newest first, stopping at the
  first commit that yields an accepted record. The v1 builders inspected only
  the first commit; three v1 groups were lost when GHSA added a newer follow-up
  commit ahead of the vulnerable one.
- Accept a function only if the pre-fix revision contains a sink for the
  labelled class and the post-fix revision differs (unchanged from v1).
- Deduplicate on `(repo, commit, file, function, cwe)`, and on function content
  within `(repo, file, function, cwe)`.
- Attribute advisories only to repositories in the selected frame. The cache may
  contain clones from earlier runs; they do not join the corpus unless selected.

## Gate

The expansion passes when, against the frozen v1 corpus:

- at least **150 new pairs**, where a pair is new when its provenance key
  `(repo, commit, file, qualname, cwe)` is absent from v1; and
- at least **40 repositories** contribute records.

New pairs are counted against v1, not against the failed pilot: that run is
kept only as a diagnostic artefact.

## Result (2026-11-23)

The gate passes on both clauses.

| Quantity | Count |
|---|---|
| New pairs against v1 | **197** (threshold 150) |
| Repositories contributing records | **43** (threshold 40) |
| Groups in the merged corpus | 155 |
| Records / pairs in the merged corpus | 738 / 369 |
| New groups against v1 | 75 |
| New repositories against v1 | 19 |

The merged class counts are CWE-22 193, CWE-79 74, CWE-89 41, CWE-94 18,
CWE-502 15, CWE-601 14, CWE-918 12, CWE-327 1, CWE-611 1. Evidence tiers are
184 direct-sink and 185 module-proximity.

Two harvests produced the expansion. The 30-repository pilot inspected 389 fix
commits, considered 1,005 candidates, rejected 439 for a missing sink and 2,232
for an unchanged function, and accepted 240 pairs from 23 repositories. The
cached pass inspected 479 commits, considered 1,139 candidates, rejected 488 and
2,500, and accepted 305 pairs from 30 repositories; only `langchain` hit the
420-second repository budget. The pilot contributed 10 pairs the cached pass did
not have (`datamodel-code-generator` 5, `roundup` 3, `notebook` 1,
`openapi-python-client` 1).

The cached pass is the broader of the two: it selected 38 repositories from the
115 frame repositories above the floor that were already cloned, and 30 of them
contributed records. That is why the repository clause passes with margin even
though the pilot alone contributed only 23 repositories.

## Deviations from this registration

Four deviations are recorded, all before the paper was updated.

1. **A cached-only pass replaced part of the density ranking.** GitHub
   throughput from this host fell to about 165 KB/s with 1.6--2.2 s RTT and 25%
   packet loss; `nltk` alone needed roughly 35 minutes for a 365 MB clone. The
   cached pass therefore selected from the same frame by advisory count among
   repositories already present in the clone cache, because clone size is
   irrelevant when nothing is downloaded. 77 frame repositories were not cached
   and are recorded as excluded; 411 repositories were below the advisory floor.
   The pilot's density ordering is unchanged. The pilot manifest records the 23
   repositories that contributed records, not the full selected list of 30.

2. **The expansion is additive.** 69 of v1's 175 pairs are absent from both
   harvests (concentrated in `apache-airflow` 15, `django` 12, `sqlalchemy` 12,
   `pillow` 4), a consequence of repository selection and commit choice as well
   as the advisory floor. Publishing the new harvest as a replacement would
   therefore have shrunk the corpus while appearing to expand it. The released
   corpus is the union of the frozen v1 corpus and the expansion, deduplicated,
   and the gate counts pairs that v1 does not contain. v1 itself is unchanged at
   `data/corpus.jsonl`.

3. **Three v1 pairs were duplicate backports and were collapsed.** One Apache
   Airflow advisory (`GHSA-ggwr-4vr8-g7wv`) has two fix commits with an
   identical pre-fix body for `DAG.run`, `DAG.create_dagrun` and
   `DagModel.__init__`. The v1 builder deduplicated within one commit but not
   across commits. The merge keeps one of each, so v1.1 contains 172 of v1's 175
   pairs. The three removed pairs were untraced in the whole-worktree replay and
   none belongs to the 57 flows of the verification study, so no published
   population changes.

4. **One released pair follows the pre-fix repository matching.** The pilot
   selected `openapi-python-client` when its advisories were attributed by
   name across two owners. The `_github_slug` fix later split that name into two
   owners with fewer than three advisories each. The selection was fixed before
   the fix and is not re-run, so the retained pair is disclosed here rather than
   silently removed; the gate still passes without it.

The pre-fix count in the frame section above is 117 repositories; the cached run
reports 115 after the advisory-to-repository matching was aligned with
attribution. The two-repository difference is the fix described in
`_github_slug`, not a change to the inclusion rule.

## What is not claimed

This is a power sample, not a prevalence sample. Selecting repositories with at
least three advisories over-represents projects that accumulate advisories; the
corpus says nothing about how common such projects are. The unit of analysis
remains the labelled function pair.
