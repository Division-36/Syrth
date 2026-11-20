## Unreleased

### Changed

- `benchmarks/verify_published` now fails when a published file points at a
  missing path, and `make verify-published` re-derives the two patch-verification
  measurements from their recorded responses (the field was stale since the
  rename).
- `benchmarks/tool_capability_study` records a warning when an instrument
  lacks capability or measurement data, and records zero-denominator rates
  explicitly rather than reporting them as if measured.
- All measurement files and harnesses now carry explicit names. The patch
  verification study is `benchmarks/patch_verification.py` publishing
  `data/patch_verification.json`; its direct comparison against the real fix is
  `benchmarks/patch_author_comparison.py` publishing
  `data/patch_author_comparison.json`; the whole-repository tool comparison is
  `benchmarks/tool_comparison.py` publishing `data/tool_comparison.json`; and
  the second paper lives in `paper-verification/`.
  Prompts and responses are `data/patch_prompts.jsonl` and
  `data/patch_responses.jsonl`. The Makefile targets are `tool-comparison`,
  `tool-capability` and `patch-verification`.

### Added

- `benchmarks/tool_capability_study.py` publishes `data/tool_capability.json`,
  one matched capability profile across the snippet and whole-tree layers. It
  states the instrument's strengths as absolute counts on the same population:
  exact dangerous calls 199/217 against the next best 73/217, vulnerability
  classes 111/116 against 23/116, advisory functions 14/24 against 4/24, and
  patch verification decisions 57 against none. These are coverage and
  verifiability results, not an accuracy or detection-quality claim.
- Two direct, like-for-like comparisons requested for the second paper.
  `benchmarks/patch_author_comparison.py` judges the real developer patch of each of the
  57 confirmed pairs with the same contract used for the model-authored patches:
  machine 31/57 verified kills and 21/57 guard-only, developer 7/57 verified
  kills and 44/57 guard-only. The guard-only difference is not a quality score;
  real fixes more often add a containment guard, which leaves the certificate
  standing by design.
- A direct tool comparison on the same 24 repositories at the labelled file
  and function: SYRTH 23/24 file and 14/24 function, Bandit 17/24 and 3/24,
  Semgrep 11/24 and 2/24, Ruff 17/24 and 4/24. The denominator is 24 for every
  arm. Both comparisons are in the second paper and in
  [benchmark.md](benchmark.md).
- Five tests that keep both arms of the direct comparison under one contract.

## v1.1 — 2026-11-18

**The measurement evidence release.** This release adds the four patch and
identity studies, the whole-repository replay, and the two registered
experiments of the second paper. The analyser change behind them is a
breadth-first parent tree per entry point for interprocedural composition,
which preserves the reported chains while removing one graph walk per emitted
certificate.

The numbers are published under `data/` and every one of them is re-derivable
with `make verify-published`. See [benchmark.md](benchmark.md) for the results
and their denominators, and `docs/experiments/` for the two pre-registered
experiments.

### Added

- The first experiment of the second paper: certificate-verified patch verification
  on the 57 pairs with a confirmed flow. A model sees only the vulnerable
  source and the certificate; the certificate judges the answer. 31 of 57
  answers are verified kills, 21 are guard-only fixes the certificate refuses
  although they parse, and 6 introduce a new flow. The method is registered
  in `docs/experiments/patch-verification-preregistration.md` before the first attempt,
  the results in `docs/experiments/patch-verification-results.md`, and the numbers
  in `data/patch_verification.json`.
- `benchmarks/patch_verification.py` prepares the prompts (refusing any that carry the
  patched side, the advisory or the commit), collects the recorded answers,
  and verifies each one by re-scanning it and comparing certificates. An
  automated test covers the leakage guard.
- The second experiment of the second paper, registered in
  `docs/experiments/tool-comparison-preregistration.md`: the four instruments run
  on whole worktrees of 24 repositories, one fix commit each. The comparison
  is co-location with certificates at file and function level, not precision
  or recall. `benchmarks/tool_comparison.py` checkpoints after each repository
  and resumes from the JSON file.
- `benchmarks/tool_comparison.py` derives the enclosing function for external
  tools' findings from the source at their reported line, because Bandit,
  Semgrep and Ruff report a file and a line but not a function name.

### Changed

- `benchmarks/verify_published.py` also checks the patch-verification study's
  published results.
- `make tool-comparison` runs the whole-tree comparison.
- The documentation was restructured for a first-time reader: `docs/README.md`
  now opens with a reading guide, a one-paragraph description and a table of
  every headline number with a link to its detail; `docs/benchmark.md` has a
  reading guide at the top. Stale figures were corrected in place -- the sample
  run showed a 76% kill rate after the published rate had become 89%, and one
  sentence described Bandit as ahead on CWE-502 while the table beside it showed
  SYRTH ahead 15/15 to 14/15. `docs/limitations.md` now states the limits of the
  two new experiments and replaces the "performance unmeasured" claim with the
  whole-repository cost actually observed.

## v1.1-measurement — 2026-11-10 (pre-release, superseded by v1.1)

The measurement evidence release: the four patch and identity studies, the
whole-repository replay, and the analyser fix that made the replay possible.

### Added

- `benchmarks/identity.py` measures the stability of the certificate key under
  renaming: parameters-only 296/312, functions-only 217/332, all 233/350, with
  origins preserved in 304/312 and 304/350.
- `benchmarks/ablation.py` disables one analysis decision at a time and
  re-measures on the same records. Coverage (111/116) and determinism (350/350)
  do not move in any variant; the kill rate falls from 89/100 to 81/102 without
  argument schemas and to 39/47 when only name-recognised parameters are seeded
  as sources. Cross-function traces are 116 with the call graph and 0 without.
- `benchmarks/patch_study.py` diffs the real patched counterpart of every corpus
  record by certificate identity: 175 pairs, 54 tracing the labelled class,
  partitioned into 46 persisting, 7 removed and 1 traded.
- `benchmarks/whole_repo_study.py` replays both revisions of all 88 fix commits
  over full working trees in 24 repositories: 175/175 pairs examined, the
  labelled class traced in 57 pairs (50 persist, 6 removed, 1 traded), and
  cross-function certificates to the same sink counted separately (23 pairs,
  4,275 certificates, 4,268 keeping the same identity).
- `tools/freeze_corpus.py` produces a byte-reproducible archive of the 350
  corpus records with a manifest and a checksum file, so a result can be pinned
  by a hash without publishing third-party source.
- `benchmarks/verify_published.py` re-derives every published measurement with
  the command the documentation prints and compares it with the published
  file, field by field. `make verify-published` is the gate; CI checks the
  published files' completeness and internal invariants, because CI does not
  generate the corpus.

### Changed

- Interprocedural certificates are now composed with one breadth-first parent
  tree per entry point instead of one graph walk per certificate. The reported
  chains are unchanged; a salt revision drops from about 3,400 s to 301 s.
- The chain search is cycle-safe breadth-first rather than an unbounded
  depth-first walk, so mutual recursion can no longer exhaust the stack.
- An argument carrying an external origin is credited to the caller that
  supplies it rather than to a placeholder name that is not in the summary
  table, and a caller with no tainted parameter of its own is no longer skipped.
- `syrth.parser.python.parameter_is_source` is a single documented seam that
  lets the ablation harness disable the position-seeded source rule without
  editing the analyser. Nothing in the product overrides it.
- The documentation quotes 680 tests, states that skips are
  environment-dependent, and adds a whole-repository section to
  [benchmark.md](benchmark.md).
- The paper sources are excluded from the tree: the manuscript is a separate
  artefact with its own history and submission state.
- The v1 classifier-era harness now says so in its own output. Its metrics
  were withdrawn and are not published; the banner points at
  `benchmarks.risk_metrics`, which produces the measurements this project does
  publish.

### Known limitations

- Extracting a function into a snippet loses context. Measured against the
  whole-repository replay, the snippet study traces 54 pairs and the
  repository study 57, and the two disagree on one outcome: a full module
  exposes flows and bindings that the extracted function does not carry.
- Certificate identity is name-based, so a flow is matched to a function by
  name. In a large repository a common method name is defined many times
  (`start` is defined 172 times in salt at one revision), which is why the
  whole-repository study pins cross-function matches to the labelled file as
  well as the labelled name.

## v1-prod — 2026-10-27

**First production release of the rewritten public history.** The analyser is
functionally the same as the withdrawn 1.0.1; what changed is what the repository
publishes.

### Removed

- Internal working material is gone from the repository and from its history:
  project-state notes, agent-facing instructions, personal working preferences,
  raw prompt transcripts, and machine-specific paths.
- The unpublished paper and its source are gone from the tree and from history.
  The withdrawal record survives as [withdrawn-v1.md](withdrawn-v1.md), rewritten
  so that it does not depend on files the repository no longer holds.
- The retired v1 pipeline, its benchmark artefacts and its plots are gone from
  history. They advertised accuracy figures that the audit withdrew.
- Superseded v1 documentation is gone. It repeated those figures behind a
  withdrawal banner, which kept the claims in circulation without keeping the
  evidence.
- `docs/measurements.md` is gone. It published precision and recall from the
  classifier era, and this project publishes no precision or recall figure.

### Changed

- Commit metadata in the reviewed history is normalised to a neutral address
  (`syrth@division-36.local`); the author's public address
  (`ziad salah <zs.01117875692@gmail.com>`) appears on later commits, since the
  study is published under the author's own name.
- `README.md`, `docs/README.md`, `docs/limitations.md` and `docs/CONTRIBUTING.md`
  now quote the current measurements and the current CI matrix. Several of them
  had drifted to the pre-rewrite numbers.
- The version is single-sourced at 1.0.0+prod across `pyproject.toml`,
  `syrth/__init__.py` and `syrth/scan.py`.

### Withdrawn

- Releases 1.0.0 and 1.0.1 are withdrawn. Their artefacts described a tree that
  is no longer published, and `v1-prod` replaces them. No code change requires a
  migration: the CLI, the Python API and the rule set are unchanged.

