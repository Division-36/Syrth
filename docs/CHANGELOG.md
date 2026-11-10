# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are named by channel rather than by a bare version number. The tag and
the release title are `v1-prod`; the packaged version is `1.0.0+prod`, because
PEP 440 can only carry `prod` as a local version segment, after a `+`.

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

- Commit metadata is normalised: no personal email address is published in the
  history.
- `README.md`, `docs/README.md`, `docs/limitations.md` and `docs/CONTRIBUTING.md`
  now quote the current measurements and the current CI matrix. Several of them
  had drifted to the pre-rewrite numbers.
- The version is single-sourced at 1.0.0+prod across `pyproject.toml`,
  `syrth/__init__.py` and `syrth/scan.py`.

### Withdrawn

- Releases 1.0.0 and 1.0.1 are withdrawn. Their artefacts described a tree that
  is no longer published, and `v1-prod` replaces them. No code change requires a
  migration: the CLI, the Python API and the rule set are unchanged.

## v1.1-measurement — 2026-11-10

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
- The documentation quotes 641 tests, states that skips are
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

