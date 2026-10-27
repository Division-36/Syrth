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

## Unreleased

Nothing yet.
