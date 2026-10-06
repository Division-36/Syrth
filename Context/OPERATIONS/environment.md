# Environment — SYRTH

## Verified runtime

`[FACT]` Observed 2026-10-02:

| Item | Value |
|---|---|
| OS | Windows (win32), PowerShell 5.1 |
| Python | 3.11.15 |
| Package requires | `>=3.10` (`pyproject.toml`) |
| Build backend | `setuptools>=68.0` + `wheel` |
| Ruff target | `py310` |
| pytest | 7.4+ |

`[FACT]` No C compiler (`cc`/`gcc` absent) — this is why one test skips.

`[FACT]` No LaTeX toolchain was confirmed; `paper/main.tex` was structurally
checked (balanced braces, no dangling labels) but **not compiled**.

## Third-party packages

`[FACT]` Runtime (required): `tree-sitter>=0.23,<0.27`,
`tree-sitter-python>=0.23`.

`[FACT]` Extras: `ml` (xgboost, scikit-learn, numpy, joblib), `explain` (shap),
`dev` (pytest, pytest-cov, ruff), `benchmark` (same as `ml`), `all`.

`[FACT]` `mypy` is referenced by `make typecheck` but is **not** declared in any
dependency group.

## External services and network

`[FACT]` The scanner requires **no network**.

`[FACT]` Network is required only for corpus generation:
- `api.osv.dev/v1/query` — vulnerability metadata, advisory CWE, fix commit SHAs.
- git remotes over HTTPS for the harvested repositories.

`[ENVIRONMENT-SPECIFIC]` Verified reachable from this machine:
- `api.osv.dev` → HTTP 200
- `api.github.com` → HTTP 200, **rate limit 60 requests/hour unauthenticated**
- `pypi.org` → HTTP 200

`[NOTE]` No `GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_PAT` is present in the
environment. The corpus builder was designed to avoid the GitHub API limit by
using `git clone` and local `git show`, so the limit does not currently block it.

## Disk footprint

`[FACT]` Largest generated artefacts on disk:

| Path | Size |
|---|---|
| `syrth_codebert/model.safetensors` | ~476 MB |
| `syrth_ensemble.joblib`, `syrth_ensemble_v1_backup.joblib` | ~24 MB each |
| `syrth_model.joblib` | ~6 MB |
| `syrth_engine.so` | ~6.6 MB |
| `syrth_engine.h` | ~22 MB |
| `_full_dataset*.json` and siblings | several MB each |
| `paper/main.pdf` | ~367 KB |

`[FACT]` Clone cache under `experiments/scratch/repos/` holds ten repositories
and is gitignored.

## Environment variables

`[FACT]` `GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_PAT` — referenced by name only;
none currently set. Only needed if a workflow requires the GitHub API.

`[FACT]` `PYTHONIOENCODING=utf-8` was set in the shell for many commands because
the console default codepage mangles the box-drawing characters in `RLTESTS/`
markers. Not a project requirement.

## Constraints

- No CI environment exists, so results depend on the local machine.
- Benchmark wall time scales with corpus size; 498 records took ~3 minutes.
- Windows path and archive behaviour differs from POSIX. `revision_diff` was
  verified on Windows; it no longer shells out to `tar`.