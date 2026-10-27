# Configuration

## Command-line flags

### Input

| Flag | Default | Effect |
|---|---|---|
| `--path PATH` | — | scan a directory or repository |
| `--file PATH` | — | scan one file |
| `--stdin` | off | read source from standard input |
| `--suppress PATH` | — | load a suppression file |

Exactly one of `--path`, `--file` or `--stdin` is required.

### Output

| Flag | Effect |
|---|---|
| `--json` | machine-readable report on stdout |
| `--sarif` | SARIF 2.1.0 with code flows |
| `--traces` | include full evidence chains |
| `--fail-on LEVEL` | exit 1 when a finding at or above LEVEL exists; levels: `any`, `critical`, `high`, `medium`, `low` |
| `--min-likelihood N` | mark findings below N with `below_threshold`; never deletes them |

`--fail-on` gates on **severity**, not likelihood, so CI does not fail on every
pattern risk in the tree.

### Patching

| Flag | Effect |
|---|---|
| `--fix` | propose and verify patches; does not write |
| `--fix-apply` | write patches that passed verification |

`--fix-apply` mutates source files. The patch is accepted only when the targeted
flow is gone, no new flow appeared, and the file still parses.

### Model

| Flag | Effect |
|---|---|
| `--model PATH` | load an XGBoost bundle to refine likelihoods |

The model refines the ranking of flows the analysis already confirmed. It cannot
create or delete a finding. A bundle whose label space or schema versions do not
match the running package is refused with a reason.

## Suppression file

INI-like, loaded with `--suppress`:

```ini
# .syrthrc
[function] migrate_legacy_*
[cwe] CWE-22
[file] tests/*
[module] legacy/*
```

| Section | Matches against | Example |
|---|---|---|
| `[function]` | function name (glob) | `migrate_legacy_*` |
| `[cwe]` | CWE identifier | `CWE-22` |
| `[file]` | file path (glob) | `tests/*` |
| `[module]` | module path (glob) | `legacy/*` |

Suppressed findings are not deleted from the run. They appear in
`report.suppressed` and in the JSON `suppressed` array, so you can audit what was
hidden and why.

## Inline suppression

```python
def handler(request):  # syrth: ignore CWE-94 -- argument is validated above
    subprocess.run(request.GET['c'], shell=True)
```

```python
def legacy(request):  # syrth: ignore
    open(request.GET['f'])
```

`# syrth: ignore` with no class suppresses every finding in that function.

## Environment

| Variable | Purpose |
|---|---|
| `PYTHONIOENCODING` | set to `utf-8` on Windows consoles; the box-drawing characters in `RLTESTS/` markers mangle otherwise |
| `GITHUB_TOKEN` | only if you regenerate the benchmark corpus; not needed by the analyser |

The analyser requires **no network access** and no environment variables.

## Files

| Path | Role |
|---|---|
| `pyproject.toml` | package metadata, dependencies, extras, ruff and pytest config |
| `.syrthrc` | suppression file (name is yours to choose) |
| `data/` | generated corpora; gitignored, not shipped |
| `models/` | trained bundles; gitignored, not shipped |

## Making the tool stricter or quieter

It cannot be made stricter — it never withheld anything. It can be made quieter
for triage:

```bash
# show only confirmed flows
syrth --path src/ --json | jq '.findings[] | select(.detector != "pattern")'

# show only likelihood above a bar
syrth --path src/ --json | jq --argjson m 0.5 '[.findings[] | select(.confidence >= $m)]'

# gate CI on severity only
syrth --path src/ --fail-on high
```