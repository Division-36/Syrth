# Usage

All output shown here was produced by the commands beside it.

## Install

```bash
pip install -e .                 # rules only: tree-sitter + tree-sitter-python
pip install -e ".[ml]"           # adds xgboost, scikit-learn, numpy, joblib
pip install -e ".[dev,benchmark]"
```

Python 3.10 or newer. The default install has **two** dependencies and starts
immediately. The ML components are optional because the report does not depend on
them — a model failure degrades the ranking, never the findings.

Verify:

```bash
python -c "import syrth; print(syrth.__version__)"
python -m pytest tests -q -o addopts=      # 624 passed, 1 skipped
python -m ruff check syrth tests benchmarks
```

## Scan a repository

```console
$ syrth --path src/
========================================================================
SYRTH - Scan Your Risk Trace History
target : (repository)
model  : rule
scanned: 2 file(s), 14 function(s), 3 trace(s)
cross-function flows resolved: 1
========================================================================

[CRITICAL] CWE-94 (EXEC) confidence 0.89
  src/handlers/admin.py:31 in rebuild_cache()
  sink: subprocess.run -> EXEC_COMMAND via pos:0
  origin: REQUEST
  >> L28     call     request.GET.get
     L30     arg      request.GET.get('path')
     L31     sink     subprocess.run
------------------------------------------------------------------------
[LOW] CWE-79 (XSS) confidence 0.40
  src/views/comment.py:12 in render_comment()
  sink: HttpResponse -> XSS_RESPONSE_BODY via none
  origin: none (sanitiser assertion)
  reaches a XSS sink but no external origin was confirmed
------------------------------------------------------------------------
```

Read the two entries as different kinds of statement. The first is a confirmed
flow: untrusted input reaches a command execution sink. The second is a sink
contact with no confirmed flow — the nearest vulnerability class to that
function, reported at low likelihood rather than omitted.

## Scan one file

```bash
syrth --file app.py
syrth --file app.py --json          # machine readable
syrth --file app.py --sarif         # SARIF 2.1.0 for code scanning
syrth --file app.py --traces        # full evidence chains
```

## Read from standard input

```bash
cat app.py | syrth --stdin
syrth --stdin --json < app.py
```

## Filter what you care about

Everything is reported. To triage, filter by likelihood in the JSON:

```bash
# only findings the tool considers likely
syrth --file app.py --json \
  | jq '.findings[] | select(.below_threshold | not)'

# one class only
syrth --file app.py --json | jq '.findings[] | select(.cwe == "CWE-89")'

# the confirmed flows, where a source actually reaches a sink
syrth --file app.py --json | jq '.findings[] | select(.detector != "pattern")'
```

## Exit codes

```bash
syrth --file app.py                       # 0
syrth --file app.py --fail-on any         # 1 when anything is reported
syrth --file app.py --fail-on critical    # 1 only when severity is critical
```

`--fail-on` is for CI. It gates on **severity**, not on likelihood, so a build
fails on a confirmed command-injection flow and not on every pattern risk in the
tree.

## Apply patches

```bash
syrth --file app.py --fix                 # propose and verify, do not write
syrth --file app.py --fix --fix-apply     # write accepted patches
```

A patch is accepted only when all three hold:

1. the targeted flow is gone,
2. no new flow appeared,
3. the file still parses.

Anything else is refused with a reason. SQL is declined outright: turning a
concatenated query into a parameterised one cannot be done soundly without
deriving placeholders from the original literal, so the tool refuses rather than
approximates.

`--fix` writes to your source. Run it on a scratch copy first if the file matters.

## Suppress deliberately

A suppression file:

```bash
syrth --path src/ --suppress .syrthrc
```

```ini
# .syrthrc
[function] migrate_legacy_*
[cwe] CWE-22
[file] tests/*
```

Or inline:

```python
def handler(request):  # syrth: ignore CWE-94 -- argument is validated above
    ...
```

These are the only things that hide output. `--threshold` does not.

## Compare two revisions

```bash
python -m benchmarks.revision_diff --base v1.0 --head v1.1
python -m benchmarks.revision_diff --base main~1 --head main --fail-on-regression
```

Reports what a revision **introduced**, **killed**, left **residual**, or
**changed**. Trace identity excludes line numbers, so moving code down a file is
not reported as a change.

## Train the optional ranker

```bash
python -m syrth.train --dataset data/corpus.jsonl --out models/ranker.joblib
syrth --path src/ --model models/ranker.joblib
```

The model refines the likelihood of a flow the analysis already confirmed. It
cannot create or delete a finding. A model whose schema or label space does not
match the running package is refused rather than loaded.

## Measure the tool

```bash
python -m benchmarks.risk_metrics --dataset data/cve_pairs.jsonl
python -m benchmarks.rltests
```

See [benchmark.md](benchmark.md) for what the numbers mean.