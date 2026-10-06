# Examples and Use Cases

> ## ⚠ Withdrawn: this document describes the retired v1 pipeline
>
> The figures, dependency lists, API signatures and target tables below refer to
> the v1 implementation, which has been replaced. They are retained for
> provenance and **must not be used as current documentation or quoted as
> results**. The full audit explaining why — including a claim-by-claim table —
> is in [`paper/WITHDRAWN.md`](../../paper/WITHDRAWN.md).
>
> Current documentation:
>
> * [`README.md`](../README.md) — what the tool does and claims today
> * [`architecture.md`](../architecture.md) — the current design and why
> * [`docs/CHANGELOG.md`](../CHANGELOG.md) — what changed, with the withdrawal recorded
>
> The current public API is `syrth.SyrthScanner`, `syrth.scan:main` and
> `syrth.patch`; it takes no PyTorch dependency. Install with
> `pip install -e .` (two dependencies) or `pip install -e ".[ml]"` to add the
> optional learned ranker.


All examples assume the model is trained (`syrth_model.joblib` exists) using
the pipeline in `INDEX.md`. There are **5** vulnerability classes: `SQLi`, `XSS`,
`PathTraversal`, `OpenRedirect`, `RCE`.

## 1. Basic File Scan

```bash
python syrth_scan.py --file vulnerable_app.py --mode dev
```

Output is per-function. A function is **CONFIRMED** only when untrusted input
reaches a dangerous sink:

```
► CONFIRMED: SQLi (95%)  [CWE-89]
  🔴 vuln_sqli (line 9): CONFIRMED → SQLi 95% | sinks=[execute] ✗ no auth
🟡 safe_sqli (line 14): review → SQLi 95% | sinks=[execute] ✗ no auth
```

`safe_sqli` uses a parameterised query, so no `tainted:execute` token exists and
it is reported as review-only rather than a false positive.

## 2. Reading JSON Output (CI / tooling)

```bash
python syrth_scan.py --file app.py --mode dev --json > report.json
```

`report.json` contains a `prediction` block (file-level class, for
compatibility with `RLTESTS/run_tests.py`) and a `findings` array with one
entry per function, including `confirmed` (taint-confirmed flag) and `sinks`.

## 3. Python API

```python
import joblib, torch
from train_model import SyrthTokenizer, SyrthEncoder

bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer(); tokenizer.vocab = bundle["tokenizer_vocab"]
model = SyrthEncoder(**bundle["model_config"])
model.load_state_dict({k: torch.as_tensor(v)
                       for k, v in bundle["model_state_dict"].items()})
model.eval()

NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

def scan(tokens):
    ids = tokenizer.encode(tokens)
    with torch.no_grad():
        probs = torch.softmax(model(torch.tensor([ids])), dim=-1)
    pred = probs.argmax(dim=-1).item()
    return NAMES[pred], probs.max().item()

# String-built SQL -> SQLi
print(scan(["def:get_user", "arg:user_id", "sink:execute", "tainted:execute"]))
# ("SQLi", 0.95)

# Parameterised query -> still classifies the sink but has no taint token
print(scan(["def:get_user", "arg:user_id", "sink:execute"]))
```

> Note: the model assigns a class to whatever sinks are present. The
> **false-positive filter is the taint gate in `syrth_scan.py`** (the
> `tainted:<sink>` token), not the raw classifier. Always read the `confirmed`
> flag, not just `prediction.class`.

## 4. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  syrth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install torch numpy scikit-learn joblib
      - run: |
          python harvester.py
          python _build_5class.py 3000 _full_dataset_5class.json
          python repair_dataset.py --top-k 30000
          python train_final_only.py
      - run: |
          python syrth_scan.py --file . --mode dev --json > syrth.json
          # Fail the build on any CONFIRMED high-confidence finding:
          python - <<'PY'
          import json, sys
          rep = json.load(open("syrth.json"))
          bad = [f for f in rep.get("findings", [])
                 if f.get("confirmed") and f.get("confidence", 0) >= 0.9]
          sys.exit(1 if bad else 0)
          PY
```

## 5. Web Service

```python
# flask_service.py
from flask import Flask, request, jsonify
import joblib, torch
from train_model import SyrthTokenizer, SyrthEncoder

app = Flask(__name__)
bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer(); tokenizer.vocab = bundle["tokenizer_vocab"]
model = SyrthEncoder(**bundle["model_config"])
model.load_state_dict({k: torch.as_tensor(v)
                       for k, v in bundle["model_state_dict"].items()})
model.eval()
NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

@app.post("/scan")
def scan():
    tokens = request.json["tokens"]
    ids = tokenizer.encode(tokens)
    with torch.no_grad():
        probs = torch.softmax(model(torch.tensor([ids])), dim=-1)
    pred = int(probs.argmax(dim=-1).item())
    return jsonify(vulnerability=NAMES[pred], confidence=float(probs.max()))
```

## 6. Batch Repository Scan

Use `syrth_scan.py` per file and aggregate the JSON. For untrusted-input gating,
rely on the per-function `confirmed` flag rather than the file-level class.

```python
import json, subprocess, glob, os

reports = []
for path in glob.glob("repo/**/*.py", recursive=True):
    out = subprocess.run(
        ["python", "syrth_scan.py", "--file", path, "--mode", "dev", "--json"],
        capture_output=True, text=True,
    )
    if out.returncode == 0 and out.stdout.strip():
        reports.append(json.loads(out.stdout))

confirmed = [f for r in reports for f in r.get("findings", []) if f.get("confirmed")]
print(f"{len(confirmed)} confirmed taint flows across {len(reports)} files")
```

## 7. End-to-End Regression Tests

`RLTESTS/` contains one real source file per class plus a runner:

```bash
python RLTESTS/run_tests.py
```

It scans each file and asserts the predicted `prediction.class` matches the
expected vulnerability (currently **6/6**).

## Remaining Gaps

- **All accuracy figures previously quoted for this pipeline are withdrawn** —
  the 86.8% real-code figure and the 70.8% held-out figure among them. See
  [`paper/WITHDRAWN.md`](../../paper/WITHDRAWN.md). No replacement measurement has
  been completed; see the measurement protocol in
  [`architecture.md`](../architecture.md) for how one will be produced.
- Taint propagation is intraprocedural and flow-insensitive within a function, so
  both branches of a conditional are analysed. A guard clause is therefore
  reported as a *partial* mitigation rather than a kill, and reachability is
  over-approximated.
- No path, field or alias sensitivity: a value assigned to an attribute
  propagates to every read of that attribute.
- Class-qualified names are not tracked, so same-named methods in different
  classes are merged.
- The deterministic patch backend declines SQL, because converting a statement to
  a parameterised query cannot be done soundly without deriving placeholders from
  the original literal.
- Cross-language libraries are modelled by name; a library that re-executes a
  string internally is not visible.
