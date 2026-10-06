# API

The public surface. Everything not listed here is internal and may change.

## Package exports

```python
import syrth

syrth.__version__          # "3.0.0"
syrth.SyrthScanner         # main entry
syrth.diff_sources         # revision comparison
syrth.patch_status         # classify a patch's effect
```

## `SyrthScanner`

```python
SyrthScanner(
    model_path: str | None = None,
    threshold: float = 0.5,
    interprocedural: bool = True,
)
```

| Argument | Meaning |
|---|---|
| `model_path` | optional XGBoost bundle; a bad bundle degrades ranking, never findings |
| `threshold` | marks findings below this as `below_threshold`. Never removes them |
| `interprocedural` | resolve cross-function flows |

Attributes: `has_ml`, `model_label`, `model_error` (`None` unless a bundle failed
to load).

### `scan_source(source, path="")` → `ScanReport`

Analyse a string. The fastest path, and what the benchmarks use.

### `scan_file(path)` → `ScanReport`

Analyse one file. Errors are recorded in `report.errors`, not raised.

### `scan_paths(target)` → `ScanReport`

Analyse a directory or repository. `*.py` only; `build`, `.git`, `venv`,
`__pycache__` and similar are pruned.

### `scan_source_pair(before, after)` → `DiffReport`

Analyse two revisions of the same file and report what changed.

### `suppress(report, suppressions)` → `ScanReport`

Move findings matching the suppression set into `report.suppressed`.

## `ScanReport`

```python
@dataclass
class ScanReport:
    file: str
    findings: list[Finding]              # ranked, everything reported
    suppressed: list[Finding]            # removed by an explicit suppression
    traces: list[Trace]                  # every trace, including suppressed
    cross_function: list[CrossFunctionTrace]
    files_scanned: int
    functions_scanned: int
    parse_errors: list[str]
    errors: list[tuple[str, str]]
    model: str

    def summary(self) -> dict             # counts by CWE and severity
    def to_dict(self) -> dict             # JSON-ready
```

## `Finding`

```python
@dataclass
class Finding:
    function: str
    lineno: int
    cwe: str                             # "CWE-94"
    category: str                        # "EXEC"
    confidence: float                    # likelihood in [0, 1]
    detector: str                        # "taint" | "pattern"
    severity: str                        # critical|high|medium|low|info
    origins: tuple[str, ...]
    sink: str                            # canonical, e.g. "EXEC_COMMAND"
    sink_call: str                       # as written, e.g. "subprocess.run"
    sink_arg: str
    steps: tuple[TraceStep, ...]
    kills: tuple[str, ...]               # sanitisers seen
    reasons: tuple[str, ...]
    file: str
    trace_id: str
    model: str
    below_threshold: bool
```

`detector` is the field to branch on:

```python
confirmed = [f for f in report.findings if f.detector != "pattern"]
touching  = [f for f in report.findings if f.detector == "pattern"]
```

## Example: triage

```python
from syrth import SyrthScanner

report = SyrthScanner().scan_file("app.py")

for finding in report.findings:
    if finding.detector == "pattern":
        continue                      # a sink contact, no flow
    print(f"{finding.severity:<9} {finding.cwe:<9} {finding.function}() "
          f"{finding.confidence:.2f}")
    for reason in finding.reasons:
        print(f"          {reason}")

if report.parse_errors:
    print("could not fully parse:", report.parse_errors)
```

## Example: revision diff

```python
from syrth import SyrthScanner, diff_sources

scanner = SyrthScanner()
before = open("v1.py", encoding="utf-8").read()
after  = open("v2.py", encoding="utf-8").read()

diff = diff_sources(scanner, before, after, "app.py")

diff.introduced    # flows the revision added
diff.killed        # flows it removed
diff.changed       # flows whose shape changed
diff.residual      # flows present in both
```

Trace identity excludes line numbers, so moving code is not a change.

## Example: verify a patch

```python
from syrth import SyrthScanner, diff_sources, patch_status

scanner = SyrthScanner()
diff = diff_sources(scanner, before, after, "app.py")

ok, reasons = patch_status(diff, expected_kills=("CWE-94",))
```

`patch_status` returns `(accepted, reasons)`. A patch is only accepted when the
targeted flow is gone, no new flow appeared, and the file still parses.

## Optional: the learned ranker

```python
from syrth.classifier import XGBoostClassifier

classifier = XGBoostClassifier(model_path="models/ranker.joblib")
bundle = classifier.save("models/ranker.joblib")   # records schema + labels
classifier.explain(features)                       # SHAP, if installed
```

A bundle is refused if its label space or either schema version disagrees with
the running package. Silent mismatches would produce confidently wrong rankings.