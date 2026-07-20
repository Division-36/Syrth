# API Reference

## Core Classes

### SyrthEncoder

The neural network model for vulnerability classification. It is a mean-pooled
embedding + MLP classifier (no recurrence), which is why it is fast and
exportable to a dependency-free C header.

```python
class SyrthEncoder(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 256,
        ffn_dim: int = 1024,
        num_classes: int = 5,
        dropout: float = 0.2,
    )
```

**Parameters:**
- `vocab_size`: Size of the token vocabulary (~32k after repair).
- `embed_dim`: Embedding dimension (default: 256).
- `ffn_dim`: Feed-forward network size (default: 1024).
- `num_classes`: Number of vulnerability classes — **5** (SQLi, XSS,
  PathTraversal, OpenRedirect, RCE).
- `dropout`: Dropout rate (default: 0.2).

**Methods:**
```python
def forward(self, x: torch.Tensor) -> torch.Tensor:
    """Return raw logits for a padded batch of token-id sequences."""

def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
    """Return softmax class probabilities."""
```

### SyrthTokenizer

Maps token strings to integer IDs using the vocabulary embedded in the model
bundle.

```python
class SyrthTokenizer:
    def __init__(self):
        self.vocab: Dict[str, int] = {}
        self._next_id = 1

    def fit(self, token_lists: List[List[str]]) -> None: ...
    def encode(self, tokens: List[str]) -> List[int]: ...
    def vocab_size(self) -> int: ...
```

## Command Line Tools

### harvester.py

Collects training data.

```bash
python harvester.py
```

- Downloads the OSV PyPI bulk feed (all packages — ~16,940 usable records).
- Generates synthetic code-only samples aligned with the scanning vocabulary.
- Writes `_full_dataset_5class.json` via `_build_5class.py` in the pipeline.

### _build_5class.py

Balances the raw OSV + synthetic data into 5 classes (cap per class = first
positional arg).

```bash
python _build_5class.py 3000 _full_dataset_5class.json
```

### repair_dataset.py

Re-tokenises records into leak-free feature tokens (the label / `cwe:` is
excluded from features) and splits into train/test with zero overlap.

```bash
python repair_dataset.py --top-k 30000
```

**Outputs:** `_balanced_dataset.json` (train), `testingMassiveDataset.json`
(test). Accepts token prefixes `def`, `arg`, `sink`, `flow`, `tainted`,
`<...>` source markers, and ordinary identifier tokens.

### train_final_only.py

Trains `SyrthEncoder` and exports both engines.

```bash
python train_final_only.py
```

**Outputs:** `syrth_model.joblib` (Python bundle), `syrth_engine.h` (C header).
The C engine is compiled to `syrth_engine.so` on first scan.

### syrth_scan.py

Scanning interface. Classifies each function independently and applies the
taint gate.

```bash
python syrth_scan.py --file app.py --mode dev
```

**Options:**
- `--file`: Python file to scan.
- `--mode`: `dev` (Python engine) or `prod` (compiled C engine).
- `--top-k`: max functions to show (default 20).

**Human-readable output** marks each function:

```
► CONFIRMED: SQLi (95%)  [CWE-89]
  🔴 vuln_sqli (line 9): CONFIRMED → SQLi 95% | sinks=[execute] ✗ no auth
🟡 safe_sqli  (line 14): review → SQLi 95% | sinks=[execute] ✗ no auth
```

Only functions carrying a `tainted:<sink>` token are **CONFIRMED**; the rest are
review-only.

**JSON output** (one object per file) includes `prediction` (file-level class
for compatibility with `RLTESTS/`), `findings` (per-function), and
`confirmed_flow` entries:

```json
{
  "file": "app.py",
  "prediction": { "class": "SQLi", "class_id": 0, "confidence": 0.95,
                  "risk": "HIGH" },
  "findings": [
    { "function": "vuln_sqli", "line": 9, "confirmed": true,
      "predicted_class": "SQLi", "confidence": 0.95, "sinks": ["execute"],
      "auth": false }
  ]
}
```

### eval_heldout.py / check_agree.py / _eval_code.py

- `eval_heldout.py` — accuracy on the held-out advisory-text test set (976
  records). Currently **70.8%** (code-only features).
- `check_agree.py` — compiles the C engine and compares dev vs prod predictions;
  **100%** agreement expected.
- `_eval_code.py` — scans 719 real CVE code blocks through the pipeline and
  reports per-class accuracy on scanned code (currently **86.8%**).

### benchmark.py

Measures Python vs C engine latency, throughput, and memory; writes charts to
`benchmark/`.

```bash
python benchmark.py
```

## Data Formats

### Token Format

Tokens follow `type:identifier`, plus source/sink markers produced by
`collect.py`:

- `def:name` — function definition
- `arg:name` — function parameter
- `sink:name` — dangerous call (execute, render, open, redirect, subprocess,
  eval, os.system, ...)
- `flow:src->sink` — a data-flow edge between a variable and a sink
- `tainted:<sink>` — a *confirmed* taint edge (untrusted input reaches the sink)
- `<REQUEST_INPUT>`, `<FILE_PATH>`, `<URL_PARAM>`, `<CMD>`, `<SQL>`, ... —
  normalised untrusted-source markers

Example for `db.execute("SELECT ..." + user_id)`:
```
def:get_user arg:user_id sink:execute flow:user_id->execute tainted:execute
```

### Dataset Format

```json
{
  "records": [
    {
      "tokens": ["def:get_user", "arg:user_id", "sink:execute", "tainted:execute"],
      "label": 0,
      "source": "osv|synthetic"
    }
  ]
}
```

### Model Bundle Format (`syrth_model.joblib`)

```json
{
  "syrth_version": "0.9.0",
  "model_state_dict": { "embedding.weight": [[...]], "head.0.weight": [[...]] },
  "model_config": { "vocab_size": 32275, "embed_dim": 256, "ffn_dim": 1024,
                    "num_classes": 5 },
  "tokenizer_vocab": { "def:get_user": 1, "tainted:execute": 2, "...": 3 },
  "metrics": { "heldout_accuracy": 0.942 }
}
```

`model_state_dict` values are stored as NumPy arrays; load with
`{k: torch.as_tensor(v) for k, v in bundle["model_state_dict"].items()}`.

## C Integration

`syrth_engine.h` exposes:
```c
const char* syrth_predict(const char** tokens, int num_tokens,
                          int* out_class, float* out_confidence);
```
Include it and link the compiled `syrth_engine.so` (or embed the arrays
statically). Output class indices match `cwe_names =
["SQLi","XSS","PathTraversal","OpenRedirect","RCE"]`.

## Error Codes

| Code | Meaning | Fix |
|------|---------|-----|
| 1 | Model not found | Run `train_final_only.py` to produce `syrth_model.joblib` |
| 2 | Invalid mode | Use `dev` or `prod` |
| 3 | No tokens extracted | File has no analyzable functions |
| 4 | C engine not found | Re-run training to regenerate `syrth_engine.h`; it is compiled on first scan |
| 10 | Dataset not found | Run `harvester.py` + `_build_5class.py` + `repair_dataset.py` |

## Python Usage

```python
import joblib, torch
from train_model import SyrthTokenizer, SyrthEncoder

bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer(); tokenizer.vocab = bundle["tokenizer_vocab"]
model = SyrthEncoder(**bundle["model_config"])
model.load_state_dict({k: torch.as_tensor(v)
                       for k, v in bundle["model_state_dict"].items()})
model.eval()

tokens = ["def:get_user", "arg:user_id", "sink:execute", "tainted:execute"]
ids = tokenizer.encode(tokens)
with torch.no_grad():
    probs = torch.softmax(model(torch.tensor([ids])), dim=-1)
    pred = probs.argmax(dim=-1).item()
    conf = probs.max().item()

names = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]
print(names[pred], f"{conf:.2f}")
```
