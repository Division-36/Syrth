# API Reference

## Core Classes

### SyrthEncoder

The main neural network model for vulnerability classification.

```python
class SyrthEncoder(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 256,
        ffn_dim: int = 1024,
        num_classes: int = 8,
        dropout: float = 0.2
    )
```

**Parameters:**
- `vocab_size`: Size of token vocabulary
- `embed_dim`: Embedding dimension (default: 256)
- `ffn_dim`: Feed-forward network size (default: 1024)
- `num_classes`: Number of vulnerability classes (default: 8)
- `dropout`: Dropout rate for regularization (default: 0.2)

**Methods:**

```python
def forward(self, x: torch.Tensor) -> torch.Tensor:
    """Forward pass through the model."""
    
def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
    """Return class probabilities."""
```

### SyrthTokenizer

Handles tokenization of Python source code.

```python
class SyrthTokenizer:
    def __init__(self):
        self.vocab = {}
        self._next_id = 1
```

**Methods:**

```python
def fit(self, token_lists: List[List[str]]) -> None:
    """Build vocabulary from token lists."""
    
def encode(self, tokens: List[str]) -> List[int]:
    """Convert tokens to integer IDs."""
    
def vocab_size(self) -> int:
    """Return vocabulary size."""
```

## Command Line Tools

### harvester.py

Data collection and dataset generation.

```bash
python harvester.py [options]
```

**Options:**
- `--output`: Output dataset path (default: `_dataset.json`)
- `--synthetic-only`: Use only synthetic data
- `--no-osv`: Skip OSV data collection
- `--no-gh`: Skip GitHub advisory collection

**Output:**
```json
{
  "records": [
    {
      "tokens": ["def:get_user", "arg:user_input", "sink:execute"],
      "label": 0,
      "source": "synthetic|osv|github"
    }
  ]
}
```

### train_model.py

Model training and export.

```bash
python train_model.py [options]
```

**Options:**
- `--dataset`: Dataset path (default: `_dataset.json`)
- `--no-export-joblib`: Skip joblib export
- `--no-export-c`: Skip C header export
- `--joblib-path`: Joblib output path
- `--c-path`: C header output path

**Outputs:**
- `syrth_model.joblib`: Trained model bundle
- `syrth_engine.h`: C header for production

### syrth_scan.py

Vulnerability scanning interface.

```bash
python syrth_scan.py [options]
```

**Options:**
- `--file`: Python file to scan
- `--mode`: `dev` (Python) or `prod` (C engine)
- `--threshold`: Minimum confidence threshold (0-1)

**Input Formats:**
1. File scanning: `python syrth_scan.py --file app.py`
2. Piped input: `cat app.py | python collect.py | python syrth_scan.py --mode dev`

**Output:**
```
[SYRTH] File: app.py
[SYRTH] Tokens: 15
[SYRTH] Prediction: SQLi (confidence: 0.92)
[SYRTH] Risk: HIGH
[SYRTH] Recommendation: Validate user input
```

### benchmark.py

Performance evaluation tool.

```bash
python benchmark.py [options]
```

**Options:**
- `--runs`: Number of benchmark iterations (default: 500)
- `--test-ratio`: Test split ratio (default: 0.2)
- `--no-charts`: Skip chart generation

**Outputs:**
- `benchmark/results.json`: Raw benchmark data
- `benchmark/metrics.json`: Processed metrics
- `benchmark/summary.txt`: Human-readable report
- `benchmark/*.png`: Performance charts

## Configuration

### Environment Variables

```bash
export SYRTH_MODEL_PATH="/path/to/syrth_model.joblib"
export SYRTH_C_HEADER="/path/to/syrth_engine.h"
export SYRTH_DATASET="/path/to/_dataset.json"
```

### Model Configuration

```python
# In train_model.py
CONFIG = {
    "embed_dim": 256,
    "ffn_dim": 1024,
    "dropout": 0.2,
    "batch_size": 64,
    "learning_rate": 5e-3,
    "epochs": 100,
    "k_folds": 7
}
```

### Benchmark Configuration

```python
# In benchmark.py
BENCHMARK_CONFIG = {
    "warmup_runs": 10,
    "benchmark_runs": 500,
    "test_split_ratio": 0.2,
    "random_seed": 42
}
```

## Data Formats

### Token Format

Tokens follow the pattern: `type:identifier`

**Types:**
- `def`: Function definitions
- `arg`: Function arguments
- `sink`: Dangerous function calls
- `query`: Database queries
- `data`: Data flow indicators
- `flow`: Control flow
- `check`: Security checks
- `context`: Execution context

**Examples:**
```python
tokens = [
    "def:get_user",           # Function definition
    "arg:user_id",           # Function parameter
    "check:auth_required",   # Security check
    "sink:db.execute",       # Database query
    "query:SELECT * FROM users WHERE id = ?",  # SQL query
    "data:user_record"        # Data flow
]
```

### Dataset Format

```json
{
  "records": [
    {
      "tokens": ["def:get_user", "arg:user_input", "sink:execute"],
      "label": 0,
      "source": "synthetic",
      "metadata": {
        "cwe": "CWE-89",
        "severity": "HIGH",
        "file": "example.py"
      }
    }
  ]
}
```

### Model Bundle Format

```json
{
  "syrth_version": "1.0.0",
  "model_state_dict": {
    "embedding.weight": [[...], [...]],
    "head.0.weight": [[...], [...]]
  },
  "model_config": {
    "vocab_size": 343,
    "embed_dim": 256,
    "ffn_dim": 1024,
    "num_classes": 8
  },
  "tokenizer_vocab": {
    "def:get_user": 1,
    "arg:user_input": 2,
    ...
  },
  "metrics": {
    "cv_accuracy_mean": 0.825,
    "ensemble_accuracy": 1.0
  }
}
```

## Error Codes

### Scanner Errors

| Code | Description | Solution |
|------|-------------|-----------|
| 1 | Model not found | Train model first with `train_model.py` |
| 2 | Invalid mode | Use `dev` or `prod` |
| 3 | No tokens extracted | Check file contains analyzable functions |
| 4 | C engine not found | Generate C header with training |

### Training Errors

| Code | Description | Solution |
|------|-------------|-----------|
| 10 | Dataset not found | Run `harvester.py` to generate dataset |
| 11 | Empty dataset | Check data sources and connectivity |
| 12 | Insufficient memory | Reduce batch size or use CPU |
| 13 | CUDA out of memory | Use CPU or reduce model size |

### Benchmark Errors

| Code | Description | Solution |
|------|-------------|-----------|
| 20 | C compilation failed | Install GCC and required flags |
| 21 | Insufficient test samples | Generate larger dataset |
| 22 | Chart generation failed | Install matplotlib/seaborn |

## Performance Metrics

### Latency Metrics

- **Mean**: Average inference time
- **Median**: 50th percentile
- **P95**: 95th percentile
- **P99**: 99th percentile
- **Std Dev**: Standard deviation
- **CV**: Coefficient of variation

### Accuracy Metrics

- **Overall accuracy**: Correct predictions / total predictions
- **Per-class accuracy**: Accuracy per vulnerability type
- **F1 score**: Harmonic mean of precision and recall
- **Confusion matrix**: Class prediction matrix

### Resource Metrics

- **Peak RAM**: Maximum memory usage
- **Average RAM**: Mean memory usage
- **CPU usage**: Processor utilization
- **Throughput**: Predictions per second

## Integration Examples

### Python Integration

```python
import joblib
from train_model import SyrthTokenizer, SyrthEncoder

# Load model
bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer()
tokenizer.vocab = bundle["tokenizer_vocab"]

# Reconstruct model
model = SyrthEncoder(**bundle["model_config"])
model.load_state_dict({k: torch.tensor(v) for k, v in bundle["model_state_dict"].items()})
model.eval()

# Predict
tokens = ["def:get_user", "arg:user_input", "sink:execute"]
ids = tokenizer.encode(tokens)
with torch.no_grad():
    logits = model(torch.tensor([ids]))
    prediction = logits.argmax(dim=-1).item()
    confidence = torch.softmax(logits, dim=-1).max().item()
```

### C Integration

```c
#include "syrth_engine.h"

int main() {
    const char* tokens[] = {"def:get_user", "arg:user_input", "sink:execute"};
    int num_tokens = 3;
    int class;
    float confidence;
    
    const char* result = syrth_predict(tokens, num_tokens, &class, &confidence);
    
    printf("Vulnerability: %s (confidence: %.2f)\n", result, confidence);
    return 0;
}
```

### Web Service Integration

```python
from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)
model = joblib.load("syrth_model.joblib")

@app.route("/scan", methods=["POST"])
def scan_code():
    code = request.json["code"]
    tokens = extract_tokens(code)  # Your token extraction
    
    # Predict
    prediction = predict_vulnerability(tokens)
    
    return jsonify({
        "vulnerability": prediction["class"],
        "confidence": prediction["confidence"],
        "risk_level": "HIGH" if prediction["confidence"] > 0.8 else "MEDIUM"
    })
```

## Troubleshooting Guide

### Performance Issues

1. **Slow Python inference**
   - Check GPU availability
   - Increase batch size for batch processing
   - Consider using C engine for production

2. **Memory errors**
   - Reduce model size parameters
   - Use CPU instead of GPU
   - Process in smaller batches

3. **Poor accuracy**
   - Ensure balanced dataset
   - Increase training epochs
   - Try ensemble voting

### Data Issues

1. **Empty tokens**
   - Verify code has analyzable functions
   - Check sink registry coverage
   - Validate token extraction logic

2. **Imbalanced classes**
   - Use dataset balancing in harvester
   - Apply class weights during training
   - Generate more synthetic samples

### Deployment Issues

1. **C compilation failures**
   - Install build-essential tools
   - Check GCC version compatibility
   - Use fallback compilation flags

2. **Model loading errors**
   - Verify model file integrity
   - Check version compatibility
   - Re-export if necessary
