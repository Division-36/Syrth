# Examples and Use Cases

## Quick Start Examples

### Basic Vulnerability Scanning

```python
# Example 1: Simple file scanning
import subprocess

# Scan a Python file
result = subprocess.run([
    "python", "syrth_scan.py", 
    "--file", "vulnerable_app.py",
    "--mode", "dev"
], capture_output=True, text=True)

print(result.stdout)
```

```python
# Example 2: Using the Python API directly
import joblib
from train_model import SyrthTokenizer, SyrthEncoder
import torch

# Load trained model
bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer()
tokenizer.vocab = bundle["tokenizer_vocab"]

# Reconstruct model
model = SyrthEncoder(**bundle["model_config"])
model.load_state_dict({k: torch.tensor(v) for k, v in bundle["model_state_dict"].items()})
model.eval()

# Scan code
def scan_code(code_snippet):
    # Extract tokens (simplified)
    tokens = extract_tokens_from_code(code_snippet)
    token_ids = tokenizer.encode(tokens)
    
    # Predict
    with torch.no_grad():
        logits = model(torch.tensor([token_ids]))
        probs = torch.softmax(logits, dim=-1)
        pred_class = probs.argmax(dim=-1).item()
        confidence = probs.max().item()
    
    return pred_class, confidence

# Usage
code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

class_id, conf = scan_code(code)
vulnerabilities = ["SQLi", "XSS", "IDOR", "SSRF", "PathTraversal", "OpenRedirect", "BrokenAuth", "RCE"]
print(f"Vulnerability: {vulnerabilities[class_id]} (confidence: {conf:.2f})")
```

## Real-World Use Cases

### 1. CI/CD Pipeline Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'
    
    - name: Install SYRTH
      run: |
        pip install torch numpy scikit-learn joblib
        # Clone SYRTH
        git clone https://github.com/Zierax/Syrth.git
        cd syrth
    
    - name: Train Model (if needed)
      run: |
        cd syrth
        python harvester.py
        python train_model.py
    
    - name: Scan Repository
      run: |
        cd syrth
        # Find all Python files
        find ../ -name "*.py" -type f | while read file; do
          echo "Scanning $file"
          python syrth_scan.py --file "$file" --mode dev >> security_report.txt
        done
    
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: syrth/security_report.txt
```

### 2. Web Service Integration

```python
# flask_service.py
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import tempfile
import os
import joblib
from train_model import SyrthTokenizer, SyrthEncoder
import torch

app = Flask(__name__)

# Load model at startup
model_bundle = joblib.load("syrth_model.joblib")
tokenizer = SyrthTokenizer()
tokenizer.vocab = model_bundle["tokenizer_vocab"]

model = SyrthEncoder(**model_bundle["model_config"])
model.load_state_dict({k: torch.tensor(v) for k, v in model_bundle["model_state_dict"].items()})
model.eval()

VULNERABILITY_NAMES = ["SQLi", "XSS", "IDOR", "SSRF", "PathTraversal", "OpenRedirect", "BrokenAuth", "RCE"]

@app.route('/scan', methods=['POST'])
def scan_code():
    """Scan code for vulnerabilities"""
    try:
        data = request.get_json()
        
        if 'code' in data:
            # Direct code input
            code = data['code']
            tokens = extract_tokens(code)
        elif 'file_content' in data:
            # File content input
            code = data['file_content']
            tokens = extract_tokens(code)
        else:
            return jsonify({'error': 'No code provided'}), 400
        
        # Tokenize and predict
        token_ids = tokenizer.encode(tokens)
        with torch.no_grad():
            logits = model(torch.tensor([token_ids]))
            probs = torch.softmax(logits, dim=-1)
            pred_class = probs.argmax(dim=-1).item()
            confidence = probs.max().item()
        
        # Risk assessment
        risk_level = "HIGH" if confidence > 0.8 else "MEDIUM" if confidence > 0.5 else "LOW"
        
        return jsonify({
            'vulnerability': VULNERABILITY_NAMES[pred_class],
            'class_id': pred_class,
            'confidence': float(confidence),
            'risk_level': risk_level,
            'tokens_found': len(tokens),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/scan_file', methods=['POST'])
def scan_file():
    """Scan uploaded file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.endswith('.py'):
        # Read file content
        code = file.read().decode('utf-8')
        
        # Scan the code
        result = scan_code_content(code)
        
        return jsonify({
            'filename': file.filename,
            **result
        })
    else:
        return jsonify({'error': 'Invalid file type'}), 400

def extract_tokens(code):
    """Simplified token extraction"""
    import re
    
    # Define patterns for different token types
    patterns = {
        'def': r'\bdef\s+(\w+)',
        'arg': r'\b(\w+)\s*[,\)]',
        'sink': r'\b(execute|query|render|open|system|eval|subprocess)\b',
        'check': r'\b(auth|verify|validate|check)\b'
    }
    
    tokens = []
    
    # Extract function definitions
    for match in re.finditer(patterns['def'], code):
        tokens.append(f"def:{match.group(1)}")
    
    # Extract dangerous function calls
    for match in re.finditer(patterns['sink'], code):
        tokens.append(f"sink:{match.group(1)}")
    
    return tokens

def scan_code_content(code):
    """Helper function to scan code content"""
    tokens = extract_tokens(code)
    token_ids = tokenizer.encode(tokens)
    
    with torch.no_grad():
        logits = model(torch.tensor([token_ids]))
        probs = torch.softmax(logits, dim=-1)
        pred_class = probs.argmax(dim=-1).item()
        confidence = probs.max().item()
    
    return {
        'vulnerability': VULNERABILITY_NAMES[pred_class],
        'class_id': pred_class,
        'confidence': float(confidence),
        'tokens': tokens
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### 3. IDE Plugin Integration

```python
# vscode_extension.py (simplified example)
import sublime
import subprocess
import json
import os

class SyrthScanCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        # Get current file content
        content = self.view.substr(sublime.Region(0, self.view.size()))
        file_path = self.view.file_name()
        
        if not file_path or not file_path.endswith('.py'):
            sublime.message_dialog("Please save the file as a .py file first")
            return
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            # Run SYRTH scan
            result = subprocess.run([
                'python', 'syrth_scan.py',
                '--file', temp_path,
                '--mode', 'dev'
            ], capture_output=True, text=True)
            
            # Parse results
            if result.returncode == 0:
                # Show results in new buffer
                results_view = self.view.window().new_file()
                results_view.set_name("SYRTH Results")
                results_view.insert(result.stdout, 0)
                results_view.set_read_only(True)
            else:
                sublime.error_message(f"Scan failed: {result.stderr}")
        
        finally:
            # Clean up
            os.unlink(temp_path)

class SyrthEventListener(sublime_plugin.EventListener):
    def on_post_save(self, view):
        # Auto-scan on save (optional)
        if view.file_name() and view.file_name().endswith('.py'):
            if sublime.load_settings("SYRTH.sublime-settings").get("auto_scan", False):
                view.run_command("syrth_scan")
```

### 4. Batch Repository Analysis

```python
# batch_scan.py
import os
import json
import subprocess
from pathlib import Path
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor

def scan_file(file_path):
    """Scan a single file"""
    try:
        result = subprocess.run([
            'python', 'syrth_scan.py',
            '--file', str(file_path),
            '--mode', 'dev'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # Parse output
            lines = result.stdout.strip().split('\n')
            prediction = None
            confidence = None
            
            for line in lines:
                if 'Prediction:' in line:
                    parts = line.split('Prediction:')[1].strip().split('(')
                    prediction = parts[0].strip()
                    if len(parts) > 1:
                        confidence = float(parts[1].split(')')[0].split(':')[1].strip())
            
            return {
                'file': str(file_path),
                'status': 'success',
                'vulnerability': prediction,
                'confidence': confidence,
                'output': result.stdout
            }
        else:
            return {
                'file': str(file_path),
                'status': 'error',
                'error': result.stderr
            }
    except Exception as e:
        return {
            'file': str(file_path),
            'status': 'error',
            'error': str(e)
        }

def batch_scan_repository(repo_path, output_file='security_report.json'):
    """Scan entire repository"""
    # Find all Python files
    python_files = list(Path(repo_path).rglob('*.py'))
    
    print(f"Found {len(python_files)} Python files to scan")
    
    # Scan files in parallel
    results = []
    with ThreadPoolExecutor(max_workers=mp.cpu_count()) as executor:
        future_to_file = {executor.submit(scan_file, f): f for f in python_files}
        
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                results.append(result)
                print(f"Scanned: {result['file']} - {result['status']}")
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
    
    # Generate summary report
    successful_scans = [r for r in results if r['status'] == 'success']
    error_scans = [r for r in results if r['status'] == 'error']
    
    # Count vulnerabilities
    vuln_counts = {}
    high_risk_files = []
    
    for scan in successful_scans:
        if scan['vulnerability']:
            vuln = scan['vulnerability']
            vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
            
            if scan['confidence'] and scan['confidence'] > 0.8:
                high_risk_files.append(scan['file'])
    
    # Create report
    report = {
        'scan_summary': {
            'total_files': len(python_files),
            'successful_scans': len(successful_scans),
            'error_scans': len(error_scans),
            'vulnerabilities_found': len(vuln_counts),
            'high_risk_files': len(high_risk_files)
        },
        'vulnerability_counts': vuln_counts,
        'high_risk_files': high_risk_files,
        'detailed_results': results
    }
    
    # Save report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nScan completed!")
    print(f"Total files: {report['scan_summary']['total_files']}")
    print(f"Vulnerabilities found: {report['scan_summary']['vulnerabilities_found']}")
    print(f"High-risk files: {report['scan_summary']['high_risk_files']}")
    print(f"Report saved to: {output_file}")
    
    return report

if __name__ == '__main__':
    import sys
    repo_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    batch_scan_repository(repo_path)
```

### 5. Custom Training Pipeline

```python
# custom_training.py
import json
import numpy as np
from sklearn.model_selection import StratifiedKFold
import torch
from train_model import SyrthEncoder, SyrthTokenizer, _load_dataset

class CustomTrainer:
    def __init__(self, dataset_path, custom_config=None):
        self.dataset_path = dataset_path
        self.config = custom_config or {
            'embed_dim': 256,
            'ffn_dim': 1024,
            'dropout': 0.2,
            'batch_size': 64,
            'learning_rate': 5e-3,
            'epochs': 100,
            'k_folds': 5
        }
        
    def load_custom_data(self, custom_data_path):
        """Load custom vulnerability data"""
        with open(custom_data_path, 'r') as f:
            data = json.load(f)
        
        # Expect format: {"samples": [{"tokens": [...], "label": 0, "metadata": {...}}]}
        return data['samples']
    
    def augment_data(self, samples, augmentation_factor=2):
        """Augment training data with variations"""
        augmented = []
        
        for sample in samples:
            # Add original
            augmented.append(sample)
            
            # Add variations
            for i in range(augmentation_factor - 1):
                new_sample = sample.copy()
                # Simple token shuffling for augmentation
                tokens = sample['tokens'][:]
                if len(tokens) > 2:
                    # Swap two random tokens
                    idx1, idx2 = np.random.choice(len(tokens), 2, replace=False)
                    tokens[idx1], tokens[idx2] = tokens[idx2], tokens[idx1]
                
                new_sample['tokens'] = tokens
                new_sample['metadata']['augmented'] = True
                augmented.append(new_sample)
        
        return augmented
    
    def train_with_custom_loss(self, model, train_loader, val_data, device):
        """Train with custom loss function"""
        import torch.nn as nn
        import torch.optim as optim
        
        # Custom loss that weights rare classes more heavily
        class_weights = torch.tensor([1.0, 2.0, 1.5, 2.5, 1.8, 2.2, 1.3, 2.8])
        criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
        optimizer = optim.AdamW(model.parameters(), lr=self.config['learning_rate'])
        
        best_val_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(self.config['epochs']):
            # Training
            model.train()
            train_loss = 0.0
            
            for batch_idx, (data, target) in enumerate(train_loader):
                data, target = data.to(device), target.to(device)
                
                optimizer.zero_grad()
                output = model(data)
                loss = criterion(output, target)
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item()
            
            # Validation
            model.eval()
            val_loss = 0.0
            correct = 0
            total = 0
            
            with torch.no_grad():
                for data, target in val_data:
                    data, target = data.to(device), target.to(device)
                    output = model(data)
                    val_loss += criterion(output, target).item()
                    
                    pred = output.argmax(dim=1, keepdim=True)
                    correct += pred.eq(target.view_as(pred)).sum().item()
                    total += target.size(0)
            
            val_loss /= len(val_data)
            accuracy = 100. * correct / total
            
            print(f'Epoch {epoch}: Train Loss: {train_loss/len(train_loader):.4f}, '
                  f'Val Loss: {val_loss:.4f}, Accuracy: {accuracy:.2f}%')
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                torch.save(model.state_dict(), 'best_custom_model.pth')
            else:
                patience_counter += 1
                if patience_counter >= 20:
                    print("Early stopping triggered")
                    break
        
        return model

# Usage example
if __name__ == '__main__':
    # Initialize custom trainer
    trainer = CustomTrainer('_dataset.json')
    
    # Load and augment data
    samples = trainer.load_custom_data('custom_vulnerabilities.json')
    augmented_samples = trainer.augment_data(samples)
    
    # Train with custom configuration
    # ... (implementation depends on your specific needs)
```

## Performance Examples

### High-Throughput Scanning

```python
# high_performance_scan.py
import asyncio
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import time

class HighPerformanceScanner:
    def __init__(self, model_path="syrth_model.joblib"):
        self.model_bundle = joblib.load(model_path)
        self.tokenizer = SyrthTokenizer()
        self.tokenizer.vocab = self.model_bundle["tokenizer_vocab"]
        self.model = SyrthEncoder(**self.model_bundle["model_config"])
        self.model.eval()
        
        # Pre-load model for faster inference
        self.model.load_state_dict({
            k: torch.tensor(v) for k, v in self.model_bundle["model_state_dict"].items()
        })
    
    async def scan_file_async(self, file_path):
        """Asynchronously scan a file"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
            
            # Quick token extraction
            tokens = self.extract_tokens_fast(content)
            if not tokens:
                return {'file': str(file_path), 'status': 'no_tokens'}
            
            # Fast prediction
            token_ids = self.tokenizer.encode(tokens)
            with torch.no_grad():
                logits = self.model(torch.tensor([token_ids]))
                probs = torch.softmax(logits, dim=-1)
                pred_class = probs.argmax(dim=-1).item()
                confidence = probs.max().item()
            
            return {
                'file': str(file_path),
                'status': 'success',
                'vulnerability': VULNERABILITY_NAMES[pred_class],
                'confidence': float(confidence),
                'tokens_count': len(tokens)
            }
        except Exception as e:
            return {'file': str(file_path), 'status': 'error', 'error': str(e)}
    
    def extract_tokens_fast(self, code):
        """Optimized token extraction"""
        import re
        
        # Pre-compiled regex patterns
        patterns = {
            r'\bdef\s+(\w+)': 'def:',
            r'\b(execute|query|render|open|system|eval|subprocess)\b': 'sink:',
            r'\b(auth|verify|validate|check)\b': 'check:',
            r'\b(id|user_id|file_id|filename|url|command|password|token)\b': 'arg:'
        }
        
        tokens = []
        for pattern, prefix in patterns.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            for match in matches:
                tokens.append(f"{prefix}{match}")
        
        return tokens[:10]  # Limit tokens for speed
    
    async def batch_scan(self, file_paths, max_concurrent=50):
        """Scan multiple files concurrently"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(file_path):
            async with semaphore:
                return await self.scan_file_async(file_path)
        
        tasks = [scan_with_semaphore(fp) for fp in file_paths]
        return await asyncio.gather(*tasks)
    
    def benchmark_performance(self, test_files):
        """Benchmark scanning performance"""
        import time
        
        print(f"Benchmarking with {len(test_files)} files...")
        
        # Warmup
        for _ in range(10):
            self.scan_file_async(test_files[0])
        
        # Benchmark
        start_time = time.time()
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.scan_file_async, f) for f in test_files]
            results = [f.result() for f in futures]
        
        end_time = time.time()
        
        successful = [r for r in results if r['status'] == 'success']
        
        print(f"Performance Results:")
        print(f"  Files scanned: {len(successful)}")
        print(f"  Total time: {end_time - start_time:.2f}s")
        print(f"  Throughput: {len(successful)/(end_time - start_time):.2f} files/s")
        print(f"  Avg time per file: {(end_time - start_time)/len(successful)*1000:.2f}ms")

# Usage
if __name__ == '__main__':
    import glob
    
    scanner = HighPerformanceScanner()
    test_files = glob.glob('path/to/project/**/*.py', recursive=True)[:100]
    
    # Run benchmark
    scanner.benchmark_performance(test_files)
```

## Integration Examples

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy SYRTH files
COPY . .

# Install Python dependencies
RUN pip install torch numpy scikit-learn joblib matplotlib seaborn psutil

# Generate model (optional - can be pre-built)
RUN python harvester.py && python train_model.py

# Expose port for web service
EXPOSE 5000

# Run web service
CMD ["python", "flask_service.py"]
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: syrth-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: syrth-scanner
  template:
    metadata:
      labels:
        app: syrth-scanner
    spec:
      containers:
      - name: syrth-scanner
        image: syrth/scanner:latest
        ports:
        - containerPort: 5000
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        env:
        - name: MODEL_PATH
          value: "/app/models/syrth_model.joblib"
        volumeMounts:
        - name: model-volume
          mountPath: /app/models
      volumes:
      - name: model-volume
        configMap:
          name: syrth-model
---
apiVersion: v1
kind: Service
metadata:
  name: syrth-scanner-service
spec:
  selector:
    app: syrth-scanner
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
  type: LoadBalancer
```

These examples demonstrate how to integrate SYRTH into various workflows and deployment scenarios. Choose the one that best fits your use case and adapt it as needed.
