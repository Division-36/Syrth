# Installation Guide

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **Memory**: 2GB RAM (4GB recommended)
- **Storage**: 500MB free space
- **OS**: Linux, macOS, or Windows (WSL2)

### Recommended Requirements
- **Python**: 3.10 or higher
- **Memory**: 8GB RAM
- **Storage**: 2GB free space
- **GPU**: CUDA-compatible (optional, for training acceleration)
- **Compiler**: GCC 7+ or Clang 8+ (for C engine)

## Installation Methods

### Method 1: Direct Download

1. **Download the project**
   ```bash
   # Clone the repository
   git clone https://github.com/Zierax/Syrth.git
   cd syrth
   
   # Or download and extract
   wget https://github.com/Zierax/Syrth/archive/main.zip
   unzip main.zip
   cd syrth-main
   ```

2. **Install Python dependencies**
   ```bash
   # Using pip (recommended)
   pip install torch numpy scikit-learn joblib matplotlib seaborn psutil
   
   # Using conda
   conda install pytorch numpy scikit-learn joblib matplotlib seaborn psutil
   ```

3. **Verify installation**
   ```bash
   python --version  # Should be 3.8+
   python -c "import torch; print('PyTorch:', torch.__version__)"
   python -c "import sklearn; print('Scikit-learn:', sklearn.__version__)"
   ```

### Method 2: Using pip (if packaged)

```bash
# Install from PyPI (when available)
pip install syrth

# Or install from source
pip install git+https://github.com/Zierax/Syrth.git
```

### Method 3: Docker Installation

1. **Pull the Docker image**
   ```bash
   docker pull syrth/syrth:latest
   ```

2. **Run the container**
   ```bash
   docker run -it --rm -v $(pwd):/workspace syrth/syrth:latest bash
   ```

3. **Or use Docker Compose**
   ```yaml
   # docker-compose.yml
   version: '3.8'
   services:
     syrth:
       image: syrth/syrth:latest
       volumes:
         - ./:/workspace
       working_dir: /workspace
   ```

## Platform-Specific Setup

### Linux (Ubuntu/Debian)

```bash
# Update package manager
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install system dependencies
sudo apt install build-essential gcc g++ make

# Install GCC for C engine (if not installed)
sudo apt install gcc

# Optional: CUDA support
# Visit https://pytorch.org/get-started/locally/ for CUDA installation
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.10

# Install GCC
brew install gcc

# Set up environment
echo 'export PATH="/usr/local/opt/python@3.10/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Windows (WSL2)

1. **Enable WSL2**
   ```powershell
   # In PowerShell as Administrator
   wsl --install
   ```

2. **Set up Ubuntu**
   ```bash
   # After WSL installation
   sudo apt update
   sudo apt install python3 python3-pip build-essential
   ```

3. **Install Windows Terminal** (recommended)
   ```powershell
   # From Microsoft Store
   winget install Microsoft.WindowsTerminal
   ```

### Windows (Native)

1. **Install Python**
   - Download from https://python.org
   - Add to PATH during installation

2. **Install Microsoft C++ Build Tools**
   - Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Select "C++ build tools"

3. **Install Git** (if not installed)
   ```powershell
   winget install Git.Git
   ```

## Virtual Environment Setup

### Using venv

```bash
# Create virtual environment
python -m venv syrth-env

# Activate
# Linux/macOS:
source syrth-env/bin/activate
# Windows:
syrth-env\Scripts\activate

# Install dependencies
pip install torch numpy scikit-learn joblib matplotlib seaborn psutil
```

### Using conda

```bash
# Create conda environment
conda create -n syrth python=3.10

# Activate
conda activate syrth

# Install dependencies
conda install pytorch numpy scikit-learn joblib matplotlib seaborn psutil
```

## Verification

### Test Installation

```bash
# 1. Test Python imports
python -c "
import torch
import numpy as np
import sklearn
import joblib
import matplotlib
import seaborn as sns
import psutil
print('✅ All dependencies installed successfully')
"

# 2. Test basic functionality
python -c "
import sys
sys.path.insert(0, '.')
from train_model import SyrthEncoder, SyrthTokenizer
print('✅ SYRTH modules import successfully')
"

# 3. Test C compilation (optional)
echo '#include <stdio.h>
int main() { printf(\"Hello C\"); return 0; }' > test.c
gcc -o test test.c
./test
rm test test.c
echo '✅ C compiler working'
```

### Quick Start Test

```bash
# 1. Harvest OSV PyPI data + synthetic samples
python harvester.py

# 2. Build a balanced 5-class dataset
python _build_5class.py 3000 _full_dataset_5class.json

# 3. Re-tokenise (leak-free) and split train/test
python repair_dataset.py --top-k 30000

# 4. Train (Python + C engine export)
python train_final_only.py

# 5. Test scanning on a tainted snippet
echo "def get_user(user_id):
    return db.execute('SELECT * FROM users WHERE id = ' + user_id)" > test.py
python syrth_scan.py --file test.py --mode dev

# 6. Run the latency/memory benchmark
python benchmark.py
```

## Common Installation Issues

### Issue: "No module named 'torch'"

**Solution:**
```bash
# Install PyTorch specifically
pip install torch torchvision torchaudio

# Or with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### Issue: "gcc: command not found"

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install build-essential gcc

# macOS
brew install gcc

# Windows
# Install Microsoft C++ Build Tools
```

### Issue: "CUDA out of memory"

**Solution:**
```bash
# Use CPU instead
export CUDA_VISIBLE_DEVICES=""

# Or reduce batch size in train_model.py
DEFAULT_BATCH_SIZE = 16
```

### Issue: "Permission denied" on Linux

**Solution:**
```bash
# Use user installation
pip install --user torch numpy scikit-learn joblib matplotlib seaborn psutil

# Or fix permissions
sudo chown -R $USER:$USER ~/.local
```

### Issue: "DLL load failed" on Windows

**Solution:**
```powershell
# Install Microsoft Visual C++ Redistributable
# Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe

# Or use conda which handles DLLs automatically
conda install pytorch numpy scikit-learn
```

## Performance Optimization

### GPU Setup (Optional)

```bash
# Check CUDA availability
python -c "import torch; print('CUDA available:', torch.cuda.is_available())"

# Install CUDA version of PyTorch
# Visit https://pytorch.org/get-started/locally/ for specific commands
```

### Memory Optimization

```bash
# For systems with limited RAM
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1

# In train_model.py, reduce batch size
DEFAULT_BATCH_SIZE = 16
DEFAULT_EMBED_DIM = 128
DEFAULT_FFN_DIM = 512
```

### Compilation Optimization

```bash
# For maximum C engine performance
export CFLAGS="-O3 -march=native -flto"

# Test compilation flags
gcc $CFLAGS test.c -o test
```

## Development Setup

### For Contributing

```bash
# 1. Fork and clone repository
git clone https://github.com/your-username/syrth.git
cd syrth

# 2. Create development environment
python -m venv dev-env
source dev-env/bin/activate  # Linux/macOS
# dev-env\Scripts\activate  # Windows

# 3. Install dependencies
pip install torch numpy scikit-learn joblib

# 4. Train a model so scans work
python harvester.py
python _build_5class.py 3000 _full_dataset_5class.json
python repair_dataset.py --top-k 30000
python train_final_only.py

# 5. Run validation
python eval_heldout.py
python _eval_code.py
python check_agree.py
python RLTESTS/run_tests.py
```

SYRTH has no `setup.py`/`pyproject.toml` yet, so it is run from the repo root
(outside the venv, activate it first). Regression coverage lives in `RLTESTS/`
and the accuracy scripts; add a `pytest` suite when extending detection.

### IDE Configuration

#### VS Code

1. Install extensions:
   - Python
   - Pylance
   - Python Docstring Generator

2. Configure settings.json:
```json
{
    "python.defaultInterpreterPath": "./syrth-env/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black"
}
```

#### PyCharm

1. Open project directory
2. Configure Python interpreter
3. Enable code inspection
4. Set up run configurations

## Next Steps

After successful installation:

1. **Build Dataset**: `python _build_5class.py 3000 _full_dataset_5class.json`
2. **Repair / Split**: `python repair_dataset.py --top-k 30000`
3. **Train Model**: `python train_final_only.py`
4. **Scan Code**: `python syrth_scan.py --file your_app.py --mode dev`
5. **Benchmark**: `python benchmark.py`

For detailed usage, see:
- [README.md](README.md) - General overview
- [API.md](API.md) - API reference
- [EXAMPLES.md](EXAMPLES.md) - Code examples
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup
