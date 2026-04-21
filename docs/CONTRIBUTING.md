# Contributing to SYRTH

Thank you for your interest in contributing to SYRTH! This guide will help you get started with contributing to the project.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of machine learning and cybersecurity
- Familiarity with Python development

### Development Setup

1. **Fork the Repository**
   ```bash
   # Fork the repository on GitHub
   # Then clone your fork
   git clone https://github.com/your-username/syrth.git
   cd syrth
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python -m venv dev-env
   
   # Activate
   # Linux/macOS:
   source dev-env/bin/activate
   # Windows:
   dev-env\Scripts\activate
   
   # Install in development mode
   pip install -e .
   
   # Install development dependencies
   pip install pytest black flake8 mypy pre-commit
   ```

3. **Set Up Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

4. **Verify Setup**
   ```bash
   # Run tests
   pytest tests/
   
   # Check code formatting
   black --check *.py
   
   # Lint code
   flake8 *.py
   ```

## Project Structure

```
syrth/
├── docs/                   # Documentation
├── tests/                  # Test suite
├── examples/               # Example code
├── harvester.py            # Data collection
├── collect.py              # Tokenization
├── train_model.py          # Model training
├── syrth_scan.py          # Scanning interface
├── benchmark.py            # Performance evaluation
└── README.md              # Project overview
```

## Contributing Guidelines

### Code Style

We use the following tools to maintain code quality:

- **Black**: For code formatting
- **Flake8**: For linting
- **MyPy**: For type checking
- **isort**: For import sorting

```bash
# Format code
black *.py

# Sort imports
isort *.py

# Lint code
flake8 *.py

# Type check
mypy *.py
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scan): add support for Django template scanning
fix(train): resolve memory leak in k-fold validation
docs(api): update API documentation for new endpoints
```

### Pull Request Process

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write code following the style guidelines
   - Add tests for new functionality
   - Update documentation if needed

3. **Run Tests**
   ```bash
   # Run all tests
   pytest tests/ -v
   
   # Run specific test
   pytest tests/test_scan.py::TestScanner::test_sql_injection -v
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   
   Then create a pull request on GitHub with:
   - Clear title and description
   - Reference any related issues
   - Include screenshots if applicable

## Areas for Contribution

### 1. Model Improvements

**Current Challenges:**
- Improving accuracy on real-world code
- Better handling of obfuscated vulnerabilities
- Reducing false positives

**How to Contribute:**
- Experiment with different architectures
- Add new features to the model
- Improve tokenization strategies
- Test on diverse datasets

**Example Contribution:**
```python
# In train_model.py
class ImprovedSyrthEncoder(SyrthEncoder):
    """Enhanced model with attention mechanism"""
    
    def __init__(self, vocab_size, embed_dim=256, ffn_dim=1024, num_classes=8, dropout=0.2):
        super().__init__(vocab_size, embed_dim, ffn_dim, num_classes, dropout)
        
        # Add attention layer
        self.attention = nn.MultiheadAttention(embed_dim, num_heads=8)
        self.norm = nn.LayerNorm(embed_dim)
    
    def forward(self, x):
        # Original embedding
        x = self.embedding(x)
        x = self.dropout(x)
        
        # Add attention
        attn_out, _ = self.attention(x, x, x)
        x = self.norm(x + attn_out)
        
        # Continue with original forward pass
        padding_mask = x == 0
        embeds = x
        mask_float = (~padding_mask).float().unsqueeze(-1)
        pooled = (embeds * mask_float).sum(dim=1) / mask_float.sum(dim=1).clamp(min=1.0)
        pooled = self.dropout(pooled)
        return self.head(pooled)
```

### 2. Tokenization Enhancements

**Current Limitations:**
- Limited to predefined patterns
- May miss context-specific vulnerabilities
- Language-specific patterns

**Contribution Ideas:**
- Add AST-based tokenization
- Support for more Python frameworks
- Dynamic pattern learning
- Multi-language support

**Example Contribution:**
```python
# In collect.py
import ast

class ASTTokenizer(SyrthTokenizer):
    """Enhanced tokenizer using AST analysis"""
    
    def extract_from_ast(self, code):
        """Extract security-relevant tokens from AST"""
        tree = ast.parse(code)
        tokens = []
        
        for node in ast.walk(tree):
            # Analyze function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if self.is_dangerous_function(func_name):
                        tokens.append(f"sink:{func_name}")
                
                # Analyze arguments
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if self.is_user_input(arg.id):
                            tokens.append(f"arg:{arg.id}")
        
        return tokens
    
    def is_dangerous_function(self, func_name):
        """Check if function is potentially dangerous"""
        dangerous_funcs = {
            'execute', 'query', 'render', 'open', 'system',
            'eval', 'subprocess', 'os.system', 'pickle.loads'
        }
        return func_name in dangerous_funcs
    
    def is_user_input(self, var_name):
        """Check if variable likely contains user input"""
        user_input_patterns = ['user', 'input', 'data', 'request', 'form']
        return any(pattern in var_name.lower() for pattern in user_input_patterns)
```

### 3. Data Sources

**Current Sources:**
- Synthetic templates
- OSV database
- GitHub Advisory Database

**Contribution Ideas:**
- Add more vulnerability databases
- Improve synthetic data generation
- Add real-world vulnerability samples
- Create benchmark datasets

**Example Contribution:**
```python
# In harvester.py
def fetch_cve_database(self):
    """Fetch vulnerability data from CVE database"""
    import requests
    from datetime import datetime, timedelta
    
    # Fetch recent CVEs
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        'startDate': start_date.strftime('%Y-%m-%d'),
        'endDate': end_date.strftime('%Y-%m-%d'),
        'keyword': 'python'
    }
    
    try:
        response = requests.get(url, params=params)
        data = response.json()
        
        records = []
        for cve_item in data.get('result', {}).get('CVE_Items', []):
            if self.is_python_related(cve_item):
                record = self.cve_to_record(cve_item)
                records.append(record)
        
        return records
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []
```

### 4. Performance Optimizations

**Current Bottlenecks:**
- Tokenization speed
- Model inference time
- Memory usage

**Contribution Ideas:**
- Implement caching
- Optimize data structures
- Use vectorized operations
- Improve C engine performance

**Example Contribution:**
```python
# In syrth_scan.py
import functools
import hashlib

class CachedTokenizer(SyrthTokenizer):
    """Tokenizer with caching for improved performance"""
    
    def __init__(self):
        super().__init__()
        self._token_cache = {}
        self._cache_size_limit = 10000
    
    @functools.lru_cache(maxsize=5000)
    def encode_cached(self, tokens_tuple):
        """Cached version of encode"""
        tokens = list(tokens_tuple)
        return super().encode(tokens)
    
    def encode(self, tokens):
        """Encode with caching"""
        # Convert to tuple for hashing
        tokens_tuple = tuple(tokens)
        
        # Check cache
        if tokens_tuple in self._token_cache:
            return self._token_cache[tokens_tuple]
        
        # Encode and cache
        result = self.encode_cached(tokens_tuple)
        
        # Manage cache size
        if len(self._token_cache) < self._cache_size_limit:
            self._token_cache[tokens_tuple] = result
        
        return result
```

### 5. New Vulnerability Types

**Current Types:**
- SQLi, XSS, IDOR, SSRF, PathTraversal, OpenRedirect, BrokenAuth, RCE

**Contribution Ideas:**
- Add new vulnerability classes
- Improve detection accuracy for existing types
- Add framework-specific vulnerabilities
- Support for custom vulnerability patterns

**Example Contribution:**
```python
# Add new vulnerability type
NEW_VULNERABILITY_TYPES = {
    8: "CryptoWeakness",      # Weak cryptography
    9: "InfoDisclosure",      # Information disclosure
    10: "RaceCondition",      # Race conditions
    11: "XXE",               # XML External Entity
}

# Update CWE mapping
CWE_LABELS.update({
    "CWE-327": 8,  # Use of Broken or Risky Cryptographic Algorithm
    "CWE-200": 9,  # Information Exposure
    "CWE-362": 10, # Race Condition
    "CWE-611": 11, # XML External Entity (XXE) Injection
})

# Add synthetic templates
_NEW_TEMPLATES = [
    # Crypto weakness
    (["def:encrypt", "arg:data", "sink:MD5", "hash:weak"], 8, "CryptoWeakness"),
    (["def:generate_token", "sink:random", "seed:timestamp"], 8, "CryptoWeakness"),
    
    # Information disclosure
    (["def:debug", "sink:print", "data:sensitive"], 9, "InfoDisclosure"),
    (["arg:error_msg", "sink:response", "data:stack_trace"], 9, "InfoDisclosure"),
    
    # Race condition
    (["def:transfer", "arg:amount", "check:balance_after"], 10, "RaceCondition"),
    (["def:update", "arg:data", "sync:none"], 10, "RaceCondition"),
    
    # XXE
    (["def:parse_xml", "arg:xml_data", "sink:xml.etree"], 11, "XXE"),
    (["arg:xml_input", "sink:lxml", "resolve:external"], 11, "XXE"),
]
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_train_model.py -v

# Run specific test
pytest tests/test_train_model.py::TestModel::test_forward_pass -v
```

### Writing Tests

**Test Structure:**
```python
# tests/test_scan.py
import pytest
from unittest.mock import patch, MagicMock
import torch
from syrth_scan import _dev_predict
from train_model import SyrthTokenizer, SyrthEncoder

class TestScanner:
    def setup_method(self):
        """Setup for each test"""
        self.sample_tokens = ["def:get_user", "arg:user_input", "sink:execute"]
        
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        # Mock model bundle
        mock_bundle = {
            "tokenizer_vocab": {"def:get_user": 1, "arg:user_input": 2, "sink:execute": 3},
            "model_config": {
                "vocab_size": 4,
                "embed_dim": 64,
                "ffn_dim": 128,
                "num_classes": 8
            },
            "model_state_dict": {
                "embedding.weight": torch.zeros(4, 64),
                # ... other model weights
            }
        }
        
        with patch('joblib.load', return_value=mock_bundle):
            result = _dev_predict(self.sample_tokens, mock_bundle)
            
        assert result is not None
        assert 'prediction' in result
        assert 'confidence' in result
    
    def test_empty_tokens(self):
        """Test handling of empty tokens"""
        result = _dev_predict([], MagicMock())
        
        assert result is not None
        assert 'error' in result
    
    @pytest.mark.parametrize("tokens,expected_class", [
        (["def:get_user", "arg:user_input", "sink:execute"], 0),  # SQLi
        (["def:render", "arg:user_input", "sink:innerHTML"], 1),  # XSS
        (["def:download", "arg:file_id", "sink:send_file"], 2),  # IDOR
    ])
    def test_vulnerability_classification(self, tokens, expected_class):
        """Test different vulnerability classifications"""
        # Mock model to return specific class
        mock_model = MagicMock()
        mock_model.return_value = torch.zeros(1, 8)
        mock_model.return_value[0][expected_class] = 5.0  # High confidence
        
        with patch('train_model.SyrthEncoder', return_value=mock_model):
            result = _dev_predict(tokens, MagicMock())
            
        assert result['prediction'] == expected_class
```

### Performance Tests

```python
# tests/test_performance.py
import time
import pytest
from syrth_scan import _dev_predict

class TestPerformance:
    def test_scan_performance(self):
        """Test scanning performance meets requirements"""
        tokens = ["def:get_user", "arg:user_input", "sink:execute"] * 10
        
        # Measure time
        start_time = time.time()
        for _ in range(100):
            _dev_predict(tokens, self.get_mock_bundle())
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 100
        
        # Should be less than 10ms per scan
        assert avg_time < 0.01, f"Scan too slow: {avg_time:.3f}s"
    
    def test_memory_usage(self):
        """Test memory usage is reasonable"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Perform many scans
        for _ in range(1000):
            _dev_predict(self.get_mock_bundle())
        
        final_memory = process.memory_info().rss
        memory_increase = (final_memory - initial_memory) / 1024 / 1024  # MB
        
        # Should not increase by more than 100MB
        assert memory_increase < 100, f"Memory leak detected: {memory_increase:.1f}MB"
```

## Documentation

### Improving Documentation

1. **Code Documentation**
   - Add docstrings to all functions and classes
   - Use Google-style docstrings
   - Include type hints

2. **README Updates**
   - Update installation instructions
   - Add new features to overview
   - Update examples

3. **API Documentation**
   - Document new functions
   - Update parameter descriptions
   - Add usage examples

### Example Documentation

```python
def extract_tokens(code: str, framework: str = "generic") -> List[str]:
    """Extract security-relevant tokens from Python code.
    
    Args:
        code: Python source code to analyze
        framework: Framework-specific patterns to use (django, flask, generic)
    
    Returns:
        List of tokens in format 'type:identifier'
        
    Raises:
        ValueError: If code is not valid Python syntax
        
    Example:
        >>> code = "def get_user(id): return db.execute('SELECT * FROM users WHERE id = ' + id)"
        >>> tokens = extract_tokens(code)
        >>> print(tokens)
        ['def:get_user', 'arg:id', 'sink:execute']
    """
    pass
```

## Release Process

### Version Management

We use semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Code Quality**
   - [ ] All tests pass
   - [ ] Code coverage > 80%
   - [ ] Documentation updated
   - [ ] Changelog updated

2. **Performance**
   - [ ] Benchmark runs successfully
   - [ ] No performance regressions
   - [ ] Memory usage acceptable

3. **Compatibility**
   - [ ] Python 3.8+ support
   - [ ] Backward compatibility maintained
   - [ ] Breaking changes documented

### Creating a Release

```bash
# Update version number
vim __init__.py  # Update __version__

# Update changelog
vim CHANGELOG.md

# Create release tag
git tag -a v1.2.0 -m "Release version 1.2.0"
git push origin v1.2.0

# Create GitHub release
# Go to GitHub and create release from tag
```

## Community

### Getting Help

- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Email**: security@syrth.dev (for security-related issues)

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and considerate
- Use inclusive language
- Focus on constructive feedback
- Help others learn and grow

## Recognition

Contributors will be recognized in:

- README.md contributors section
- Release notes
- Annual contribution report

Thank you for contributing to SYRTH! Your contributions help make software security more accessible to everyone.
