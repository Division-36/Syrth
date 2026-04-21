# SYRTH Documentation Index

Welcome to the SYRTH (Scan Your Risk Trace History) documentation. This comprehensive guide covers everything from installation to advanced usage and contribution.

## 📚 Documentation Structure

### [README.md](../README.md)
**Getting Started Guide**
- Project overview and architecture
- Quick start instructions
- Vulnerability classes detected
- Performance metrics
- File structure

### [API.md](API.md)
**API Reference**
- Core classes and methods
- Command-line tools
- Configuration options
- Data formats
- Error codes and troubleshooting

### [INSTALLATION.md](INSTALLATION.md)
**Installation Guide**
- System requirements
- Platform-specific setup
- Virtual environment configuration
- Verification and testing
- Common installation issues

### [EXAMPLES.md](EXAMPLES.md)
**Examples and Use Cases**
- Basic vulnerability scanning
- CI/CD pipeline integration
- Web service implementation
- IDE plugin development
- Batch repository analysis
- Performance optimization
- Docker and Kubernetes deployment

### [CONTRIBUTING.md](CONTRIBUTING.md)
**Contributing Guide**
- Development setup
- Code style and standards
- Pull request process
- Areas for contribution
- Testing guidelines
- Release process

##  Quick Start

1. **Install SYRTH**
   ```bash
   pip install torch numpy scikit-learn joblib matplotlib seaborn psutil
   ```

2. **Generate Dataset**
   ```bash
   python harvester.py
   ```

3. **Train Model**
   ```bash
   python train_model.py --dataset _dataset.json
   ```

4. **Scan Code**
   ```bash
   python syrth_scan.py --file your_app.py --mode dev
   ```

5. **Benchmark Performance**
   ```bash
   python benchmark.py
   ```

## Key Features

###  Vulnerability Detection
- **8 vulnerability classes**: SQLi, XSS, IDOR, SSRF, PathTraversal, OpenRedirect, BrokenAuth, RCE
- **High accuracy**: ~80-85% on real vulnerability data (Per fold, K=7)
- **Context-aware**: Understands code flow and security patterns

###  Performance
- **Python engine**: ~500μs inference time
- **C engine**: ~20μs inference time (25x faster)
- **Low memory**: <5MB RAM usage
- **High throughput**: 50K+ samples/second (C engine)

###  Security
- **No data leakage**: Strict train/test separation
- **Privacy-focused**: Local processing only
- **Auditable**: Open source with transparent algorithms

###  Integration
- **Multiple interfaces**: CLI, Python API, C header
- **CI/CD ready**: GitHub Actions, Jenkins support
- **Framework agnostic**: Works with any Python codebase

##  Performance Benchmarks

| Metric | Python Engine | C Engine | Improvement |
|--------|---------------|-----------|-------------|
| Mean Latency | ~500μs | ~20μs | **25x faster** |
| P99 Latency | ~2ms | ~50μs | **40x faster** |
| Throughput | ~2K/s | ~50K/s | **25x higher** |
| Memory Usage | ~2-5MB | ~0.5-1MB | **5x lower** |

##  Configuration

### Model Parameters
```python
DEFAULT_EMBED_DIM = 256    # Embedding dimension
DEFAULT_FFN_DIM = 1024     # Feed-forward network size
DEFAULT_DROPOUT = 0.2      # Regularization strength
DEFAULT_BATCH_SIZE = 64     # Training batch size
DEFAULT_LR = 5e-3          # Learning rate
K_FOLDS = 7                # Cross-validation folds
```

### Benchmark Settings
```python
BENCHMARK_RUNS = 500       # Test iterations
TEST_SPLIT_RATIO = 0.2      # Train/test split
RANDOM_SEED = 42            # Reproducibility
```

##  Common Issues & Solutions

### Installation Issues
- **Missing dependencies**: Install with `pip install torch numpy scikit-learn joblib`
- **C compilation fails**: Install GCC with `sudo apt install build-essential`
- **Permission denied**: Use `pip install --user` or virtual environment

### Performance Issues
- **Slow inference**: Use C engine with `--mode prod`
- **Memory errors**: Reduce batch size in training
- **Low accuracy**: Ensure balanced dataset and proper training

### Accuracy Issues
- **False positives**: Adjust confidence threshold
- **Missing detections**: Update token patterns
- **Poor performance**: Retrain with more diverse data

##  Version History

### v1.0.0 (Current)
- Initial release
- 8 vulnerability classes supported
- Python and C inference engines
- Comprehensive benchmarking suite
- CI/CD integration examples

### Upcoming Features
- [ ] Multi-language support (JavaScript, Java)
- [ ] Advanced AST-based tokenization
- [ ] Real-time monitoring dashboard
- [ ] Plugin system for custom detectors
- [ ] Cloud deployment templates

##  Community

### Getting Help
- **GitHub Issues**: [Report bugs](https://github.com/Zierax/Syrth/issues)
- **Discussions**: [Ask questions](https://github.com/Zierax/Syrth/discussions)
- **Security**: security@syrth.dev

### Contributing
- **Contributors**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Code of Conduct**: Be respectful and inclusive
- **Recognition**: Contributors acknowledged in releases

##  Checklists

### Before Scanning
- [ ] Model trained (`syrth_model.joblib` exists)
- [ ] Dataset generated (`_dataset.json` exists)
- [ ] Dependencies installed
- [ ] C engine compiled (for production mode)

### Before Deployment
- [ ] Performance benchmarked
- [ ] Accuracy validated on test data
- [ ] Memory usage acceptable
- [ ] Error handling implemented

### Before Release
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version number updated

##  External Resources

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Mitigation](https://cwe.mitre.org/)
- [NVD Database](https://nvd.nist.gov/)

### Python Security
- [Bandit](https://bandit.readthedocs.io/) - Static analysis
- [Safety](https://github.com/pyupio/safety) - Dependency checking
- [Semgrep](https://semgrep.dev/) - Pattern matching

### Machine Learning
- [PyTorch](https://pytorch.org/) - Deep learning framework
- [Scikit-learn](https://scikit-learn.org/) - Machine learning library
- [Joblib](https://joblib.readthedocs.io/) - Model serialization

##  Support

### Documentation Issues
Found an error in the documentation? Please:
1. Check the [latest version](https://github.com/Zierax/Syrth/tree/main/docs)
2. [Open an issue](https://github.com/Zierax/Syrth/issues/new)
3. Include the documentation page and section

### Feature Requests
Have an idea for improvement? Please:
1. Check [existing issues](https://github.com/Zierax/Syrth/issues)
2. [Open a new issue](https://github.com/Zierax/Syrth/issues/new) with "enhancement" label
3. Describe the use case and expected behavior

### Security Vulnerabilities
Found a security issue in SYRTH itself? Please:
1. Do **not** open a public issue
2. Email details to security@syrth.dev
3. Include steps to reproduce and potential impact

##  License

SYRTH is provided under the MIT License. See [LICENSE](LICENSE) for full details.

---

**Version**: 1.0.0  
**Maintainers**: Zierax

For the most up-to-date information, visit the [GitHub repository](https://github.com/Zierax/Syrth).
