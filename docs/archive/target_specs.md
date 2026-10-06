# SYRTH v2 Target Specifications

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


## Overview

This document defines the performance targets, benchmark specifications, and success criteria for SYRTH v2. The goal is to create a lightweight, CPU-only, multi-language vulnerability detector that achieves competitive results on standard benchmarks.

## Primary Objectives

1. **Lightweight Deployment**: Installation <50MB, runs on any modern CPU
2. **Real-Time Performance**: Inference <50ms per file, RAM <100MB
3. **Multi-Language Support**: Python, C, C++, Java, JavaScript
4. **Competitive Accuracy**: Beat Bandit by +20-30% F1 on standard benchmarks
5. **Publication Ready**: Results suitable for academic paper

## Performance Targets

### System Requirements
| Requirement | Minimum | Recommended | Target |
|-------------|---------|-------------|--------|
| CPU | i5-8250U (2018) | i5-10400 (2020) | i5-8250U |
| RAM | 2GB | 4GB | <100MB usage |
| Disk | 100MB | 200MB | <50MB installation |
| OS | Windows 10, macOS 10.15, Ubuntu 18.04 | Latest | All major OS |
| Python | 3.10+ | 3.11+ | 3.10+ |

### Inference Performance
| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Parse time | <1ms/1000 lines | tree-sitter benchmark |
| Feature extraction | <10ms/file | Profiling |
| Classification | <15ms/file | XGBoost prediction |
| Total inference | <50ms/file | End-to-end timing |
| Memory usage | <100MB | Peak RSS monitoring |
| CPU utilization | <50% single core | top/htop monitoring |

### Installation Performance
| Metric | Target | Measurement |
|--------|--------|-------------|
| Package size | <50MB | pip install size |
| Download time | <30s | 100Mbps connection |
| Install time | <60s | SSD storage |
| First run | <5s | Model loading |

## Benchmark Specifications

### 1. BigVul Dataset
**Source**: https://github.com/Zeo123/BigVul-dataset
**Size**: 188,042 C/C++ functions
**Labels**: Vulnerable/Non-vulnerable (binary classification)
**Split**: Train/Val/Test (70/10/20)

**Target Metrics**:
| Metric | Target | Baseline (Bandit) | Improvement |
|--------|--------|-------------------|-------------|
| F1 Score | ≥65% | ~45% | +20% |
| Precision | ≥70% | ~50% | +20% |
| Recall | ≥60% | ~40% | +20% |
| Accuracy | ≥75% | ~55% | +20% |

**Evaluation Protocol**:
- 5-fold cross-validation
- Stratified sampling
- Leak-free train/test split
- Statistical significance testing (p<0.05)

### 2. Devign Dataset
**Source**: https://github.com/Zeo123/Devign-dataset
**Size**: 25,347 C/C++ functions
**Labels**: Vulnerable/Non-vulnerable (binary classification)
**Split**: Train/Val/Test (70/10/20)

**Target Metrics**:
| Metric | Target | Baseline (Bandit) | Improvement |
|--------|--------|-------------------|-------------|
| F1 Score | ≥60% | ~40% | +20% |
| Precision | ≥65% | ~45% | +20% |
| Recall | ≥55% | ~35% | +20% |
| Accuracy | ≥70% | ~50% | +20% |

### 3. RealVuln Dataset
**Source**: https://github.com/RealVuln/RealVuln
**Size**: 796 Python entries
**Labels**: 120 false-positive traps
**Languages**: Python only

**Target Metrics**:
| Metric | Target | Baseline (Semgrep) | Improvement |
|--------|--------|-------------------|-------------|
| F1 Score | ≥55% | 17.7% | +37% |
| Precision | ≥60% | ~20% | +40% |
| Recall | ≥50% | ~15% | +35% |

### 4. SYRTH Internal Benchmark
**Source**: Real GitHub advisories (OSV PyPI bulk corpus)
**Size**: 2,299 records
**Languages**: Python only
**CWE Classes**: 5 (v1) → 15+ (v2)

**Target Metrics**:
| Metric | v1 Result | v2 Target | Improvement |
|--------|-----------|-----------|-------------|
| Held-out accuracy | 69.0% | ≥75% | +6% |
| F1 Score | 68.5% | ≥72% | +3.5% |
| Real code accuracy | withdrawn | ≥88% | +1.2% |

## CWE Class Specifications

### Expanded Coverage (15+ Classes)
| Class | CWE ID | Name | Languages | Detection Complexity |
|-------|--------|------|-----------|---------------------|
| 0 | CWE-89 | SQL Injection | Python, Java, JS | Medium |
| 1 | CWE-79 | Cross-Site Scripting | Python, Java, JS | Medium |
| 2 | CWE-22 | Path Traversal | All | Low |
| 3 | CWE-601 | Open Redirect | Python, Java, JS | Low |
| 4 | CWE-94 | Remote Code Execution | All | High |
| 5 | CWE-502 | Deserialization | Python, Java | High |
| 6 | CWE-798 | Hard-coded Credentials | All | Low |
| 7 | CWE-200 | Information Exposure | All | Medium |
| 8 | CWE-287 | Improper Authentication | All | High |
| 9 | CWE-306 | Missing Authentication | All | Medium |
| 10 | CWE-311 | Missing Encryption | All | High |
| 11 | CWE-327 | Broken Crypto | All | High |
| 12 | CWE-434 | Unrestricted Upload | Python, Java, JS | Medium |
| 13 | CWE-611 | XXE | Python, Java | High |
| 14 | CWE-918 | SSRF | Python, Java, JS | High |

### Detection Complexity Levels
- **Low**: Pattern matching, simple taint analysis
- **Medium**: Inter-procedural analysis, data flow tracking
- **High**: Complex control flow, context-sensitive analysis

## Feature Specifications

### Feature Vector Dimensions
| Feature Category | Count | Description |
|-----------------|-------|-------------|
| Sink features | 15 | Count, types, and patterns of dangerous sinks |
| Taint features | 12 | Source-to-sink propagation metrics |
| Decorator features | 8 | Security decorator presence and types |
| Control flow features | 10 | Branch, loop, and guard analysis |
| Language features | 5 | Language-specific patterns |
| Context features | 3 | File, function, and class context |
| **Total** | **53** | Same as v1 for compatibility |

### Feature Extraction Performance
| Operation | Target | Measurement |
|-----------|--------|-------------|
| Sink detection | <2ms/file | Profiling |
| Taint analysis | <5ms/file | Profiling |
| Decorator detection | <1ms/file | Profiling |
| Control flow analysis | <2ms/file | Profiling |
| Total extraction | <10ms/file | End-to-end |

## Model Specifications

### XGBoost Configuration
```python
# Optimized for CPU performance
model_config = {
    "objective": "multi:softprob",
    "num_class": 15,                    # 15+ CWE classes
    "max_depth": 8,                     # Balanced depth
    "learning_rate": 0.1,               # Standard learning rate
    "n_estimators": 200,                # Sufficient trees
    "subsample": 0.8,                   # Prevent overfitting
    "colsample_bytree": 0.8,            # Feature sampling
    "tree_method": "hist",              # CPU-optimized
    "predictor": "auto",                # Auto-detect CPU
    "random_state": 42,                 # Reproducibility
    "n_jobs": -1,                       # Use all CPU cores
}
```

### Model Performance Targets
| Metric | Target | Measurement |
|--------|--------|-------------|
| Training time | <5 minutes | On benchmark datasets |
| Model size | <10MB | Serialized joblib |
| Load time | <1s | Model deserialization |
| Prediction time | <15ms/sample | Single prediction |
| Batch prediction | <5ms/sample | 1000+ samples |

## Explainability Specifications

### Required Explanations
1. **Token Importance**: Top-10 tokens influencing classification
2. **Taint Flow**: Path from user input to dangerous sink
3. **CWE Mapping**: Why this vulnerability class was selected
4. **Confidence Scores**: Probability for each CWE class
5. **Recommendation**: Specific fix suggestion

### Explanation Performance
| Operation | Target | Measurement |
|-----------|--------|-------------|
| Token importance | <2ms/file | Profiling |
| Taint flow generation | <5ms/file | Profiling |
| Report generation | <3ms/file | Profiling |
| Total explanation | <10ms/file | End-to-end |

## Quality Assurance

### Test Coverage
| Component | Target Coverage | Test Count |
|-----------|----------------|------------|
| Parser | 90% | 50+ tests |
| Feature extraction | 85% | 40+ tests |
| Classifier | 80% | 30+ tests |
| Integration | 75% | 20+ tests |
| **Total** | **85%** | **140+ tests** |

### Performance Testing
- **Latency tests**: Measure inference time under load
- **Memory tests**: Monitor RSS during extended use
- **CPU tests**: Profile single-core and multi-core performance
- **Scalability tests**: Test with 1KB to 10MB files

### Accuracy Testing
- **Cross-validation**: 5-fold on each benchmark
- **Statistical significance**: p<0.05 for all comparisons
- **Ablation studies**: Measure impact of each component
- **Edge cases**: Test with empty, malformed, and large files

## Publication Requirements

### Paper Metrics
| Metric | Target | Justification |
|--------|--------|---------------|
| F1 vs Bandit | +20-30% | Clear superiority |
| F1 vs Semgrep | +30-40% | Significant improvement |
| Installation size | <50MB | Lightweight advantage |
| Inference speed | <50ms | Real-time capability |
| CPU requirement | i5-8250U | Accessibility |

### Reproducibility
- **Code**: Open-source on GitHub
- **Models**: Pre-trained models included
- **Data**: Benchmark datasets referenced
- **Instructions**: Clear setup and evaluation steps
- **Environment**: Docker image for exact reproduction

### Comparison Baselines
1. **Bandit**: Python-only security scanner
2. **Semgrep**: Multi-language pattern matcher
3. **CodeQL**: GitHub's semantic analysis engine
4. **LLMs**: GPT-4, Claude, CodeBERT (GPU-based)

## Success Criteria

### Minimum Viable Product (MVP)
- [ ] Python parser working with tree-sitter
- [ ] XGBoost classifier trained on BigVul
- [ ] Inference <100ms per file
- [ ] Installation <100MB
- [ ] Basic explainability output

### Target Release
- [ ] All 5 languages supported
- [ ] 15+ CWE classes detected
- [ ] Inference <50ms per file
- [ ] Installation <50MB
- [ ] Full explainability suite
- [ ] Benchmark results published

### Publication Ready
- [ ] Beat Bandit by +20% F1
- [ ] Competitive with LLMs on CPU
- [ ] Reproducible results
- [ ] Open-source release
- [ ] Paper submitted

## Timeline

### Phase 0: Documentation (Week 1)
- [x] Architecture document
- [x] Dependency analysis
- [x] Target specifications (this file)

### Phase 1: Parser Foundation (Weeks 2-3)
- [ ] tree-sitter installation and testing
- [ ] BaseParser abstract class
- [ ] Python parser implementation
- [ ] SINK_REGISTRY porting
- [ ] Token vocabulary system

### Phase 2: Feature Extraction (Weeks 4-5)
- [ ] Sink detection for all languages
- [ ] Taint propagation engine
- [ ] Security decorator detection
- [ ] Control flow analysis
- [ ] Feature vector generation

### Phase 3: Classification (Weeks 6-7)
- [ ] XGBoost training pipeline
- [ ] Benchmark dataset preparation
- [ ] Model optimization
- [ ] C header export
- [ ] Performance tuning

### Phase 4: Integration (Weeks 8-9)
- [ ] CLI frontend
- [ ] Explainability reporting
- [ ] Benchmark suite
- [ ] Test suite
- [ ] Documentation

### Phase 5: Publication (Weeks 10-12)
- [ ] Benchmark validation
- [ ] Bandit comparison
- [ ] Paper writing
- [ ] Open-source release
- [ ] Conference submission

## Risk Mitigation

### High Risk Items
1. **Accuracy drop from PyTorch to XGBoost**
   - Mitigation: Extensive hyperparameter tuning, feature engineering
   - Contingency: Hybrid model (XGBoost + lightweight neural)

2. **tree-sitter grammar issues**
   - Mitigation: Pin grammar versions, test thoroughly
   - Contingency: Fallback to custom parsers for problematic languages

### Medium Risk Items
1. **Installation size exceeds 50MB**
   - Mitigation: Optional dependencies, lazy loading
   - Contingency: Accept 75MB limit

2. **Inference time exceeds 50ms**
   - Mitigation: Optimize feature extraction, use C extension
   - Contingency: Accept 100ms limit

### Low Risk Items
1. **Python version compatibility**
   - Mitigation: Document requirement, provide Docker image
   - Contingency: Support Python 3.9 with limited features

2. **Benchmark dataset access**
   - Mitigation: Download scripts, local mirrors
   - Contingency: Use alternative datasets

## Conclusion

SYRTH v2 aims to be a lightweight, CPU-only, multi-language vulnerability detector that achieves competitive results on standard benchmarks. The key targets are:

- **Installation**: <50MB
- **Inference**: <50ms per file
- **Accuracy**: Beat Bandit by +20-30% F1
- **Languages**: Python, C, C++, Java, JavaScript
- **CWE Classes**: 15+ categories

With careful implementation and thorough testing, these targets are achievable within the 3-3.5 month timeline. The result will be a tool suitable for both practical use and academic publication.