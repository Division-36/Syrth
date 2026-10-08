# SYRTH — development and verification targets.
#
#   make check        lint and test, which is the gate every change passes
#   make test         the test suite alone
#   make lint         ruff over the package, tests, benchmarks and tools
#   make scan         scan a file and print the report
#   make bench        the risk-model benchmark against the built corpus
#   make competitors  SYRTH against Bandit and Semgrep on the same corpus
#   make corpus       rebuild the corpus from advisories (slow, checkpointed)
#
# Runtime dependencies are tree-sitter and tree-sitter-python, both declared in
# pyproject.toml. Everything else is an extra:
#
#   pip install -e ".[dev,benchmark]"

PYTHON ?= python
TARGET ?= syrth
THRESHOLD ?= 0.5
DATASET ?= data/corpus.jsonl
FILE ?=

.PHONY: help install install-dev install-benchmark test test-verbose lint \
        check scan scan-json scan-sarif fix diff bench competitors corpus \
        train export-smoke docs-check build clean clean-windows

help:
	@echo "make check | test | lint | scan FILE= | bench | competitors | corpus"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

install-benchmark:
	$(PYTHON) -m pip install -e ".[benchmark]"

test:
	$(PYTHON) -m pytest tests -q -o addopts=

test-verbose:
	$(PYTHON) -m pytest tests -v -o addopts=

lint:
	$(PYTHON) -m ruff check syrth tests benchmarks tools

check: lint test

scan:
	$(TARGET) --file "$(FILE)" --threshold $(THRESHOLD)

scan-json:
	$(TARGET) --file "$(FILE)" --threshold $(THRESHOLD) --json

scan-sarif:
	$(TARGET) --file "$(FILE)" --threshold $(THRESHOLD) --format sarif

fix:
	$(TARGET) --file "$(FILE)" --fix

diff:
	$(TARGET) --file "$(FILE)" --diff

# The contract-defined measurements: coverage, rank agreement, rename invariance,
# kill rate, determinism. Precision is deliberately absent -- docs/risk-model.md
# does not define it and this project reports no verdict.
bench:
	$(PYTHON) -m benchmarks.risk_metrics --dataset $(DATASET) \
		--json data/risk_benchmark.json

# Bandit and two Semgrep rule sets, on the same corpus and the same ground truth.
# The two right-hand columns are how many fixes each tool registered.
competitors:
	$(PYTHON) -m benchmarks.competitors --dataset $(DATASET) \
		--json data/competitor_benchmark.json

# Rebuilds from GHSA/OSV. Checkpointed: a run interrupted by the time budget
# resumes from where it stopped rather than starting over.
corpus:
	$(PYTHON) tools/build_corpus.py --out $(DATASET)

train:
	$(PYTHON) -m syrth.train --dataset $(DATASET)

docs-check:
	$(PYTHON) -m pytest tests/test_docs_consistency.py -q -o addopts=

build:
	$(PYTHON) -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	rm -f syrth_engine.h syrth_engine.so

clean-windows:
	rmdir /s /q build dist syrth.egg-info .pytest_cache .ruff_cache 2>nul || ver > nul
	del /q syrth_engine.h syrth_engine.so 2>nul || ver > nul