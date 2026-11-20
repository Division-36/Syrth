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
# The studies that produced the published numbers, each of which writes the
# file the documentation quotes:
#
#   make patch-study    what a real fix commit does to a certificate
#   make ablation       which analysis decision each number depends on
#   make identity       certificate identity under renaming
#   make whole-repo     the same patch study over full working trees (hours)
#
#   make verify-published   re-derive every published number and compare it
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
        patch-study ablation identity whole-repo verify-published \
        tool-comparison tool-capability patch-verification \
        train export-smoke docs-check build clean clean-windows

help:
	@echo "make check | test | lint | scan FILE= | bench | competitors | corpus"
	@echo "make patch-study | ablation | identity | whole-repo | verify-published"
	@echo "make tool-comparison | tool-capability | patch-verification"

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

# The real-commit patch study: what a developer's fix does to the certificate
# the advisory is about.
patch-study:
	$(PYTHON) -m benchmarks.patch_study --dataset $(DATASET) \
		--json data/patch_study.json

# Which analysis decision each published number depends on.
ablation:
	$(PYTHON) -m benchmarks.ablation --dataset $(DATASET) \
		--json data/ablation.json

# Certificate identity under renaming.
identity:
	$(PYTHON) -m benchmarks.identity --dataset $(DATASET) \
		--json data/identity_rename.json

# The same patch study over full working trees: every fix commit, both
# revisions, 24 repositories. Needs the repositories under
# experiments/scratch/repos and takes hours. Results are checkpointed per
# commit, so an interrupted run resumes where it stopped.
whole-repo:
	$(PYTHON) -m benchmarks.whole_repo_study --dataset $(DATASET) \
		--repos experiments/scratch/repos \
		--json data/whole_repo_study.json

# Re-derive every published number and compare it with what is published.
# Exits non-zero when a published file no longer matches its harness.
verify-published:
	$(PYTHON) -m benchmarks.verify_published --dataset $(DATASET)

# Whole-repository tool comparison: one fix commit per repository, whole
# worktrees, four instruments. Needs bandit, semgrep and ruff on PATH, plus
# the repositories under experiments/scratch/repos. Takes minutes; the JSON
# is a checkpoint, so a killed run resumes at the last finished repository.
tool-comparison:
	$(PYTHON) -m benchmarks.tool_comparison --dataset $(DATASET) \
		--repos experiments/scratch/repos \
		--json data/tool_comparison.json

# Consolidate both matched comparisons into one capability profile, with the
# strength margins stated in absolute counts on the same population.
tool-capability:
	$(PYTHON) -m benchmarks.tool_capability_study \
		--competitors data/competitor_benchmark.json \
		--trees data/tool_comparison.json \
		--json data/tool_capability.json

# Re-derive the patch-verification study from its recorded answers. The raw
# answers embed third-party source and are not committed; see the study doc.
patch-verification:
	$(PYTHON) -m benchmarks.patch_verification verify --dataset $(DATASET) \
		--responses data/patch_responses.jsonl \
		--json data/patch_verification.json
	$(PYTHON) -m benchmarks.patch_author_comparison --dataset $(DATASET) \
		--responses data/patch_responses.jsonl \
		--json data/patch_author_comparison.json

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