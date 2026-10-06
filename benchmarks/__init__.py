"""
SYRTH v2 Benchmarks
===================
Benchmark harness for detection quality and runtime performance.

- ``synthetic.py``: deterministic vulnerable/clean code generator
- ``datasets.py``: real-dataset loaders (BigVul / Devign / RealVuln)
- ``run_benchmarks.py``: CLI entry point producing a JSON report
"""

__all__ = ["run", "synthetic", "datasets"]
