"""
SYRTH Taint Analysis
====================
Value-level taint state and the operations that combine it.

See :mod:`syrth.taint.engine` for the model and the merge semantics.
"""

from .engine import TaintEngine, TaintState, TaintValue

__all__ = ["TaintEngine", "TaintState", "TaintValue"]
