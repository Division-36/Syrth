"""The ordered class labels a SYRTH model is trained against.

Separate from :mod:`syrth.classifier.xgboost` because that module imports
numpy at import time, and the C exporter only needs the label list. A rules-only
install has no numpy, so importing the exporter used to fail with a
``ModuleNotFoundError`` on a path that never needed a numerical stack.
"""

from __future__ import annotations

from ..registry import CATEGORIES, CATEGORY_CWE

#: Index *n* of this list is the class of output *n*. The order is part of the
#: model contract: an exported header and its ``.joblib`` bundle must agree.
CWE_CLASSES: list[str] = [CATEGORY_CWE[category] for category in CATEGORIES]
