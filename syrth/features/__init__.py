"""
SYRTH Feature Extraction
========================
Converts parsed ``FileTrace`` objects into fixed-size, rename-invariant feature
vectors for the optional ML classifier.

The vector layout is versioned by
:data:`syrth.features.extractor.FEATURE_SCHEMA_VERSION` and deliberately
contains no identifier-derived features, so a model trained on these vectors
cannot acquire a dependence on naming conventions.
"""

from .extractor import (
    FEATURE_INDEX,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    NUM_FEATURES,
    FeatureExtractionError,
    FeatureExtractor,
    feature_schema,
)

__all__ = [
    "FEATURE_INDEX",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FeatureExtractionError",
    "FeatureExtractor",
    "NUM_FEATURES",
    "feature_schema",
]
