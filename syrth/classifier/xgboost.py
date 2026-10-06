"""
XGBoost Classifier
==================
Optional learned ranker over the rename-invariant feature vector.

Role in the pipeline
--------------------
The classifier **refines** findings; it never creates or removes them. A
confirmed source-to-sink trace is reported whether or not a model is loaded, and
the model only contributes a probability and a class prior. This is a
deliberate inversion of the usual arrangement and it is what makes the tool's
output trustworthy: an unavailable or broken model degrades precision, not
correctness.

Label space
-----------
Predictions are CWE identifiers derived from
:data:`syrth.registry.CATEGORY_CWE`, so the ML path and the rule path emit from
one closed set. :data:`CWE_CLASSES` is generated from that table rather than
maintained by hand, which is what previously let the two drift apart into a
five-class rule space and a fifteen-class model space.

Schema guard
------------
A saved bundle records :data:`syrth.features.FEATURE_SCHEMA_VERSION`. Loading a
bundle trained against a different layout raises :class:`SchemaMismatch` instead
of silently scoring a wrong-width vector -- the failure mode that made the
previous meta-learner silently dead rather than loudly broken.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from ..features.extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, NUM_FEATURES
from ..registry import CATEGORIES, CATEGORY_CWE

#: Canonical prediction order. Generated from the category table so the label
#: space can never drift from the registry.
CWE_CLASSES: list[str] = [CATEGORY_CWE[category] for category in CATEGORIES]
CWE_TO_INDEX: dict[str, int] = {cwe: i for i, cwe in enumerate(CWE_CLASSES)}

#: Model hyper-parameters. Chosen for CPU-only, small-data, many-class operation:
#: a shallow histogram-boosted forest fits this feature space without the
#: capacity to memorise identifiers, which the vector does not contain anyway.
MODEL_CONFIG: dict[str, Any] = {
    "objective": "multi:softprob",
    "num_class": len(CWE_CLASSES),
    "max_depth": 6,
    "learning_rate": 0.08,
    "n_estimators": 300,
    "subsample": 0.85,
    "colsample_bytree": 0.85,
    "min_child_weight": 3,
    "reg_lambda": 1.5,
    "tree_method": "hist",
    "predictor": "auto",
    "random_state": 42,
    "n_jobs": -1,
    "eval_metric": "mlogloss",
    "verbosity": 0,
}


class SchemaMismatch(RuntimeError):
    """Raised when a model bundle was trained on a different feature layout."""


def _import_xgboost():
    """Import xgboost with an actionable error message."""
    try:
        import xgboost  # noqa: PLC0415 - deliberately lazy
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "xgboost is required for the ML classifier. Install it with "
            "`pip install xgboost`, or run SYRTH rules-only (the default)."
        ) from exc
    return xgboost


def _to_label_indices(y: Sequence[Any]) -> np.ndarray:
    """Convert CWE strings or integers to integer label indices."""
    array = np.asarray(y)
    if array.dtype.kind in ("U", "S", "O"):
        return np.array([CWE_TO_INDEX[str(label)] for label in array], dtype=int)
    return array.astype(int)


class XGBoostClassifier:
    """XGBoost classifier over the rename-invariant feature vector."""

    def __init__(self, model_path: str | None = None):
        """
        Args:
            model_path: Path to a saved bundle. When ``None`` an untrained
                classifier is created.

        Raises:
            FileNotFoundError: If ``model_path`` does not exist.
            SchemaMismatch: If the bundle was trained on another layout.
        """
        self.model = None
        self.feature_names: list[str] | None = None
        self.model_path: str | None = model_path
        self.feature_schema_version: int = FEATURE_SCHEMA_VERSION
        self._classes_: np.ndarray | None = None
        self._n_features_in_: int | None = None
        self._global_importances_: np.ndarray | None = None

        if model_path:
            self.load_model(model_path)
        else:
            xgb = _import_xgboost()
            self.model = xgb.XGBClassifier(**MODEL_CONFIG)

    # ---------------------------------------------------------------- model
    def is_fitted(self) -> bool:
        """True when the classifier holds a fitted model."""
        if self.model is None:
            return False
        try:
            return bool(self.model.__sklearn_is_fitted__())
        except AttributeError:
            return hasattr(self.model, "n_estimators_")

    def train(
        self,
        X: np.ndarray,
        y: Sequence[Any],
        eval_set: tuple[np.ndarray, Sequence[Any]] | None = None,
        early_stopping_rounds: int | None = None,
    ) -> dict[str, Any]:
        """Fit the model.

        Args:
            X: Feature matrix of shape ``(n_samples, NUM_FEATURES)``.
            y: CWE strings or integer label indices.
            eval_set: Optional ``(X_val, y_val)`` used for early stopping. This
                must be a *validation* split, never the test split; selecting on
                the test set is what made the previous ensemble weights invalid.
            early_stopping_rounds: Rounds without improvement before stopping.

        Returns:
            A metrics dict describing the fit.

        Raises:
            ValueError: If the feature width does not match the current schema.
        """
        matrix = np.asarray(X, dtype=float)
        if matrix.ndim != 2 or matrix.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"expected {NUM_FEATURES} features, got "
                f"{matrix.shape if matrix.ndim == 2 else matrix.ndim} "
                "dimensions"
            )
        labels = _to_label_indices(y)

        fit_kwargs: dict[str, Any] = {"verbose": False}
        if eval_set is not None:
            X_val, y_val = eval_set
            fit_kwargs["eval_set"] = [(np.asarray(X_val, dtype=float), _to_label_indices(y_val))]
            fit_kwargs["eval_metric"] = "mlogloss"
            if early_stopping_rounds:
                fit_kwargs["early_stopping_rounds"] = int(early_stopping_rounds)

        self.model.fit(matrix, labels, **fit_kwargs)
        self._classes_ = np.asarray(self.model.classes_, dtype=int)
        self._n_features_in_ = int(matrix.shape[1])
        self._prime_importance_cache()

        metrics: dict[str, Any] = {
            "n_samples": int(matrix.shape[0]),
            "n_features": int(matrix.shape[1]),
            "n_classes_seen": int(len(self._classes_)),
            "n_classes_total": len(CWE_CLASSES),
            "feature_schema_version": self.feature_schema_version,
        }
        try:
            for split, values in self.model.evals_result().items():
                for name, series in values.items():
                    metrics[f"{split}_{name}"] = round(float(series[-1]), 6)
        except Exception:  # noqa: BLE001 - metrics are best-effort
            pass
        best = getattr(self.model, "best_iteration", None)
        if best is not None:
            metrics["best_iteration"] = int(best)
        return metrics

    def _prime_importance_cache(self) -> None:
        """Cache global feature importances once, for explanation fallbacks."""
        try:
            self._global_importances_ = np.asarray(
                self.model.feature_importances_, dtype=float
            )
        except Exception:  # noqa: BLE001 - explanation is optional
            self._global_importances_ = None

    # ------------------------------------------------------------ inference
    def _check_ready(self) -> None:
        if self.model is None or not self.is_fitted():
            raise ValueError("model is not trained or loaded")

    def _check_width(self, array: np.ndarray) -> np.ndarray:
        if self._n_features_in_ is not None and array.shape[1] != self._n_features_in_:
            raise SchemaMismatch(
                f"model expects {self._n_features_in_} features, got {array.shape[1]}"
            )
        return array

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Predict labels and probabilities.

        Returns:
            ``(label_indices, probabilities)`` where indices address
            :data:`CWE_CLASSES`.
        """
        self._check_ready()
        matrix = self._check_width(np.asarray(X, dtype=float))
        probabilities = np.asarray(self.model.predict_proba(matrix), dtype=float)
        return np.argmax(probabilities, axis=1), probabilities

    def predict_single(self, X: Sequence[float]) -> dict[str, Any]:
        """Predict one sample with detailed output.

        Returns:
            Dict with ``predicted_cwe``, ``confidence``, ``ood``,
            ``all_probabilities``, ``top_predictions`` and ``feature_importance``.
        """
        self._check_ready()
        array = np.asarray(X, dtype=float)
        if array.ndim == 1:
            array = array.reshape(1, -1)
        array = self._check_width(array)

        probabilities = np.asarray(self.model.predict_proba(array)[0], dtype=float)
        columns = self._column_to_cwe_index(probabilities)
        top = int(np.argmax(probabilities))
        best_index = int(columns[top])

        by_cwe = {
            CWE_CLASSES[int(columns[i])]: float(probabilities[i])
            for i in range(len(probabilities))
            if 0 <= int(columns[i]) < len(CWE_CLASSES)
        }
        order = np.argsort(probabilities)[::-1]
        top_predictions = [
            {
                "cwe": CWE_CLASSES[int(columns[i])] if int(columns[i]) < len(CWE_CLASSES)
                else "UNKNOWN",
                "confidence": float(probabilities[i]),
                "rank": rank,
            }
            for rank, i in enumerate(order[:3], start=1)
        ]
        confidence = float(probabilities[top])
        return {
            "predicted_cwe": CWE_CLASSES[best_index] if best_index < len(CWE_CLASSES)
            else "UNKNOWN",
            "confidence": confidence,
            # The model contributes a probability, not a verdict. A low score
            # marks the *prior* as weak; it never suppresses a confirmed flow.
            "ood": confidence < 1.0 / len(CWE_CLASSES) * 2.0,
            "all_probabilities": by_cwe,
            "top_predictions": top_predictions,
            "feature_importance": self.local_feature_importance(array[0]),
        }

    def local_feature_importance(self, X: Sequence[float]) -> list[dict[str, Any]]:
        """Per-feature importance for one sample.

        Uses SHAP when it is importable, and the cached global gain
        importances otherwise. The fallback is deterministic and is labelled as
        global rather than per-sample, because presenting a global ranking as a
        per-sample attribution is misleading.
        """
        self._check_ready()
        explainer = getattr(self, "_shap_explainer_", None)
        if explainer is not None:
            try:
                values = explainer.shap_values(np.asarray(X).reshape(1, -1))
                if isinstance(values, list):
                    values = np.abs(np.asarray(values)).mean(axis=0)[0]
                return self._ranked(np.asarray(values)[0])
            except Exception:  # noqa: BLE001 - fall through to the cache
                pass
        if self._global_importances_ is not None:
            ranked = self._ranked(self._global_importances_)
            for item in ranked:
                item["scope"] = "global"
            return ranked
        return []

    @staticmethod
    def _ranked(values: np.ndarray) -> list[dict[str, Any]]:
        ranked = [
            {
                "feature_index": int(i),
                "feature_name": (
                    FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"f{i}"
                ),
                "importance": float(values[i]),
                "abs_importance": float(abs(values[i])),
                "scope": "local",
            }
            for i in range(len(values))
        ]
        ranked.sort(key=lambda item: -item["abs_importance"])
        return ranked[:10]

    def _column_to_cwe_index(self, probabilities: np.ndarray) -> np.ndarray:
        """Map probability columns onto :data:`CWE_CLASSES` indices.

        With the fixed ``num_class`` configuration the columns already match, but
        a model trained before a category was added has fewer columns, so the
        model's own fitted ``classes_`` mapping is honoured when present.

        Accepts either a 1-D single-sample vector or a 2-D matrix.
        """
        n_columns = int(np.atleast_2d(probabilities).shape[1])
        if n_columns == len(CWE_CLASSES):
            return np.arange(len(CWE_CLASSES), dtype=int)
        classes = self.model_classes()
        if len(classes) == n_columns:
            return np.asarray(classes, dtype=int)[:n_columns]
        return np.arange(n_columns, dtype=int)

    def model_classes(self) -> np.ndarray:
        """Class indices the model was fitted on."""
        if self._classes_ is None and self.model is not None:
            try:
                self._classes_ = np.asarray(self.model.classes_, dtype=int)
            except Exception:  # noqa: BLE001
                return np.arange(len(CWE_CLASSES))
        return self._classes_ if self._classes_ is not None else np.arange(len(CWE_CLASSES))

    # ------------------------------------------------------------- scoring
    def evaluate(self, X: np.ndarray, y: Sequence[Any]) -> dict[str, float]:
        """Score a held-out set.

        Returns:
            Accuracy plus weighted and macro precision/recall/F1.

        Raises:
            ValueError: If the model is unfitted.
        """
        from sklearn.metrics import (
            accuracy_score,
            f1_score,
            precision_score,
            recall_score,
        )

        self._check_ready()
        labels = _to_label_indices(y)
        matrix = np.asarray(X, dtype=float)
        predicted, _probabilities = self.predict(matrix)
        columns = self._column_to_cwe_index(_probabilities)
        mapped = np.array([columns[i] for i in predicted], dtype=int)
        return {
            "accuracy": float(accuracy_score(labels, mapped)),
            "precision_weighted": float(
                precision_score(labels, mapped, average="weighted", zero_division=0)
            ),
            "recall_weighted": float(
                recall_score(labels, mapped, average="weighted", zero_division=0)
            ),
            "f1_weighted": float(
                f1_score(labels, mapped, average="weighted", zero_division=0)
            ),
            "f1_macro": float(f1_score(labels, mapped, average="macro", zero_division=0)),
        }

    # --------------------------------------------------------- persistence
    def save_model(self, path: str) -> None:
        """Write a self-describing model bundle.

        The bundle records the feature schema, the category table and the label
        order, so a loader can refuse a mismatched model instead of silently
        scoring garbage.
        """
        import joblib  # noqa: PLC0415 - keeps import cost off the rules path

        if self.model is None:
            raise ValueError("no model to save")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_names": list(self.feature_names or FEATURE_NAMES),
                "feature_schema_version": self.feature_schema_version,
                "n_features": NUM_FEATURES,
                "cwe_classes": list(CWE_CLASSES),
                "categories": list(CATEGORIES),
                "classes": self.model_classes().tolist(),
                "syrth_trace_schema": _trace_schema(),
            },
            target,
        )

    def load_model(self, path: str) -> None:
        """Load a model bundle, verifying the feature schema.

        Raises:
            FileNotFoundError: If the bundle does not exist.
            SchemaMismatch: If the bundle's feature layout differs from this
                build's.
        """
        import joblib  # noqa: PLC0415

        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"model file not found: {path}")
        bundle = joblib.load(target)

        version = bundle.get("feature_schema_version")
        if version is not None and int(version) != FEATURE_SCHEMA_VERSION:
            raise SchemaMismatch(
                f"model {path} was trained with feature schema v{version}; "
                f"this build uses v{FEATURE_SCHEMA_VERSION}. Retrain with "
                "`python -m syrth.train`."
            )
        self.feature_schema_version = int(version or FEATURE_SCHEMA_VERSION)

        n_features = bundle.get("n_features")
        if n_features is not None and int(n_features) != NUM_FEATURES:
            raise SchemaMismatch(
                f"model {path} expects {n_features} features, this build "
                f"produces {NUM_FEATURES}"
            )

        classes = bundle.get("cwe_classes")
        if classes and list(classes) != CWE_CLASSES:
            raise SchemaMismatch(
                f"model {path} was trained on a different label space: "
                f"{list(classes)} != {CWE_CLASSES}"
            )

        self.model = bundle["model"]
        self.feature_names = bundle.get("feature_names")
        classes_fitted = bundle.get("classes")
        self._classes_ = (
            np.asarray(classes_fitted, dtype=int) if classes_fitted else None
        )
        self._n_features_in_ = int(getattr(self.model, "n_features_in_", NUM_FEATURES))
        self._prime_importance_cache()

    # ------------------------------------------------------------- queries
    def get_model_info(self) -> dict[str, Any]:
        """Summary of the loaded model."""
        if self.model is None:
            return {"status": "not_loaded"}
        info: dict[str, Any] = {
            "status": "loaded" if self.is_fitted() else "constructed",
            "n_features": self._n_features_in_ or NUM_FEATURES,
            "n_classes": int(len(self.model_classes())),
            "label_space": list(CWE_CLASSES),
            "feature_schema_version": self.feature_schema_version,
            "rename_invariant": True,
        }
        for attribute in ("n_estimators", "max_depth", "learning_rate", "best_iteration"):
            value = getattr(self.model, attribute, None)
            if value is not None:
                info[attribute] = int(value) if isinstance(value, (int, np.integer)) else value
        return info

    def export_header(self, output_path: str) -> str:
        """Export the model to a self-contained C header."""
        from .export import export_c_header

        self._check_ready()
        self.feature_names = list(self.feature_names or FEATURE_NAMES)
        return export_c_header(self, output_path)


def _trace_schema() -> int:
    """Trace schema version, imported lazily to avoid a cycle."""
    from ..trace import SCHEMA_VERSION

    return SCHEMA_VERSION


__all__ = [
    "CWE_CLASSES",
    "CWE_TO_INDEX",
    "MODEL_CONFIG",
    "SchemaMismatch",
    "XGBoostClassifier",
]
