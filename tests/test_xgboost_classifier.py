"""
Tests for the optional XGBoost ranker.

The ranker is an *additive* component: it refines the probability of a flow the
analysis has already confirmed, and can neither create nor delete a finding.
These tests cover the parts of that contract which are easy to get wrong --
schema guards, label-space guards, and the degraded path -- plus ordinary
fit/predict behaviour.
"""

from __future__ import annotations

import numpy as np
import pytest

from syrth.classifier import CWE_CLASSES
from syrth.classifier.xgboost import MODEL_CONFIG, SchemaMismatch, XGBoostClassifier
from syrth.features import FEATURE_NAMES, NUM_FEATURES
from syrth.registry import CATEGORY_CWE

xgb = pytest.importorskip("xgboost")
pytest.importorskip("sklearn")


def make_dataset(n_per_class: int = 24, seed: int = 0):
    """Build a separable synthetic dataset over the real feature layout."""
    rng = np.random.RandomState(seed)
    X, y = [], []
    for index, _cwe in enumerate(CWE_CLASSES):
        for _ in range(n_per_class):
            row = rng.rand(NUM_FEATURES) * 0.15
            # Give each class a distinctive, legal feature signature.
            for offset in range(index, NUM_FEATURES, len(CWE_CLASSES)):
                row[offset] = 0.8
            X.append(row)
            y.append(_cwe)
    return np.asarray(X), y


class TestTraining:
    def test_fit_and_score(self):
        X, y = make_dataset()
        clf = XGBoostClassifier()
        metrics = clf.train(X, y)
        assert metrics["n_features"] == NUM_FEATURES
        assert metrics["feature_schema_version"] == 3
        assert clf.is_fitted()

    def test_predict_returns_label_indices_in_cwe_order(self):
        X, y = make_dataset()
        clf = XGBoostClassifier()
        clf.train(X, y)
        indices, probabilities = clf.predict(X[:5])
        assert len(indices) == 5
        assert probabilities.shape[0] == 5
        assert probabilities.shape[1] == len(CWE_CLASSES)
        assert probabilities.sum(axis=1) == pytest.approx(np.ones(5), abs=1e-6)

    def test_predict_single_shape(self):
        X, y = make_dataset()
        clf = XGBoostClassifier()
        clf.train(X, y)
        out = clf.predict_single(X[0])
        assert out["predicted_cwe"] in CWE_CLASSES
        assert 0.0 <= out["confidence"] <= 1.0
        assert len(out["top_predictions"]) == 3
        assert out["feature_importance"]

    def test_evaluate_reports_weighted_and_macro(self):
        X, y = make_dataset()
        clf = XGBoostClassifier()
        clf.train(X, y)
        scores = clf.evaluate(X, y)
        assert 0.0 <= scores["accuracy"] <= 1.0
        assert "f1_macro" in scores and "f1_weighted" in scores

    def test_label_string_and_integer_paths_agree(self):
        X, y = make_dataset()
        as_strings = XGBoostClassifier()
        as_strings.train(X, y)
        as_indices = XGBoostClassifier()
        as_indices.train(X, [CWE_CLASSES.index(label) for label in y])
        assert as_strings.predict_single(X[0])["predicted_cwe"] == (
            as_indices.predict_single(X[0])["predicted_cwe"]
        )


class TestGuards:
    def test_wrong_feature_width_is_refused_at_training(self):
        clf = XGBoostClassifier()
        with pytest.raises(ValueError):
            clf.train(np.zeros((4, 7)), ["CWE-89"] * 4)

    def test_wrong_feature_width_is_refused_at_prediction(self):
        X, y = make_dataset(n_per_class=4)
        clf = XGBoostClassifier()
        clf.train(X, y)
        with pytest.raises(SchemaMismatch):
            clf.predict(np.zeros((2, 5)))

    def test_untrained_prediction_raises(self):
        clf = XGBoostClassifier()
        with pytest.raises(ValueError):
            clf.predict_single(np.zeros(NUM_FEATURES))

    def test_label_space_is_generated_from_the_registry(self):
        assert CWE_CLASSES == [CATEGORY_CWE[category] for category in CATEGORY_CWE]
        assert len(set(CWE_CLASSES)) == len(CWE_CLASSES)

    def test_model_config_targets_cpu_histogram_boosting(self):
        assert MODEL_CONFIG["tree_method"] == "hist"
        assert MODEL_CONFIG["objective"] == "multi:softprob"
        assert MODEL_CONFIG["num_class"] == len(CWE_CLASSES)


class TestPersistence:
    def test_round_trip(self, tmp_path):
        X, y = make_dataset(n_per_class=6)
        clf = XGBoostClassifier()
        clf.train(X, y)
        clf.feature_names = list(FEATURE_NAMES)
        path = str(tmp_path / "m.joblib")
        clf.save_model(path)
        restored = XGBoostClassifier(model_path=path)
        assert restored.is_fitted()
        assert restored.get_model_info()["n_features"] == NUM_FEATURES

    def test_bundle_records_rename_invariance(self, tmp_path):
        X, y = make_dataset(n_per_class=4)
        clf = XGBoostClassifier()
        clf.train(X, y)
        path = str(tmp_path / "m.joblib")
        clf.save_model(path)
        assert XGBoostClassifier(model_path=path).get_model_info()["rename_invariant"]

    def test_missing_model_raises(self):
        with pytest.raises(FileNotFoundError):
            XGBoostClassifier(model_path="does-not-exist.joblib")

    def test_bundle_with_a_foreign_label_space_is_refused(self, tmp_path):
        import joblib

        X, y = make_dataset(n_per_class=4)
        clf = XGBoostClassifier()
        clf.train(X, y)
        path = tmp_path / "m.joblib"
        clf.save_model(str(path))
        bundle = joblib.load(path)
        bundle["cwe_classes"] = ["CWE-1", "CWE-2"]
        joblib.dump(bundle, path)
        with pytest.raises(SchemaMismatch) as info:
            XGBoostClassifier(model_path=str(path))
        assert "label space" in str(info.value)

    def test_bundle_with_a_foreign_schema_version_is_refused(self, tmp_path):
        import joblib

        X, y = make_dataset(n_per_class=4)
        clf = XGBoostClassifier()
        clf.train(X, y)
        path = tmp_path / "m.joblib"
        clf.save_model(str(path))
        bundle = joblib.load(path)
        bundle["feature_schema_version"] = 1
        joblib.dump(bundle, path)
        with pytest.raises(SchemaMismatch) as info:
            XGBoostClassifier(model_path=str(path))
        assert "feature schema" in str(info.value)
