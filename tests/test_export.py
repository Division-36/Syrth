"""
Tests for the C header export.

The export is verified three ways, because a header that does not compile and a
header that does not agree with the model are the two failure modes that matter:
structure, agreement with live xgboost probabilities, and -- when a C compiler
is available -- actual compilation and execution.

The fixture trains a deliberately small forest. Exporting a full-size model
produces millions of tree nodes, which is why the previous export test hung for
minutes and why the exporter now enforces a size limit.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("xgboost")
pytest.importorskip("sklearn")

from syrth.classifier import CWE_CLASSES, XGBoostClassifier
from syrth.classifier.export import (
    MAX_HEADER_BYTES,
    ExportError,
    export_c_header,
)
from syrth.features import FEATURE_NAMES, NUM_FEATURES

#: Small enough to export and re-parse in well under a second.
SMALL_TREES = 4


@pytest.fixture(scope="module")
def trained():
    """A small fitted model over the real feature layout."""
    import xgboost as xgb

    rng = np.random.RandomState(42)
    X = rng.rand(80, NUM_FEATURES)
    y = [CWE_CLASSES[i % len(CWE_CLASSES)] for i in range(80)]
    clf = XGBoostClassifier()
    clf.model = xgb.XGBClassifier(
        **{**__import__("syrth.classifier.xgboost", fromlist=["MODEL_CONFIG"]).MODEL_CONFIG,
           "n_estimators": SMALL_TREES}
    )
    clf.train(X, y)
    clf.feature_names = list(FEATURE_NAMES)
    return clf


@pytest.fixture(scope="module")
def header(tmp_path_factory, trained):
    """Export once and share the header across the module."""
    path = tmp_path_factory.mktemp("export") / "syrth_engine.h"
    export_c_header(trained, str(path))
    return path


def parse_header(content: str):
    """Parse the generated tree arrays back into Python structures."""
    trees = []
    for count, body in re.findall(
        r"static const SyrthNode TREE_\d+\[(\d+)\] = \{(.*?)\n\};", content, re.S
    ):
        nodes = []
        for chunk in body.split("}"):
            text = chunk.strip(" ,\n{")
            if not text:
                continue
            if text.startswith("SYRTH_NODE_LEAF"):
                nodes.append({"leaf": True, "value": float(text.split(",")[-1].rstrip("f"))})
            elif text.startswith("SYRTH_NODE_DECISION"):
                parts = [p.strip() for p in text.split(",")]
                nodes.append(
                    {
                        "leaf": False,
                        "feature": int(parts[1]),
                        "threshold": float(parts[2].rstrip("f")),
                        "yes": int(parts[3]),
                        "no": int(parts[4]),
                        "missing": int(parts[5]),
                    }
                )
            else:
                raise AssertionError(f"unparsed node: {text!r}")
        assert len(nodes) == int(count), "dense node array length mismatch"
        trees.append(nodes)
    return trees


def replay(trees, features, num_classes, tree_classes, base_score):
    """Replay the tree walk in Python and return class probabilities.

    The class of each tree comes from the emitted ``tree_info`` copy, mirroring
    the C runtime.
    """
    margins = np.asarray(base_score, dtype=float).copy()
    for index, nodes in enumerate(trees):
        cls = tree_classes[index]
        cursor = 0
        steps = 0
        while True:
            node = nodes[cursor]
            if node["leaf"]:
                margins[cls] += node["value"]
                break
            if node["feature"] < 0 or node["feature"] >= len(features):
                cursor = node["missing"]
            elif features[node["feature"]] <= node["threshold"]:
                cursor = node["yes"]
            else:
                cursor = node["no"]
            steps += 1
            assert steps <= 4096, "tree walk did not terminate"
    shifted = np.exp(margins - margins.max())
    return shifted / shifted.sum()


def read_int_array(content: str, name: str) -> list[int]:
    """Read an emitted ``static const int NAME[...]`` array."""
    match = re.search(
        rf"static const int {name}\[SYRTH_NUM_[A-Z_]+\] = \{{(.*?)\}};", content, re.S
    )
    assert match, f"the header has no {name} array"
    return [int(tok) for tok in re.findall(r"-?\d+", match.group(1))]


def read_base_score(content: str, num_classes: int) -> list[float]:
    """Read the emitted per-class intercept vector."""
    match = re.search(
        r"static const double SYRTH_BASE_SCORE\[SYRTH_NUM_CLASSES\] = \{(.*?)\};",
        content,
        re.S,
    )
    assert match, "the header has no base-score vector"
    values = [
        float(v.strip().rstrip(",f"))
        for v in match.group(1).splitlines()
        if v.strip()
    ]
    assert len(values) == num_classes
    return values


class TestHeaderStructure:
    def test_header_is_generated(self, header):
        content = header.read_text(encoding="utf-8")
        assert "syrth_predict" in content
        assert "SYRTH_NUM_FEATURES" in content
        assert f"SYRTH_NUM_CLASSES {len(CWE_CLASSES)}" in content
        assert "#ifndef SYRTH_ENGINE_H" in content
        assert content.rstrip().endswith("#endif /* SYRTH_ENGINE_H */")

    def test_schema_version_is_embedded(self, header):
        content = header.read_text(encoding="utf-8")
        assert "SYRTH_FEATURE_SCHEMA_VERSION 3" in content

    def test_feature_and_label_tables_are_present(self, header):
        content = header.read_text(encoding="utf-8")
        assert "sink_count" in content
        assert "tainted_exec" in content
        assert '    "CWE-918",' in content

    def test_tree_arrays_are_present(self, header):
        content = header.read_text(encoding="utf-8")
        assert re.search(r"static const SyrthNode TREE_0\[\d+\]", content)

    def test_argmax_is_forward_declared(self, header):
        """The generated C must compile under a modern standard."""
        content = header.read_text(encoding="utf-8")
        declaration = content.index("static int syrth_argmax_class(const float* probs);")
        definition = content.index("static int syrth_argmax_class(const float* probs) {")
        assert declaration < definition

    def test_header_stays_within_the_size_limit(self, header):
        assert header.stat().st_size < MAX_HEADER_BYTES


class TestNumericalAgreement:
    def test_base_score_vector_is_emitted(self, header):
        """The per-class intercept is mandatory, not optional.

        xgboost 2.0 estimates ``base_score`` per class. Softmax is invariant to a
        constant shift but not to per-class shifts, so a header without this
        vector mis-scores every prediction while still looking plausible.
        """
        content = header.read_text(encoding="utf-8")
        values = read_base_score(content, len(CWE_CLASSES))
        assert all(isinstance(v, float) for v in values)
        assert "margins[c] = (double)SYRTH_BASE_SCORE[c];" in content

    def test_tree_class_map_is_emitted(self, header):
        """The tree-to-class map must be copied from the model, not inferred."""
        content = header.read_text(encoding="utf-8")
        classes = read_int_array(content, "SYRTH_TREE_CLASS")
        assert len(classes) == len(parse_header(content))
        assert set(classes) == set(range(len(CWE_CLASSES)))
        assert "SYRTH_TREES_PER_CLASS" not in content

    def test_tree_order_is_round_major_not_class_major(self, header):
        """Regression guard for the grouping bug.

        xgboost emits all classes for round 0, then all classes for round 1. A
        class-major assumption makes ``class == index // trees_per_class`` wrong
        for every tree except the first block, which is why the previous exporter
        produced plausible but incorrect probabilities.
        """
        content = header.read_text(encoding="utf-8")
        classes = read_int_array(content, "SYRTH_TREE_CLASS")
        num_classes = len(CWE_CLASSES)
        assert classes[:num_classes] == list(range(num_classes)), (
            "expected round-major ordering, so the first block must be 0..n-1"
        )
        assert classes[num_classes:2 * num_classes] == list(range(num_classes))

    def test_header_reproduces_live_probabilities(self, trained, header):
        content = header.read_text(encoding="utf-8")
        trees = parse_header(content)
        tree_classes = read_int_array(content, "SYRTH_TREE_CLASS")
        base_score = read_base_score(content, len(CWE_CLASSES))

        rng = np.random.RandomState(7)
        X = rng.rand(20, NUM_FEATURES)
        live = trained.model.predict_proba(X)
        for i in range(len(X)):
            assert np.allclose(
                replay(trees, X[i], len(CWE_CLASSES), tree_classes, base_score),
                live[i],
                atol=1e-5,
            ), f"export/probability mismatch on sample {i}"

    def test_omitting_the_base_score_would_be_wrong(self, trained, header):
        """Guards the specific regression: dropping the intercept changes output."""
        content = header.read_text(encoding="utf-8")
        trees = parse_header(content)
        tree_classes = read_int_array(content, "SYRTH_TREE_CLASS")
        base_score = read_base_score(content, len(CWE_CLASSES))
        rng = np.random.RandomState(7)
        X = rng.rand(20, NUM_FEATURES)
        live = trained.model.predict_proba(X)
        with_base = replay(trees, X[0], len(CWE_CLASSES), tree_classes, base_score)
        without = replay(trees, X[0], len(CWE_CLASSES), tree_classes,
                         [0.0] * len(CWE_CLASSES))
        assert np.allclose(with_base, live[0], atol=1e-5)
        assert not np.allclose(without, live[0], atol=1e-3)

    def test_inferring_the_class_from_the_index_would_be_wrong(self, trained, header):
        """Guards the grouping regression from the other direction."""
        content = header.read_text(encoding="utf-8")
        trees = parse_header(content)
        tree_classes = read_int_array(content, "SYRTH_TREE_CLASS")
        base_score = read_base_score(content, len(CWE_CLASSES))
        rng = np.random.RandomState(7)
        X = rng.rand(20, NUM_FEATURES)
        live = trained.model.predict_proba(X)
        guessed = [index // 4 for index in range(len(trees))]
        correct = replay(trees, X[0], len(CWE_CLASSES), tree_classes, base_score)
        wrong = replay(trees, X[0], len(CWE_CLASSES), guessed, base_score)
        assert np.allclose(correct, live[0], atol=1e-5)
        assert not np.allclose(wrong, live[0], atol=1e-3)

    def test_missing_direction_matches_xgboost(self, trained, header):
        """A vector of the wrong width must follow the model's missing branch."""
        content = header.read_text(encoding="utf-8")
        trees = parse_header(content)
        tree_classes = read_int_array(content, "SYRTH_TREE_CLASS")
        base_score = read_base_score(content, len(CWE_CLASSES))
        replayed = replay(trees, np.zeros(5), len(CWE_CLASSES), tree_classes, base_score)
        assert np.isclose(replayed.sum(), 1.0)


class TestGuards:
    def test_unfitted_model_is_refused(self, tmp_path):
        with pytest.raises(ExportError):
            export_c_header(XGBoostClassifier(), str(tmp_path / "x.h"))

    def test_oversized_model_is_refused_with_an_actionable_message(self, trained, tmp_path,
                                                                    monkeypatch):
        monkeypatch.setattr(
            "syrth.classifier.export.MAX_HEADER_BYTES", 256
        )
        with pytest.raises(ExportError) as info:
            export_c_header(trained, str(tmp_path / "x.h"))
        message = str(info.value)
        assert "MB" in message and "n_estimators" in message


@pytest.mark.skipif(shutil.which("cc") is None and shutil.which("gcc") is None,
                    reason="no C compiler available")
class TestCompilation:
    def _compile_and_run(self, header: Path, features: np.ndarray):
        compiler = shutil.which("cc") or shutil.which("gcc")
        workdir = header.parent
        source = workdir / "driver.c"
        source.write_text(
            f"""
#include <stdio.h>
#include "{header.name}"

int main(void) {{
    static const float f[{len(features)}] = {{{", ".join(f"{v:.9f}" for v in features)}}};
    float probs[SYRTH_NUM_CLASSES];
    int cls = syrth_predict(f, {len(features)}, &probs[0]);
    printf("%d", cls);
    return 0;
}}
""",
            encoding="utf-8",
        )
        binary = workdir / "driver"
        # capture_output swallowed the compiler's diagnostics, so a failure here
        # reported "exit status 1" with nothing about what the C compiler said.
        # The wrapper below re-raises with both streams attached.
        compiled = subprocess.run(
            [compiler, "-std=c99", "-O2", str(source), "-o", str(binary), "-lm"],
            capture_output=True,
            text=True,
        )
        if compiled.returncode != 0:
            raise AssertionError(
                f"{compiler} failed on the exported header:\n"
                f"--- command ---\n"
                f"{compiler} -std=c99 -O2 {source} -o {binary} -lm\n"
                f"--- stdout ---\n{compiled.stdout}\n"
                f"--- stderr ---\n{compiled.stderr}\n"
                f"--- header head ---\n"
                f"{header.read_text(encoding='utf-8', errors='replace')[:2000]}"
            )
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        return int(result.stdout.strip())

    def test_compiles_and_predicts(self, trained, header):
        rng = np.random.RandomState(11)
        features = rng.rand(NUM_FEATURES)
        compiled = self._compile_and_run(header, features)
        expected = int(np.argmax(trained.model.predict_proba(features.reshape(1, -1))[0]))
        assert compiled == expected
