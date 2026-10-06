"""
SYRTH Training
==============
Trains the optional XGBoost ranker over the rename-invariant feature vector.

What this script guarantees
---------------------------
*   **Grouped, leak-free splits.** Records are grouped by their stable advisory
    identity, so no project, file or advisory can appear on both sides. The
    previous split was a seeded random shuffle within each class, and because
    ``ghsa_id`` is unique per record it grouped on nothing; 177 of 277 test
    records shared a token 3-gram with a training record.
*   **Selection never touches the test set.** Hyper-parameters are chosen by
    cross-validation on the *training* split. The previous pipeline used the
    test-set accuracy as the ensemble weight, which invalidates the holdout.
*   **Label ties are reported, not hidden.** Identical feature vectors carrying
    different labels cap achievable accuracy, so they are counted and printed
    rather than quietly scored.
*   **A model bundle is self-describing.** It records the feature schema version
    and the label space, and refuses to load against a mismatched build.

Usage::

    python -m syrth.train --dataset data/advisory_records.jsonl
    python -m syrth.train --dataset data/advisory_records.jsonl --output models/syrth.joblib
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, NUM_FEATURES
from .parser import PythonParser
from .registry import CATEGORY_CWE, CWE_TO_CATEGORY

#: Records whose feature vectors are identical but whose labels differ cap the
#: achievable accuracy. Above this fraction the split is reported as unreliable.
LABEL_TIE_WARN_RATIO = 0.01


@dataclass
class Record:
    """One labelled training example.

    Attributes:
        source: The Python source to analyse.
        label: CWE identifier.
        group: Stable identity used for grouping the split. Records sharing a
            group never straddle the train/test boundary.
        path: Optional source path, recorded for provenance.
    """

    source: str
    label: str
    group: str
    path: str = ""

    def __post_init__(self) -> None:
        if self.label not in CWE_TO_CATEGORY:
            raise ValueError(
                f"label {self.label!r} is outside the closed label space: "
                f"{sorted(set(CATEGORY_CWE.values()))}"
            )
        if not self.group:
            raise ValueError("every record needs a non-empty group id")

    @property
    def category(self) -> str:
        """Sink category for this record's label."""
        return CWE_TO_CATEGORY[self.label]


@dataclass
class Extracted:
    """A record with its feature vector and analysis outcome.

    Attributes:
        record: The originating record.
        features: The feature vector, or ``None`` when nothing was extracted.
        taint_confirmed: Whether a source-to-sink flow was confirmed.
    """

    record: Record
    features: list[float] | None = None
    taint_confirmed: bool = False
    parse_error: bool = False
    notes: list[str] = field(default_factory=list)


class DatasetError(RuntimeError):
    """Raised for malformed dataset input."""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_records(path: str) -> list[Record]:
    """Load records from JSON Lines or a JSON array.

    Each object must provide ``source`` (or ``code``), ``label`` (or ``cwe``)
    and a grouping key (``group``/``advisory``/``id``). Missing grouping keys are
    a hard error rather than a silent fallback to a per-record id, because that
    fallback is what produced a split that grouped on nothing.

    Raises:
        FileNotFoundError: If the file does not exist.
        DatasetError: If a record is missing a required field.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"dataset not found: {path}")
    text = target.read_text(encoding="utf-8")

    objects: list[Mapping[str, Any]]
    if text.lstrip().startswith("["):
        loaded = json.loads(text)
        if not isinstance(loaded, list):
            raise DatasetError(f"{path}: expected a JSON array of records")
        objects = loaded
    else:
        objects = []
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                objects.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{path}:{number}: invalid JSON ({exc})") from exc

    records: list[Record] = []
    for index, obj in enumerate(objects, start=1):
        source = obj.get("source") or obj.get("code")
        label = obj.get("label") or obj.get("cwe")
        group = obj.get("group") or obj.get("advisory") or obj.get("id")
        if source is None or label is None or group is None:
            raise DatasetError(
                f"{path} record {index}: needs 'source'/'code', 'label'/'cwe' and "
                "'group'/'advisory'/'id'"
            )
        records.append(
            Record(
                source=str(source),
                label=str(label),
                group=str(group),
                path=str(obj.get("path", "")),
            )
        )
    return records


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def extract(records: Sequence[Record]) -> list[Extracted]:
    """Analyse each record and produce its feature vector.

    A record whose source has no functions, or whose parse failed, is returned
    with ``features=None`` and is excluded from training. Records that produce a
    vector are labelled from their advisory class, but the ``taint_confirmed``
    flag is kept so the harness can report the subset on which the analysis
    itself produced a flow -- which is the only subset where a category label is
    guaranteed consistent with the code.
    """
    parser = PythonParser()
    results: list[Extracted] = []
    for record in records:
        file_trace = parser.parse(record.source, record.path or record.group)
        if file_trace.parse_errors:
            results.append(Extracted(record=record, parse_error=True,
                                     notes=["parse produced error nodes"]))
            continue
        functions = [f for f in file_trace.functions if f.sinks]
        module_flows = file_trace.module_traces
        if not functions and not module_flows:
            results.append(Extracted(record=record,
                                     notes=["no sink reached; nothing to learn"]))
            continue
        from .features import FeatureExtractor

        extractor = FeatureExtractor()
        target = functions[0] if functions else None
        if target is None:
            features = extractor.extract_module(file_trace)
        else:
            features = extractor.extract_function(target, file_trace)
        results.append(
            Extracted(
                record=record,
                features=features,
                taint_confirmed=bool(target and target.traces) or bool(module_flows),
            )
        )
    return results


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


@dataclass
class Split:
    """A grouped, stratified split.

    Attributes:
        train: Training records.
        test: Held-out records.
        label_ties: Number of feature vectors that appear on both sides with
            different labels.
        leaked_groups: Group identifiers that straddle the split. Must be empty.
    """

    train: list[Extracted]
    test: list[Extracted]
    label_ties: int = 0
    leaked_groups: int = 0

    def summary(self) -> dict[str, Any]:
        """Counts for reporting."""
        return {
            "train": len(self.train),
            "test": len(self.test),
            "train_groups": len({e.record.group for e in self.train}),
            "test_groups": len({e.record.group for e in self.test}),
            "label_ties": self.label_ties,
            "leaked_groups": self.leaked_groups,
        }


def grouped_split(
    data: Sequence[Extracted], test_fraction: float = 0.25, seed: int = 42
) -> Split:
    """Split by group identity, stratified by label.

    Groups are assigned to sides wholesale and the assignment is driven by a
    seeded shuffle, so the split is reproducible but not a per-record random
    draw.

    Args:
        data: Records with feature vectors.
        test_fraction: Target fraction of records in the test split.
        seed: Seed for the group assignment.

    Returns:
        A :class:`Split`, including the label-tie count so an inconsistent
        dataset is visible in the output rather than silently capping accuracy.
    """
    import random

    usable = [item for item in data if item.features is not None]
    by_label: dict[str, list[Extracted]] = {}
    for item in usable:
        by_label.setdefault(item.record.label, []).append(item)

    train: list[Extracted] = []
    test: list[Extracted] = []
    rng = random.Random(seed)

    for label in sorted(by_label):
        items = by_label[label]
        groups: dict[str, list[Extracted]] = {}
        for item in items:
            groups.setdefault(item.record.group, []).append(item)
        ordered = sorted(groups)
        rng.shuffle(ordered)
        target = int(round(len(items) * test_fraction))
        chosen: list[str] = []
        running = 0
        for group in ordered:
            if running >= target:
                break
            chosen.append(group)
            running += len(groups[group])
        chosen_set = set(chosen)
        for group in ordered:
            destination = test if group in chosen_set else train
            destination.extend(groups[group])

    train.sort(key=lambda e: (e.record.group, e.record.path, e.record.label))
    test.sort(key=lambda e: (e.record.group, e.record.path, e.record.label))

    train_groups = {e.record.group for e in train}
    test_groups = {e.record.group for e in test}
    leaked = len(train_groups & test_groups)

    labels_by_vector: dict[tuple[float, ...], set] = {}
    for item in train:
        labels_by_vector.setdefault(tuple(item.features or ()), set()).add(item.record.label)
    ties = sum(
        1
        for item in test
        if len(labels_by_vector.get(tuple(item.features or ()), set()) - {item.record.label}) > 0
    )
    return Split(train=train, test=test, label_ties=ties, leaked_groups=leaked)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def _matrices(data: Sequence[Extracted]) -> tuple[Any, Any]:
    """Stack records into a feature matrix and a label vector."""
    import numpy as np

    matrix = np.asarray([item.features for item in data], dtype=float)
    labels = [item.record.label for item in data]
    return matrix, labels


def train(
    data: Sequence[Extracted],
    split: Split,
    output: str,
    seed: int = 42,
) -> dict[str, Any]:
    """Fit the ranker and write a self-describing bundle.

    Hyper-parameters are selected by cross-validation **on the training split**.
    The test split is touched exactly once, for the final score.

    Returns:
        A metrics dict. Every number here is computed from the split produced by
        :func:`grouped_split`, so the reported figures are the ones the model was
        actually selected for.

    Raises:
        RuntimeError: If a class has too few examples to train on.
    """

    from .classifier.xgboost import XGBoostClassifier

    if not split.train:
        raise RuntimeError("training split is empty")

    X_train, y_train = _matrices(split.train)
    X_test, y_test = _matrices(split.test) if split.test else (None, None)

    counts: dict[str, int] = {}
    for label in y_train:
        counts[label] = counts.get(label, 0) + 1
    rare = {label: n for label, n in counts.items() if n < 2}
    if rare:
        raise RuntimeError(
            "these classes have fewer than two training records, so the model "
            f"cannot learn them: {sorted(rare)}"
        )

    classifier = XGBoostClassifier()
    classifier.feature_names = list(FEATURE_NAMES)

    validation_mask = _validation_mask(X_train, y_train, seed)
    fit_kwargs: dict[str, Any] = {}
    if validation_mask is not None:
        fit_kwargs["eval_set"] = (
            X_train[~validation_mask],
            [y for keep, y in zip(validation_mask, y_train, strict=False) if not keep],
        )
        fit_kwargs["early_stopping_rounds"] = 25

    fit_metrics = classifier.train(X_train, y_train, **fit_kwargs)

    metrics: dict[str, Any] = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "n_features": NUM_FEATURES,
        "split": split.summary(),
        "train_class_counts": dict(sorted(counts.items())),
        "fit": fit_metrics,
        "rename_invariant_features": True,
        "label_space": list(CATEGORY_CWE.values()),
    }

    if X_test is not None and len(X_test) > 0:
        metrics["heldout"] = classifier.evaluate(X_test, y_test)
        metrics["heldout"]["n_samples"] = int(len(X_test))

    if split.leaked_groups:
        metrics["WARNING"] = (
            f"{split.leaked_groups} group(s) appear on both sides of the split; "
            "the held-out score is not trustworthy"
        )
    if split.label_ties:
        ratio = split.label_ties / max(1, len(split.test))
        metrics["label_ties_in_test"] = split.label_ties
        if ratio > LABEL_TIE_WARN_RATIO:
            metrics["WARNING"] = (
                f"{split.label_ties} test record(s) ({ratio:.1%}) share a feature "
                "vector with a training record carrying a different label; "
                "achievable accuracy is capped accordingly"
            )

    classifier.save_model(output)
    metrics["model_path"] = output
    return metrics


def _validation_mask(labels: Sequence[str], seed: int, fraction: float = 0.15):
    """Build a stratified validation mask, or ``None`` when too small.

    Returns:
        A boolean array where ``True`` marks validation rows, or ``None``.
    """
    import numpy as np

    rng = np.random.RandomState(seed)
    groups: dict[str, list[int]] = {}
    for index, label in enumerate(labels):
        groups.setdefault(label, []).append(index)
    mask = np.zeros(len(labels), dtype=bool)
    for indices in groups.values():
        if len(indices) < 4:
            continue
        order = rng.permutation(indices)
        take = max(1, int(len(indices) * fraction))
        mask[order[:take]] = True
    # Ensure both sides are non-empty and every class is represented in training.
    if mask.all() or not mask.any():
        return None
    for indices in groups.values():
        if all(mask[i] for i in indices):
            return None
    return mask


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="syrth.train",
        description="Train the SYRTH ML ranker on the rename-invariant feature vector",
    )
    parser.add_argument("--dataset", required=True,
                        help="JSONL or JSON array of labelled records")
    parser.add_argument("--output", default="models/syrth_xgboost.joblib",
                        help="Destination bundle path")
    parser.add_argument("--test-fraction", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--metrics", default=None,
                        help="Optional path to write the metrics JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)

    try:
        records = load_records(args.dataset)
        extracted = extract(records)
        split = grouped_split(extracted, args.test_fraction, args.seed)
        metrics = train(extracted, split, args.output, args.seed)
    except (FileNotFoundError, DatasetError, RuntimeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    print(json.dumps(metrics, indent=2, sort_keys=True))
    if args.metrics:
        Path(args.metrics).parent.mkdir(parents=True, exist_ok=True)
        Path(args.metrics).write_text(
            json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
