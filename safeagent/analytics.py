"""Small, dependency-light analytics helpers used by the safety dashboard."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .ml_pipeline import classification_metrics, load_labeled_commands
from .risk_models import LogisticRegressionClassifier, load_model_metadata


def _curve_points(labels: list[int], probabilities: list[float]) -> tuple[list[dict[str, float]], list[dict[str, float]]]:
    roc: list[dict[str, float]] = []
    precision_recall: list[dict[str, float]] = []
    for index in range(21):
        threshold = index / 20
        metrics = classification_metrics(labels, probabilities, threshold)
        false_positive_rate = metrics.false_positives / (metrics.false_positives + metrics.true_negatives) if metrics.false_positives + metrics.true_negatives else 0.0
        roc.append({"threshold": threshold, "false_positive_rate": false_positive_rate, "true_positive_rate": metrics.recall})
        precision_recall.append({"threshold": threshold, "precision": metrics.precision, "recall": metrics.recall})
    return roc, precision_recall


def model_diagnostics(model_path: str | Path, dataset_path: str | Path) -> dict[str, Any] | None:
    """Compute transparent diagnostics only when a saved model and labelled data exist."""
    if not Path(model_path).exists() or not Path(dataset_path).exists():
        return None
    classifier = LogisticRegressionClassifier.load(model_path)
    commands, labels = load_labeled_commands(dataset_path)
    probabilities = [classifier.predict_proba(command) for command in commands]
    metrics = classification_metrics(labels, probabilities)
    roc, precision_recall = _curve_points(labels, probabilities)
    importance = sorted(
        ({"feature": name, "coefficient": coefficient, "absolute_importance": abs(coefficient)} for name, coefficient in zip(classifier.feature_names, classifier.coefficients)),
        key=lambda item: item["absolute_importance"],
        reverse=True,
    )
    return {
        "metadata": load_model_metadata(model_path),
        "metrics": metrics.as_dict(),
        "roc": roc,
        "precision_recall": precision_recall,
        "feature_importance": importance,
        "confusion_matrix": [
            {"actual": "Safe", "predicted": "Safe", "count": metrics.true_negatives},
            {"actual": "Safe", "predicted": "Unsafe", "count": metrics.false_positives},
            {"actual": "Unsafe", "predicted": "Safe", "count": metrics.false_negatives},
            {"actual": "Unsafe", "predicted": "Unsafe", "count": metrics.true_positives},
        ],
    }


def risk_heatmap(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], int] = {}
    for record in records:
        key = (str(record.get("category", "Unknown")), str(record.get("decision", "Unknown")))
        grouped[key] = grouped.get(key, 0) + 1
    return [{"risk_category": category, "decision": decision, "count": count} for (category, decision), count in grouped.items()]
