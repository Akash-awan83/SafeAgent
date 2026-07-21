"""Dataset loading and transparent binary-classification metrics."""
from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClassificationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positives: int
    false_negatives: int
    true_positives: int
    true_negatives: int

    def as_dict(self) -> dict[str, float | int]:
        return self.__dict__.copy()


def load_labeled_commands(path: str | Path) -> tuple[list[str], list[int]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or not {"command", "is_unsafe"}.issubset(rows[0]):
        raise ValueError("Dataset needs command and is_unsafe columns.")
    commands = [str(row["command"]) for row in rows]
    labels = [int(str(row["is_unsafe"]).strip().lower() in {"1", "true", "yes"}) for row in rows]
    if not {0, 1}.issubset(labels):
        raise ValueError("Dataset needs both safe and unsafe labels.")
    return commands, labels


def stratified_split(commands: list[str], labels: list[int], validation_fraction: float = 0.25, seed: int = 7) -> tuple[list[str], list[int], list[str], list[int]]:
    if not 0 < validation_fraction < 0.5:
        raise ValueError("validation_fraction must be between 0 and 0.5.")
    groups = {0: [], 1: []}
    for command, label in zip(commands, labels):
        groups[label].append(command)
    randomizer = random.Random(seed)
    train_commands: list[str] = []
    train_labels: list[int] = []
    validation_commands: list[str] = []
    validation_labels: list[int] = []
    for label, group in groups.items():
        randomizer.shuffle(group)
        validation_count = max(1, round(len(group) * validation_fraction))
        for command in group[:validation_count]:
            validation_commands.append(command)
            validation_labels.append(label)
        for command in group[validation_count:]:
            train_commands.append(command)
            train_labels.append(label)
    return train_commands, train_labels, validation_commands, validation_labels


def classification_metrics(labels: list[int], probabilities: list[float], threshold: float = 0.5) -> ClassificationMetrics:
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("Metrics require equally sized non-empty labels and probabilities.")
    predictions = [int(probability >= threshold) for probability in probabilities]
    tp = sum(prediction == 1 and label == 1 for prediction, label in zip(predictions, labels))
    tn = sum(prediction == 0 and label == 0 for prediction, label in zip(predictions, labels))
    fp = sum(prediction == 1 and label == 0 for prediction, label in zip(predictions, labels))
    fn = sum(prediction == 0 and label == 1 for prediction, label in zip(predictions, labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return ClassificationMetrics((tp + tn) / len(labels), precision, recall, 2 * precision * recall / (precision + recall) if precision + recall else 0.0, fp, fn, tp, tn)
