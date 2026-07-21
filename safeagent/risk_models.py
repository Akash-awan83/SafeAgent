"""Hybrid command-risk models inspired by decoupled HC-RLHF cost modelling.

This module implements supervised command-risk classification, not RLHF or
Seldonian optimisation. The deterministic rule model is always retained.
"""
from __future__ import annotations

import json
import math
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .cost_model import RuleBasedCostModel
from .features import FEATURE_NAMES, extract_features, feature_vector
from .models import RiskAssessment, RiskCategory


def _sigmoid(value: float) -> float:
    clipped = max(-35.0, min(35.0, value))
    return 1.0 / (1.0 + math.exp(-clipped))


def _category(score: float) -> RiskCategory:
    if score >= 0.85:
        return RiskCategory.DANGEROUS
    if score >= 0.4:
        return RiskCategory.RISKY
    return RiskCategory.SAFE


_SECURITY_SIGNALS = (
    "recursive_operation",
    "delete_operation",
    "overwrite_operation",
    "privilege_escalation",
    "network_access",
    "download_execute",
    "encoding_technique",
    "suspicious_path",
    "process_termination",
)


def _recognised_safe_operation(command: str, features: dict[str, float]) -> bool:
    """Identify narrow, transparent safe-operation families for ML calibration.

    This does not bypass the cost model: any destructive or security-sensitive
    signal disables the calibration path before it can reduce ML uncertainty.
    """
    if any(features.get(name, 0.0) > 0.0 for name in _SECURITY_SIGNALS):
        return False
    lowered = command.lower()
    return bool(re.match(
        r"\s*(?:"
        r"mkdir|md|touch|"
        r"new-item\b.*?(?:^|\s)-itemtype\s+(?:directory|dir|file)\b|"
        r"ls|dir|pwd|cat|type|get-content|git\s+status|"
        r"pytest|python(?:3)?\s+-m\s+compileall|py\s+-m\s+compileall|"
        r"npm\s+(?:test|run\s+test)|go\s+test|cargo\s+test"
        r")\b",
        lowered,
        flags=re.IGNORECASE | re.DOTALL,
    ))


def _combine_hybrid_risk(rule_score: float, probability: float | None, command: str) -> tuple[float, dict[str, float], tuple[str, ...]]:
    """Combine deterministic severity with ML uncertainty without overriding rules."""
    features = extract_features(command)
    if probability is None:
        factors = ("No learned-model score was available.",)
        return rule_score, features, factors

    if rule_score > 0.0:
        score = 1.0 - (1.0 - rule_score) * (1.0 - probability)
        factors = (
            "A deterministic security rule matched the command.",
            f"Rule severity is {rule_score:.2f}; the learned model reported {probability:.2f}.",
            "The final score preserves deterministic rule severity and cannot be lowered by ML calibration.",
        )
        return score, features, factors

    if _recognised_safe_operation(command, features):
        score = min(probability * 0.25, 0.20)
        factors = (
            "No deterministic destructive pattern matched.",
            "A recognized safe operation type was detected with no security-sensitive feature.",
            f"Moderate ML uncertainty {probability:.2f} was conservatively calibrated to {score:.2f}.",
        )
        return score, features, factors

    if any(features.get(name, 0.0) > 0.0 for name in _SECURITY_SIGNALS):
        score = max(probability, 0.40)
        factors = (
            "No deterministic rule matched, but security-sensitive command features were detected.",
            f"Learned-model risk is {probability:.2f}; final risk remains at least the human-review threshold ({score:.2f}).",
        )
        return score, features, factors

    score = probability if probability >= 0.70 else probability * 0.60
    factors = (
        "No deterministic destructive pattern matched.",
        f"Learned-model uncertainty is {probability:.2f}; calibrated final risk is {score:.2f}.",
        "Moderate ML uncertainty alone does not override deterministic security policy.",
    )
    return score, features, factors


class RiskModel(ABC):
    """Common model interface; XGBoost or neural models can implement this later."""

    @abstractmethod
    def assess(self, command: str) -> RiskAssessment:
        raise NotImplementedError


class RuleBasedRiskModel(RiskModel):
    """Adapter that preserves the existing interpretable rule-based cost model."""

    def __init__(self, model: RuleBasedCostModel | None = None) -> None:
        self.model = model or RuleBasedCostModel()

    def assess(self, command: str) -> RiskAssessment:
        assessment = self.model.assess(command)
        factors = tuple(match.explanation for match in assessment.matches) or ("No destructive command pattern was detected.",)
        return RiskAssessment(
            command=assessment.command,
            score=assessment.score,
            category=assessment.category,
            matches=assessment.matches,
            explanation=assessment.explanation,
            rule_score=assessment.score,
            final_score=assessment.score,
            risk_factors=factors,
        )


@dataclass
class LogisticRegressionClassifier:
    """Small dependency-free logistic-regression classifier for reproducible demos."""

    feature_names: tuple[str, ...] = FEATURE_NAMES
    coefficients: list[float] = field(default_factory=list)
    intercept: float = 0.0
    means: list[float] = field(default_factory=list)
    scales: list[float] = field(default_factory=list)

    @property
    def fitted(self) -> bool:
        return len(self.coefficients) == len(self.feature_names) and bool(self.means) and bool(self.scales)

    def fit(self, commands: list[str], labels: list[int], iterations: int = 900, learning_rate: float = 0.15, l2: float = 0.002) -> "LogisticRegressionClassifier":
        if len(commands) != len(labels) or len(commands) < 2 or not {0, 1}.issubset(set(labels)):
            raise ValueError("Training needs at least two commands with both safe and unsafe labels.")
        vectors = [feature_vector(command) for command in commands]
        width = len(self.feature_names)
        self.means = [sum(row[index] for row in vectors) / len(vectors) for index in range(width)]
        self.scales = [max(1e-6, math.sqrt(sum((row[index] - self.means[index]) ** 2 for row in vectors) / len(vectors))) for index in range(width)]
        normalized = [[(value - self.means[index]) / self.scales[index] for index, value in enumerate(row)] for row in vectors]
        self.coefficients = [0.0] * width
        self.intercept = 0.0
        for _ in range(iterations):
            gradient = [0.0] * width
            intercept_gradient = 0.0
            for row, label in zip(normalized, labels):
                error = _sigmoid(self.intercept + sum(weight * value for weight, value in zip(self.coefficients, row))) - label
                intercept_gradient += error
                for index, value in enumerate(row):
                    gradient[index] += error * value
            count = len(labels)
            self.intercept -= learning_rate * intercept_gradient / count
            self.coefficients = [weight - learning_rate * (gradient[index] / count + l2 * weight) for index, weight in enumerate(self.coefficients)]
        return self

    def predict_proba(self, command: str) -> float:
        if not self.fitted:
            raise RuntimeError("Logistic regression model has not been trained.")
        vector = feature_vector(command)
        normalized = [(value - self.means[index]) / self.scales[index] for index, value in enumerate(vector)]
        return _sigmoid(self.intercept + sum(weight * value for weight, value in zip(self.coefficients, normalized)))

    def save(self, path: str | Path, metadata: dict[str, object] | None = None) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({"model_type": "logistic_regression", "model_version": 1, "feature_names": self.feature_names, "coefficients": self.coefficients, "intercept": self.intercept, "means": self.means, "scales": self.scales, "metadata": metadata or {}}, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "LogisticRegressionClassifier":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if tuple(payload["feature_names"]) != FEATURE_NAMES:
            raise ValueError("Model feature schema does not match this SafeAgent version.")
        return cls(tuple(payload["feature_names"]), list(payload["coefficients"]), float(payload["intercept"]), list(payload["means"]), list(payload["scales"]))


def load_model_metadata(path: str | Path) -> dict[str, object]:
    """Read display metadata without coupling the runtime classifier to dashboards."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return {"model_type": payload.get("model_type", "logistic_regression"), "model_version": payload.get("model_version", 1), **dict(payload.get("metadata", {}))}


class MLRiskModel(RiskModel):
    """Probability model with explicit unavailable state until it is trained and loaded."""

    def __init__(self, classifier: LogisticRegressionClassifier | None = None) -> None:
        self.classifier = classifier

    @property
    def available(self) -> bool:
        return self.classifier is not None and self.classifier.fitted

    def predict_probability(self, command: str) -> float | None:
        return self.classifier.predict_proba(command) if self.available and self.classifier else None

    def assess(self, command: str) -> RiskAssessment:
        probability = self.predict_probability(command)
        if probability is None:
            raise RuntimeError("ML risk model is not trained or loaded.")
        return RiskAssessment(
            command=command,
            score=probability,
            category=_category(probability),
            explanation="The learned command-risk model identified command features requiring review.",
            ml_probability=probability,
            final_score=probability,
            feature_values=extract_features(command),
            risk_factors=(f"Learned-model risk is {probability:.2f}.",),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "MLRiskModel":
        return cls(LogisticRegressionClassifier.load(path))


class HybridRiskModel(RiskModel):
    """Combines rules and ML with a conservative noisy-OR score.

    The ML model can raise risk but never lowers a deterministic rule score.
    """

    def __init__(self, rule_model: RuleBasedRiskModel | None = None, ml_model: MLRiskModel | None = None) -> None:
        self.rule_model = rule_model or RuleBasedRiskModel()
        if ml_model is None:
            model_path = Path(os.getenv("SAFEAGENT_MODEL_PATH", "models/logistic_risk_model.json"))
            ml_model = MLRiskModel.from_file(model_path) if model_path.exists() else MLRiskModel()
        self.ml_model = ml_model

    def assess(self, command: str) -> RiskAssessment:
        rule_assessment = self.rule_model.assess(command)
        probability = self.ml_model.predict_probability(command)
        score, features, factors = _combine_hybrid_risk(rule_assessment.score, probability, command)
        explanation = " ".join(tuple(match.explanation for match in rule_assessment.matches) + factors)
        return RiskAssessment(
            command=command,
            score=score,
            category=_category(score),
            matches=rule_assessment.matches,
            explanation=explanation,
            rule_score=rule_assessment.score,
            ml_probability=probability,
            final_score=score,
            feature_values=features,
            risk_factors=factors,
        )
