"""Evaluate a previously trained SafeAgent command-risk model."""
from __future__ import annotations

import argparse
import json

from safeagent.ml_pipeline import classification_metrics, load_labeled_commands
from safeagent.risk_models import LogisticRegressionClassifier


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the SafeAgent logistic command-risk model")
    parser.add_argument("--dataset", default="data/training.csv")
    parser.add_argument("--model", default="models/logistic_risk_model.json")
    args = parser.parse_args()
    commands, labels = load_labeled_commands(args.dataset)
    classifier = LogisticRegressionClassifier.load(args.model)
    metrics = classification_metrics(labels, [classifier.predict_proba(command) for command in commands])
    print(json.dumps(metrics.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
