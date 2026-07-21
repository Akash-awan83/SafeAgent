"""Train SafeAgent's logistic command-risk model on non-calibration data."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from safeagent.ml_pipeline import classification_metrics, load_labeled_commands, stratified_split
from safeagent.risk_models import LogisticRegressionClassifier


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the SafeAgent logistic command-risk model")
    parser.add_argument("--dataset", default="data/training.csv")
    parser.add_argument("--model-out", default="models/logistic_risk_model.json")
    args = parser.parse_args()
    commands, labels = load_labeled_commands(args.dataset)
    train_commands, train_labels, validation_commands, validation_labels = stratified_split(commands, labels)
    classifier = LogisticRegressionClassifier().fit(train_commands, train_labels)
    probabilities = [classifier.predict_proba(command) for command in validation_commands]
    metrics = classification_metrics(validation_labels, probabilities).as_dict()
    metadata = {"trained_at": datetime.now(timezone.utc).isoformat(), "training_samples": len(train_commands), "validation_samples": len(validation_commands), "validation_metrics": metrics}
    classifier.save(args.model_out, metadata)
    print(json.dumps({"model": args.model_out, **metadata}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
