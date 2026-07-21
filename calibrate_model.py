"""Run held-out certification; this script never trains on calibration data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from safeagent.certification import certify_from_csv
from safeagent.risk_models import HybridRiskModel, MLRiskModel


def main() -> int:
    parser = argparse.ArgumentParser(description="Certify a SafeAgent model against held-out data")
    parser.add_argument("--calibration", default="data/calibration.csv")
    parser.add_argument("--model", default="models/logistic_risk_model.json")
    parser.add_argument("--threshold", type=float, default=0.05)
    parser.add_argument("--delta", type=float, default=0.05)
    args = parser.parse_args()
    ml_model = MLRiskModel.from_file(args.model) if Path(args.model).exists() else MLRiskModel()
    result = certify_from_csv(args.calibration, HybridRiskModel(ml_model=ml_model), args.threshold, args.delta)
    print(json.dumps(result.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
