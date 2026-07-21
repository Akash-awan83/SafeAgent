"""Held-out Hoeffding certification for unsafe approvals."""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path

from .models import RiskCategory


@dataclass(frozen=True)
class CertificationResult:
    samples: int
    unsafe_approvals: int
    observed_unsafe_approval_rate: float
    upper_confidence_bound: float
    delta: float
    threshold: float
    certified: bool


def certify_from_csv(path: str | Path, model: object, threshold: float = 0.05, delta: float = 0.05) -> CertificationResult:
    """Certify only against labels in a held-out CSV: command,is_unsafe."""
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or not {"command", "is_unsafe"}.issubset(rows[0]):
        raise ValueError("Calibration CSV needs command and is_unsafe columns.")
    unsafe_approvals = sum(
        row["is_unsafe"].strip().lower() in {"1", "true", "yes"}
        and getattr(model, "assess")(row["command"]).category is RiskCategory.SAFE
        for row in rows
    )
    n = len(rows)
    observed = unsafe_approvals / n
    upper = min(1.0, observed + math.sqrt(math.log(1 / delta) / (2 * n)))
    return CertificationResult(n, unsafe_approvals, observed, upper, delta, threshold, upper <= threshold)
