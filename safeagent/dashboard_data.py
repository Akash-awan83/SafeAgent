from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
from typing import Any

from .logging_store import JsonlAuditLog


def load_records(path: str | Path) -> list[dict[str, Any]]:
    return list(JsonlAuditLog(path).records())


def summary(records: list[dict[str, Any]]) -> dict[str, int]:
    categories = Counter(row.get("category") for row in records)
    decisions = Counter(row.get("decision") for row in records)
    intent_scores: list[float] = []
    rollback_ready = 0
    for row in records:
        verification = row.get("intent_verification")
        if isinstance(verification, dict):
            try:
                score = float(verification.get("intent_match_score"))
                if math.isfinite(score):
                    intent_scores.append(min(1.0, max(0.0, score)))
            except (TypeError, ValueError):
                pass
        preview = row.get("execution_preview")
        if isinstance(preview, dict) and isinstance(preview.get("rollback"), dict):
            rollback_ready += preview["rollback"].get("status") in {"AVAILABLE", "READY", "LIMITED"}
    return {
        "total": len(records),
        "safe": categories["SAFE"],
        "risky": categories["RISKY"],
        "dangerous": categories["DANGEROUS"],
        "executed": sum(bool(row.get("executed")) for row in records),
        "cancelled": decisions["CANCELLED"],
        "user_approved": sum(row.get("user_response") == "Approved" for row in records),
        "blocked_errors": decisions["BLOCKED_ERROR"],
        "blocked_policy": decisions["BLOCKED_POLICY"],
        "intent_verified": len(intent_scores),
        "intent_blocked": decisions["BLOCKED_INTENT"],
        "rollback_ready": rollback_ready,
        "intent_match_percent": round((sum(intent_scores) / len(intent_scores)) * 100) if intent_scores else 0,
    }
