from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .action_verification import ActionVerification


class RiskCategory(str, Enum):
    SAFE = "SAFE"
    RISKY = "RISKY"
    DANGEROUS = "DANGEROUS"


class Decision(str, Enum):
    AUTO_ALLOWED = "AUTO_ALLOWED"
    USER_CONFIRMATION = "USER_CONFIRMATION"
    CANCELLED = "CANCELLED"
    BLOCKED_INTENT = "BLOCKED_INTENT"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_ERROR = "BLOCKED_ERROR"


@dataclass(frozen=True)
class Match:
    rule_id: str
    score: float
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    command: str
    score: float
    category: RiskCategory
    matches: list[Match] = field(default_factory=list)
    explanation: str = "No destructive command pattern was detected."
    rule_score: float | None = None
    ml_probability: float | None = None
    final_score: float | None = None
    feature_values: dict[str, float] = field(default_factory=dict)
    risk_factors: tuple[str, ...] = ()
    verification: ActionVerification | None = None


@dataclass(frozen=True)
class Advisory:
    explanation: str
    safer_alternative: str | None = None
    source: str = "AI-generated"


@dataclass
class GateResult:
    assessment: RiskAssessment
    decision: Decision
    executed: bool = False
    execution_result: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    user_response: str | None = None
    advisory: Advisory | None = None
    error: str | None = None
    approval_time_ms: float | None = None
    execution_time_ms: float | None = None
    execution_command: str | None = None

    def to_log_record(self) -> dict[str, Any]:
        verification = None if self.assessment.verification is None else self.assessment.verification.to_dict()
        return {
            "command": self.assessment.command,
            "risk_score": self.assessment.score,
            "rule_score": self.assessment.rule_score,
            "ml_probability": self.assessment.ml_probability,
            "final_score": self.assessment.final_score if self.assessment.final_score is not None else self.assessment.score,
            "category": self.assessment.category.value,
            "decision": self.decision.value,
            "reason": self.assessment.explanation,
            "matched_rules": [item.rule_id for item in self.assessment.matches],
            "rule_detections": [{"id": item.rule_id, "score": item.score, "explanation": item.explanation} for item in self.assessment.matches],
            "feature_values": self.assessment.feature_values,
            "risk_factors": list(self.assessment.risk_factors),
            "intent_verification": None if verification is None else verification["intent"],
            "execution_preview": None if verification is None else verification["execution_preview"],
            "user_response": self.user_response,
            "executed": self.executed,
            "execution_result": self.execution_result,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_command": self.execution_command,
            "approval_time_ms": self.approval_time_ms,
            "execution_time_ms": self.execution_time_ms,
            "advisory": None
            if self.advisory is None
            else {
                "source": self.advisory.source,
                "explanation": self.advisory.explanation,
                "safer_alternative": self.advisory.safer_alternative,
            },
            "error": self.error,
        }
