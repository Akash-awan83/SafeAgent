from __future__ import annotations

import subprocess
from time import perf_counter
from collections.abc import Callable
from dataclasses import replace

from .action_verification import ActionVerification, RollbackGuardian, enrich_assessment, preview_action
from .advisory import OpenAIAdvisoryProvider
from .execution import PlatformShellExecutor, normalize_safe_command
from .logging_store import JsonlAuditLog
from .models import Advisory, Decision, GateResult, RiskAssessment, RiskCategory
from .risk_models import HybridRiskModel, RiskModel

Confirm = Callable[[RiskAssessment, Advisory | None], bool]
Executor = Callable[[str], subprocess.CompletedProcess[str]]


class SafetyGate:
    def __init__(self, model: RiskModel | None = None, audit_log: JsonlAuditLog | None = None, advisory_provider: OpenAIAdvisoryProvider | None = None, executor: Executor | None = None, rollback_guardian: RollbackGuardian | None = None) -> None:
        self.model = model or HybridRiskModel()
        self.audit_log = audit_log or JsonlAuditLog()
        self.advisory_provider = advisory_provider or OpenAIAdvisoryProvider()
        self.executor = executor or PlatformShellExecutor()
        self.rollback_guardian = rollback_guardian or RollbackGuardian()

    def evaluate(self, command: str, confirm: Confirm | None = None, execute: bool = False, user_request: str | None = None) -> GateResult:
        try:
            # Logging is a required component, so verify it before approval or execution.
            self.audit_log.probe()
            assessment = enrich_assessment(self.model.assess(command), user_request)
            verification = assessment.verification
            if any(match.rule_id == "download_and_execute" for match in assessment.matches):
                # Downloaded code piped straight to an interpreter is an explicit
                # non-interactive policy boundary, not a command to approve later.
                result = GateResult(
                    assessment,
                    Decision.BLOCKED_POLICY,
                    user_response="Not requested",
                )
                self.audit_log.append(result)
                return result
            if verification is not None and verification.intent.decision == "BLOCK":
                result = GateResult(
                    assessment,
                    Decision.BLOCKED_INTENT,
                    user_response="Not requested",
                )
                self.audit_log.append(result)
                return result
            needs_intent_confirmation = verification is not None and verification.intent.decision == "CONFIRM"
            advisory = self.advisory_provider.explain(assessment) if assessment.category is not RiskCategory.SAFE else None
            if assessment.category is RiskCategory.SAFE and not needs_intent_confirmation:
                result = GateResult(assessment, Decision.AUTO_ALLOWED, user_response="Not required", advisory=advisory)
            else:
                approval_started = perf_counter()
                approved = bool(confirm and confirm(assessment, advisory))
                approval_time_ms = round((perf_counter() - approval_started) * 1000, 2)
                if approved:
                    result = GateResult(assessment, Decision.USER_CONFIRMATION, user_response="Approved", advisory=advisory, approval_time_ms=approval_time_ms)
                else:
                    result = GateResult(assessment, Decision.CANCELLED, user_response="Cancelled", advisory=advisory, approval_time_ms=approval_time_ms)
            if execute and result.decision in {Decision.AUTO_ALLOWED, Decision.USER_CONFIRMATION}:
                if assessment.category is RiskCategory.DANGEROUS:
                    if verification is None:
                        raise RuntimeError("Action verification is unavailable.")
                    rollback = self.rollback_guardian.prepare(command, verification.preview)
                    updated_preview = preview_action(command, assessment, rollback)
                    assessment = replace(
                        assessment,
                        verification=ActionVerification(intent=verification.intent, preview=updated_preview),
                    )
                    result.assessment = assessment
                execution_command = normalize_safe_command(command, assessment.category)
                execution_started = perf_counter()
                completed = self.executor(execution_command)
                result.executed = True
                result.stdout = (completed.stdout or "")[-4000:]
                result.stderr = (completed.stderr or "")[-4000:]
                result.execution_result = (result.stdout + result.stderr)[-4000:]
                result.execution_command = execution_command
                result.execution_time_ms = round((perf_counter() - execution_started) * 1000, 2)
            self.audit_log.append(result)
            return result
        except Exception as error:
            fallback = RiskAssessment(command=str(command), score=1.0, category=RiskCategory.DANGEROUS, explanation="Safety verification failed.")
            result = GateResult(fallback, Decision.BLOCKED_ERROR, user_response="Not requested", error=str(error))
            try:
                self.audit_log.append(result)
            except Exception:
                # The original error is reported; most importantly, no execution was attempted.
                pass
            return result
