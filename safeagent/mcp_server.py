"""SafeAgent MCP stdio server for command execution requests from AI agents."""
from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from typing import Any

from .gate import SafetyGate
from .models import Advisory, Decision, GateResult, RiskAssessment

Confirmation = Callable[[RiskAssessment, Advisory | None], bool]
FAIL_CLOSED_MESSAGE = "SafeAgent encountered an internal error. The command has NOT been executed because safety verification failed."


class ApprovalConsoleUnavailable(RuntimeError):
    """Raised when the local, human-operated approval console is unreachable."""


class ApprovalConsoleClient:
    def __init__(self, host: str | None = None, port: int | None = None, timeout: float | None = None) -> None:
        self.host = host or os.getenv("SAFEAGENT_APPROVAL_HOST", "127.0.0.1")
        self.port = port or int(os.getenv("SAFEAGENT_APPROVAL_PORT", "8765"))
        self.timeout = timeout if timeout is not None else float(os.getenv("SAFEAGENT_APPROVAL_TIMEOUT_SECONDS", "300"))

    def __call__(self, assessment: RiskAssessment, advisory: Advisory | None) -> bool:
        verification = None if assessment.verification is None else assessment.verification.to_dict()
        payload = {
            "command": assessment.command,
            "risk_score": assessment.score,
            "category": assessment.category.value,
            "reasons": list(dict.fromkeys([match.explanation for match in assessment.matches] + list(assessment.risk_factors))),
            "advisory": None if advisory is None else {
                "source": advisory.source,
                "explanation": advisory.explanation,
                "safer_alternative": advisory.safer_alternative,
            },
            "intent_verification": None if verification is None else verification["intent"],
            "execution_preview": None if verification is None else verification["execution_preview"],
        }
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as connection:
                connection.settimeout(self.timeout)
                connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                response = b""
                while not response.endswith(b"\n"):
                    chunk = connection.recv(4096)
                    if not chunk:
                        raise ApprovalConsoleUnavailable("approval console closed the connection")
                    response += chunk
            decoded = json.loads(response.decode("utf-8"))
            if "approved" not in decoded:
                raise ApprovalConsoleUnavailable("approval console returned an invalid response")
            return bool(decoded["approved"])
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ApprovalConsoleUnavailable("human approval console is unavailable") from error


class SafeAgentMCPService:
    """Protocol-independent command service; the MCP tool is a thin adapter over it."""

    def __init__(self, gate: SafetyGate | None = None, confirm: Confirmation | None = None) -> None:
        self.gate = gate or SafetyGate()
        self.confirm = confirm or ApprovalConsoleClient()

    def execute_command(self, command: str, user_request: str | None = None) -> dict[str, Any]:
        """Run after deterministic scoring, intent verification, and human approval when required."""
        try:
            result = self.gate.evaluate(command, confirm=self.confirm, execute=True, user_request=user_request)
            return self._response(result)
        except Exception:
            # This catches adapter-level faults before a command can be returned as successful.
            return {"ok": False, "executed": False, "decision": Decision.BLOCKED_ERROR.value, "message": FAIL_CLOSED_MESSAGE}

    @staticmethod
    def _response(result: GateResult) -> dict[str, Any]:
        verification = None if result.assessment.verification is None else result.assessment.verification.to_dict()
        if result.decision is Decision.BLOCKED_ERROR:
            return {"ok": False, "executed": False, "decision": result.decision.value, "message": FAIL_CLOSED_MESSAGE, "error": result.error}
        return {
            "ok": result.executed,
            "executed": result.executed,
            "decision": result.decision.value,
            "category": result.assessment.category.value,
            "risk_score": result.assessment.score,
            "rule_score": result.assessment.rule_score,
            "ml_probability": result.assessment.ml_probability,
            "final_score": result.assessment.final_score,
            "reason": result.assessment.explanation,
            "risk_factors": list(result.assessment.risk_factors),
            "user_response": result.user_response,
            "output": result.execution_result,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "approval_time_ms": result.approval_time_ms,
            "execution_time_ms": result.execution_time_ms,
            "intent_verification": None if verification is None else verification["intent"],
            "execution_preview": None if verification is None else verification["execution_preview"],
            "message": "Command executed." if result.executed else "Command was not executed.",
        }


def create_mcp_server(service: SafeAgentMCPService | None = None) -> Any:
    """Create an MCP server lazily so core tests do not require MCP at import time."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as error:
        raise RuntimeError("MCP dependency is missing. Install with: pip install -e .") from error

    command_service = service or SafeAgentMCPService()
    server = FastMCP("SafeAgent")

    @server.tool()
    def execute_command(command: str, user_request: str | None = None) -> dict[str, Any]:
        """Request execution through SafeAgent. Provide the user's original request for intent verification."""
        return command_service.execute_command(command, user_request=user_request)

    return server


def main() -> int:
    try:
        create_mcp_server().run(transport="stdio")
        return 0
    except Exception as error:
        # stderr is safe for diagnostics; stdout is reserved for MCP JSON-RPC traffic.
        import sys
        print(f"{FAIL_CLOSED_MESSAGE} ({error})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
