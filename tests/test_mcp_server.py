import subprocess

from safeagent.gate import SafetyGate
from safeagent.logging_store import JsonlAuditLog
from safeagent.mcp_server import SafeAgentMCPService
from safeagent.models import Decision


def completed(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout="done", stderr="")


def test_mcp_receives_and_executes_safe_command(tmp_path):
    service = SafeAgentMCPService(SafetyGate(audit_log=JsonlAuditLog(tmp_path / "audit.jsonl"), executor=completed))
    result = service.execute_command("echo hello")
    assert result["executed"] is True
    assert result["decision"] == Decision.AUTO_ALLOWED.value
    assert result["output"] == "done"
    assert result["stdout"] == "done"


def test_mcp_routes_dangerous_command_to_confirmation(tmp_path):
    asked = []
    service = SafeAgentMCPService(
        SafetyGate(audit_log=JsonlAuditLog(tmp_path / "audit.jsonl"), executor=completed),
        confirm=lambda assessment, advisory: asked.append(assessment.command) or False,
    )
    result = service.execute_command("rm -rf build")
    assert asked == ["rm -rf build"]
    assert result["executed"] is False
    assert result["decision"] == Decision.CANCELLED.value


def test_mcp_approval_executes_dangerous_command(tmp_path):
    service = SafeAgentMCPService(
        SafetyGate(audit_log=JsonlAuditLog(tmp_path / "audit.jsonl"), executor=completed),
        confirm=lambda *_: True,
    )
    assert service.execute_command("rm -rf build")["executed"] is True


def test_mcp_failure_is_fail_closed(tmp_path):
    class ExplodingGate:
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("MCP routing failure")

    result = SafeAgentMCPService(gate=ExplodingGate()).execute_command("echo hello")
    assert result["executed"] is False
    assert result["decision"] == Decision.BLOCKED_ERROR.value
    assert "NOT been executed" in result["message"]
