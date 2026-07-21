#!/usr/bin/env python3
"""Optional standalone fallback; the recommended Codex integration is MCP."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from safeagent.gate import SafetyGate
from safeagent.models import Advisory, RiskAssessment


def prompt(assessment: RiskAssessment, advisory: Advisory | None) -> bool:
    print("\n⚠ Dangerous Command Detected" if assessment.category.value == "DANGEROUS" else "\n⚠ Risky Command Detected")
    print(f"\nCommand: {assessment.command}\nRisk Score: {assessment.score:.2f} ({assessment.category.value.title()})")
    print("\nReason:")
    for item in assessment.matches:
        print(f"• {item.explanation}")
    if advisory:
        print(f"\nAI-generated advisory:\n{advisory.explanation}")
        if advisory.safer_alternative:
            print(f"Safer alternative: {advisory.safer_alternative}")
    return input("\nExecute anyway? [Y] Yes  [N] Cancel: ").strip().lower() in {"y", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(description="SafeAgent standalone command safety fallback")
    parser.add_argument("--execute", metavar="COMMAND", help="inspect, confirm, then execute a shell command")
    parser.add_argument("program", nargs=argparse.REMAINDER, help="launch an agent program after --")
    args = parser.parse_args()
    gate = SafetyGate()
    if args.execute is not None:
        result = gate.evaluate(args.execute, confirm=prompt, execute=True)
        if result.decision.value == "BLOCKED_ERROR":
            print("SafeAgent encountered an internal error. The command has NOT been executed because safety verification failed.", file=sys.stderr)
            return 2
        if not result.executed:
            print("Command cancelled; it was not executed.")
            return 1
        print(result.execution_result or "Command executed.")
        return 0
    program = args.program[1:] if args.program[:1] == ["--"] else args.program
    if not program:
        parser.error("provide --execute COMMAND or a program after --")
    env = os.environ.copy()
    env["SAFEAGENT_COMMAND_GATEWAY"] = f'"{sys.executable}" "{os.path.abspath(__file__)}" --execute'
    print("SafeAgent fallback launcher started. For Codex, prefer the MCP integration in README.md.")
    return subprocess.run(program, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
