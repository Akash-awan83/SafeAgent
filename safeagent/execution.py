"""Platform-aware shell execution that only normalises harmless aliases."""
from __future__ import annotations

import platform
import re
import subprocess

from .models import RiskCategory


def normalize_safe_command(command: str, category: RiskCategory, system: str | None = None) -> str:
    """Translate safe POSIX display aliases for Windows; never rewrite risky commands."""
    if (system or platform.system()).lower() != "windows" or category is not RiskCategory.SAFE:
        return command
    stripped = command.strip()
    if stripped == "pwd":
        return "cd"
    if re.fullmatch(r"ls(?:\s+[-/\\.\w]+)*", stripped, flags=re.IGNORECASE):
        return "dir" + stripped[2:]
    return command


class PlatformShellExecutor:
    def __call__(self, command: str) -> subprocess.CompletedProcess[str]:
        # No arbitrary 120-second execution deadline: approval is already complete.
        return subprocess.run(command, shell=True, text=True, capture_output=True, check=False)
