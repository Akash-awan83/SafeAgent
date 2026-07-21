"""Deterministic, inspectable feature extraction for command-risk learning."""
from __future__ import annotations

import re
from typing import Final

FEATURE_NAMES: Final[tuple[str, ...]] = (
    "command_length",
    "token_count",
    "shell_operator_count",
    "recursive_operation",
    "delete_operation",
    "overwrite_operation",
    "privilege_escalation",
    "network_access",
    "download_execute",
    "encoding_technique",
    "suspicious_path",
    "process_termination",
    "package_installation",
)


def extract_features(command: str) -> dict[str, float]:
    """Extract fixed, human-auditable features without running or parsing the command."""
    lowered = command.lower()
    tokens = re.findall(r"[^\s]+", command)
    return {
        "command_length": min(len(command), 2000) / 200.0,
        "token_count": min(len(tokens), 100) / 20.0,
        "shell_operator_count": min(len(re.findall(r"(?:&&|\|\||\||;|>|<|`|\$\()", command)), 20) / 5.0,
        "recursive_operation": float(bool(re.search(r"(?:\brm\s+-[^\s]*r|\bchmod\s+-r|\bfind\b.*-delete)", lowered))),
        "delete_operation": float(bool(re.search(r"\b(?:rm|del|erase|rmdir|remove|unlink)\b|\b-delete\b", lowered))),
        "overwrite_operation": float(bool(re.search(r"(?:\bdd\b.*\bof=|\b(?:cp|copy|mv|move)\b.*(?:>|/y\b)|>\s*[^&])", lowered))),
        "privilege_escalation": float(bool(re.search(r"\b(?:sudo|su\s|runas|setuid|icacls)\b", lowered))),
        "network_access": float(bool(re.search(r"\b(?:curl|wget|invoke-webrequest|iwr|nc|ncat|ssh|scp)\b", lowered))),
        "download_execute": float(bool(re.search(r"\b(?:curl|wget|iwr|invoke-webrequest)\b.*(?:\||;|&&).*\b(?:bash|sh|zsh|powershell|pwsh)\b", lowered))),
        "encoding_technique": float(bool(re.search(r"(?:base64|-enc(?:odedcommand)?\b|frombase64string|\beval\b)", lowered))),
        "suspicious_path": float(bool(re.search(r"(?:\b/\b|/dev/|\b(?:c:)?\\windows\\|~[\\/]|\.\.[\\/])", lowered))),
        "process_termination": float(bool(re.search(r"\b(?:kill|killall|pkill|taskkill|stop-process)\b", lowered))),
        "package_installation": float(bool(re.search(r"\b(?:pip|npm|yarn|pnpm|brew|apt(?:-get)?|choco|winget)\s+(?:install|add|remove|uninstall|purge)\b", lowered))),
    }


def feature_vector(command: str) -> list[float]:
    values = extract_features(command)
    return [values[name] for name in FEATURE_NAMES]
