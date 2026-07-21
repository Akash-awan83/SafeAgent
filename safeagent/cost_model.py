"""Inspectable, conservative cost model for shell commands."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Match, RiskAssessment, RiskCategory


@dataclass(frozen=True)
class DestructiveRule:
    rule_id: str
    pattern: str
    score: float
    explanation: str


# These rules deliberately favor false positives. Calibration data must remain held out.
DESTRUCTIVE_PATTERNS: tuple[DestructiveRule, ...] = (
    DestructiveRule("recursive_delete", r"\brm\s+(?:-[^\s]*[rf][^\s]*\s+|--recursive\s+--force\s+).+", 0.98, "Recursive deletion can permanently remove many files and may be difficult to recover."),
    DestructiveRule("windows_recursive_delete", r"\b(?:rmdir|rd)\s+(?:(?:/s\b.*)|(?:/q\s+/s\b.*))", 0.98, "Recursive Windows directory deletion can permanently remove many files and may be difficult to recover."),
    DestructiveRule("powershell_recursive_delete", r"\bremove-item\b.*(?:^|\s)-recurse\b", 0.98, "PowerShell recursive deletion can permanently remove many files and may be difficult to recover."),
    DestructiveRule("find_delete", r"\bfind\b.+\s-delete\b", 0.96, "find -delete can remove every matching file without a recycle bin."),
    DestructiveRule("format_disk", r"\b(?:mkfs(?:\.[\w-]+)?|diskpart)\b", 1.0, "Disk formatting can destroy an entire filesystem."),
    DestructiveRule("raw_disk_write", r"\bdd\s+.*\bof=/dev/", 1.0, "Writing directly to a device can overwrite a disk or boot record."),
    DestructiveRule("download_and_execute", r"\b(?:curl|wget)\b.+\|\s*(?:ba)?sh\b", 0.97, "Downloaded code is being executed immediately without inspection."),
    DestructiveRule("world_writable_recursive", r"\bchmod\s+(?:-R\s+)?(?:777|a\+rwx)\b", 0.94, "Broad permissions can expose files or make them modifiable by other users."),
    DestructiveRule("force_push", r"\bgit\s+push\b.*(?:--force(?:-with-lease)?|-f)\b", 0.72, "A force push can overwrite remote history and collaborators' work."),
    DestructiveRule("uninstall", r"\b(?:pip(?:3)?|npm|brew|apt(?:-get)?)\s+(?:uninstall|remove|purge)\b", 0.65, "Removing packages can break the current environment or dependent tools."),
    DestructiveRule("move_or_overwrite", r"\b(?:mv|move|cp|copy)\b.+", 0.45, "Moving or copying files may overwrite or displace important data."),
    DestructiveRule("shell_expansion_delete", r"\brm\b.+(?:\*|~|/)", 0.88, "Deletion with wildcard or root-like paths can affect more files than intended."),
)


class CommandParseError(ValueError):
    """Raised when the minimal command validation cannot safely inspect input."""


class RuleBasedCostModel:
    def __init__(self, rules: tuple[DestructiveRule, ...] = DESTRUCTIVE_PATTERNS) -> None:
        self.rules = rules

    def assess(self, command: str) -> RiskAssessment:
        if not isinstance(command, str) or not command.strip():
            raise CommandParseError("Command must be a non-empty string.")
        if "\x00" in command:
            raise CommandParseError("Command contains a null byte.")
        if len(command) > 16_384:
            raise CommandParseError("Command exceeds the inspection limit.")

        matches = [
            Match(rule.rule_id, rule.score, rule.explanation)
            for rule in self.rules
            if re.search(rule.pattern, command, flags=re.IGNORECASE | re.DOTALL)
        ]
        score = max((match.score for match in matches), default=0.0)
        category = (
            RiskCategory.DANGEROUS if score >= 0.85 else RiskCategory.RISKY if score >= 0.4 else RiskCategory.SAFE
        )
        explanation = " ".join(match.explanation for match in matches) or "No destructive command pattern was detected."
        return RiskAssessment(command=command, score=score, category=category, matches=matches, explanation=explanation)
