"""Deterministic intent, preview, and recovery helpers for SafeAgent actions.

The module deliberately uses inspectable command heuristics.  It explains an
action to a human; it does not ask an LLM to decide whether the action runs.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import RiskAssessment, RiskCategory


_SECRET_MARKERS = (".env", "id_rsa", "id_ed25519", "credentials", "secret", "token", ".pem", ".key")
_DELETE_WORDS = ("delete", "remove", "clean", "cleanup", "erase", "wipe")
_CREATE_WORDS = ("create", "make", "generate", "mkdir", "md", "new-item")
_INSPECT_WORDS = ("list", "show", "inspect", "check", "view", "read")
_NETWORK_WORDS = ("download", "upload", "fetch", "curl", "wget", "http", "https")
_PACKAGE_WORDS = ("install", "uninstall", "package", "dependency")
_TARGET_TYPE_WORDS = {"folder", "directory", "dir", "path"}
_TARGET_SYNONYMS = {"temp": "temporary", "tmp": "temporary"}
_TARGET_FILLER_WORDS = {"a", "an", "the", "new", "named", "called", "using", "with", "at", "in", "to", "for"}


@dataclass(frozen=True)
class IntentAssessment:
    """Comparison between the originating user instruction and one shell action."""

    score: float | None
    expected_action: str
    actual_action: str
    expected_targets: tuple[str, ...]
    actual_targets: tuple[str, ...]
    decision: str
    explanation: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "intent_match_score": self.score,
            "expected_action": self.expected_action,
            "actual_action": self.actual_action,
            "expected_targets": list(self.expected_targets),
            "actual_targets": list(self.actual_targets),
            "intent_decision": self.decision,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RollbackPlan:
    """Recovery information created for one action, when it can be created safely."""

    status: str
    rollback_id: str | None = None
    artifact_path: str | None = None
    protected_targets: tuple[str, ...] = ()
    instructions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "rollback_id": self.rollback_id,
            "artifact_path": self.artifact_path,
            "protected_targets": list(self.protected_targets),
            "instructions": list(self.instructions),
        }


@dataclass(frozen=True)
class ExecutionPreview:
    """Human-readable impact description shown before a command is executed."""

    summary: str
    files_affected: tuple[str, ...]
    directories_affected: tuple[str, ...]
    git_operations: tuple[str, ...]
    network_access: tuple[str, ...]
    secret_access: tuple[str, ...]
    estimated_impact: str
    risk_explanation: str
    rollback: RollbackPlan

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "files_affected": list(self.files_affected),
            "directories_affected": list(self.directories_affected),
            "git_operations": list(self.git_operations),
            "network_access": list(self.network_access),
            "secret_access": list(self.secret_access),
            "estimated_impact": self.estimated_impact,
            "risk_explanation": self.risk_explanation,
            "rollback": self.rollback.to_dict(),
        }


@dataclass(frozen=True)
class ActionVerification:
    """The verification evidence associated with a RiskAssessment."""

    intent: IntentAssessment
    preview: ExecutionPreview

    def to_dict(self) -> dict[str, object]:
        return {"intent": self.intent.to_dict(), "execution_preview": self.preview.to_dict()}


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        raw = value.strip().strip("`'\"")
        cleaned = raw if raw in {".", "..", "/", "~"} else raw.rstrip(".,;:")
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            result.append(cleaned)
    return tuple(result)


def _normalise_target(value: str) -> str:
    normalised = value.strip().strip("`'\"").replace("\\", "/").rstrip("/").lower()
    while normalised.startswith("./"):
        normalised = normalised[2:]
    if normalised in {".", "..", "/", "~"}:
        return normalised

    canonical_parts: list[str] = []
    for segment in normalised.split("/"):
        tokens = [token for token in re.split(r"[\s_-]+", segment) if token]
        canonical_tokens: list[str] = []
        for token in tokens:
            token = _TARGET_SYNONYMS.get(token, token)
            # A target named "temp_folder" and a request for a "temporary
            # directory" describe the same target concept.  Preserve a lone
            # descriptor, but remove it when it merely labels another name.
            if token in _TARGET_TYPE_WORDS and len(tokens) > 1:
                continue
            canonical_tokens.append(token)
        canonical_parts.append("_".join(canonical_tokens) or segment)
    return "/".join(canonical_parts) or "."


def _user_action(request: str) -> str:
    lowered = request.lower()
    if any(word in lowered for word in _DELETE_WORDS):
        return "delete"
    if any(re.search(rf"\b{re.escape(word)}\b", lowered) for word in _CREATE_WORDS):
        return "create"
    if any(word in lowered for word in _INSPECT_WORDS):
        return "inspect"
    if any(word in lowered for word in _NETWORK_WORDS):
        return "network"
    if any(word in lowered for word in _PACKAGE_WORDS):
        return "package"
    if any(word in lowered for word in ("commit", "push", "pull", "branch", "merge", "rebase", "checkout")):
        return "git"
    if any(word in lowered for word in ("run", "execute", "build", "test", "start")):
        return "execute"
    return "unspecified"


def _command_action(command: str) -> str:
    lowered = command.lower()
    if re.search(r"\b(?:rm|rmdir|rd|remove-item)\b|\bfind\b.+\s-delete\b", lowered, re.DOTALL):
        return "delete"
    if re.search(r"\b(?:mkdir|md|touch)\b|\bnew-item\b.*?(?:^|\s)-itemtype\s+(?:directory|dir|file)\b", lowered, re.DOTALL):
        return "create"
    if re.search(r"\bgit\s+", lowered):
        return "git"
    if re.search(r"\b(?:curl|wget|invoke-webrequest|start-bitstransfer)\b", lowered):
        return "network"
    if re.search(r"\b(?:pip(?:3)?|npm|brew|apt(?:-get)?)\s+(?:install|uninstall|remove|purge)\b", lowered):
        return "package"
    if re.match(r"\s*(?:ls|dir|pwd|git\s+status|cat|type|get-childitem)\b", lowered):
        return "inspect"
    return "execute"


def _user_targets(request: str) -> tuple[str, ...]:
    targets: list[str] = []
    targets.extend(re.findall(r"(?:delete|remove|clean|cleanup|erase)\s+(?:the\s+)?([\w.\\/:-]+)\s+(?:folder|directory|file|path)\b", request, flags=re.IGNORECASE))
    targets.extend(re.findall(r"(?:folder|directory|file|path)\s+(?:named\s+)?[`'\"]?([\w.\\/:-]+)", request, flags=re.IGNORECASE))
    create_prefix = r"(?:create|make|generate|mkdir|md|new-item)"
    target_token = r"[\w.\\/:-]+"
    # "create directory test" / "make a folder named build"
    targets.extend(re.findall(rf"\b{create_prefix}\b\s+(?:a|an|the)?\s*(?:folder|directory|dir|file)\s+(?:named|called)?\s*({target_token})", request, flags=re.IGNORECASE))
    # "create a temp folder" / "mkdir temp_folder".  The optional type word
    # is deliberately outside the capture so it cannot become the target.
    targets.extend(re.findall(rf"\b{create_prefix}\b\s+(?:a|an|the)?\s*({target_token})(?:\s+(?:folder|directory|dir|file|path))?\b", request, flags=re.IGNORECASE))
    targets.extend(re.findall(r"[`'\"]([^`'\"]+)[`'\"]", request))
    return _deduplicate(target for target in targets if target.lower() not in _TARGET_FILLER_WORDS | _TARGET_TYPE_WORDS)


def command_targets(command: str) -> tuple[str, ...]:
    """Extract direct path targets from the narrow set of commands SafeAgent previews."""
    targets: list[str] = []
    powershell = re.search(r"\b(?:remove-item|clear-item|new-item)\b.*?-(?:literalpath|path)\s+(['\"]?)([^'\"\s;]+)\1", command, flags=re.IGNORECASE | re.DOTALL)
    if powershell:
        targets.append(powershell.group(2))

    for match in re.finditer(r"\b(?:rm|rmdir|rd)\b\s+([^;|&]+)", command, flags=re.IGNORECASE):
        tokens = re.findall(r"[^\s'\"]+|'[^']*'|\"[^\"]*\"", match.group(1))
        for token in tokens:
            lowered = token.lower()
            if lowered.startswith("-") or lowered in {"/s", "/q", "/f", "/r"}:
                continue
            targets.append(token)
            break
    for match in re.finditer(r"\b(?:mkdir|md|touch)\b\s+([^;|&]+)", command, flags=re.IGNORECASE):
        tokens = re.findall(r"[^\s'\"]+|'[^']*'|\"[^\"]*\"", match.group(1))
        for token in tokens:
            lowered = token.lower()
            if lowered.startswith("-") or lowered in {"/p", "/q"}:
                continue
            targets.append(token)
            break
    return _deduplicate(targets)


def verify_intent(user_request: str | None, command: str) -> IntentAssessment:
    """Make a deterministic, explainable intent comparison.

    A missing user request is explicitly reported as unverified rather than silently
    treated as a match.  It remains compatible with agents that only provide a command.
    """
    actual_action = _command_action(command)
    actual_targets = command_targets(command)
    if not isinstance(user_request, str) or not user_request.strip():
        return IntentAssessment(
            score=None,
            expected_action="User request not supplied",
            actual_action=actual_action,
            expected_targets=(),
            actual_targets=actual_targets,
            decision="UNVERIFIED",
            explanation="Intent could not be verified because the originating user request was not supplied.",
            evidence=("Originating user request was not supplied.",),
        )

    expected_action = _user_action(user_request)
    expected_targets = _user_targets(user_request)
    action_score = 1.0 if expected_action == actual_action else (0.65 if expected_action == "unspecified" else 0.0)

    expected_normalised = {_normalise_target(target) for target in expected_targets}
    actual_normalised = {_normalise_target(target) for target in actual_targets}
    scope_expansion = bool(expected_normalised and actual_normalised & {".", "..", "/", "~"})
    if not expected_normalised:
        target_score = 0.75
    elif not actual_normalised:
        target_score = 0.45
    elif expected_normalised & actual_normalised:
        target_score = 1.0
    else:
        target_score = 0.0
    score = round((0.45 * action_score) + (0.55 * target_score), 2)

    if action_score == 0.0 or scope_expansion or (expected_normalised and actual_normalised and target_score == 0.0):
        decision = "BLOCK"
        explanation = "The planned action exceeds the requested action or target scope and has been blocked before execution."
        evidence = (
            "Action or target scope did not match the user request.",
            "The command was blocked before execution.",
        )
    elif score < 0.8:
        decision = "CONFIRM"
        explanation = "The action is only partially aligned with the request and requires explicit human review."
        evidence = (
            "Action comparison was only partially aligned.",
            "Target evidence needs explicit human review.",
        )
    else:
        decision = "ALLOW"
        semantic_equivalence = bool(
            expected_normalised
            and actual_normalised
            and expected_normalised == actual_normalised
            and set(expected_targets) != set(actual_targets)
        )
        evidence = ["Action matched the requested operation.", "Target matched the requested scope."]
        if semantic_equivalence:
            evidence.append("Controlled synonym normalization recognized an equivalent target.")
        explanation = " ".join(evidence)
    return IntentAssessment(score, expected_action, actual_action, expected_targets, actual_targets, decision, explanation, tuple(evidence))


def _git_operations(command: str) -> tuple[str, ...]:
    lowered = command.lower()
    if not re.search(r"\bgit\b", lowered):
        return ()
    operations = re.findall(r"\bgit\s+(?:-[^\s]+\s+)*(push|pull|commit|reset|checkout|merge|rebase|clean|branch)\b", lowered)
    return _deduplicate(f"git {operation}" for operation in operations) or ("git command",)


def _network_access(command: str) -> tuple[str, ...]:
    urls = re.findall(r"https?://[^\s'\"|;]+", command, flags=re.IGNORECASE)
    if urls:
        return _deduplicate(urls)
    if re.search(r"\b(?:curl|wget|invoke-webrequest|start-bitstransfer)\b", command, flags=re.IGNORECASE):
        return ("Network utility detected; destination could not be resolved.",)
    return ()


def _secret_access(command: str) -> tuple[str, ...]:
    lowered = command.lower()
    return tuple(marker for marker in _SECRET_MARKERS if marker in lowered)


def _impact(category: RiskCategory, targets: tuple[str, ...], network: tuple[str, ...], secrets: tuple[str, ...]) -> str:
    if category is RiskCategory.DANGEROUS or secrets:
        return "CRITICAL"
    if category is RiskCategory.RISKY or network:
        return "HIGH"
    if targets:
        return "MEDIUM"
    return "LOW"


def _created_file_targets(command: str, targets: tuple[str, ...]) -> tuple[str, ...]:
    if not targets:
        return ()
    if re.search(r"\b(?:touch)\b|\bnew-item\b.*?(?:^|\s)-itemtype\s+file\b", command, flags=re.IGNORECASE | re.DOTALL):
        return targets
    return tuple(target for target in targets if Path(target).suffix)


def _package_targets(command: str) -> tuple[str, ...]:
    match = re.search(r"\b(?:pip(?:3)?|npm|yarn|pnpm|brew|apt(?:-get)?|choco|winget)\s+install\s+([\w.@+:/-]+)", command, flags=re.IGNORECASE)
    return (match.group(1),) if match else ()


def _reversible_rollback(command: str, action: str, targets: tuple[str, ...]) -> RollbackPlan | None:
    """Describe a safe inverse operation before a reversible action executes."""
    if action == "create" and targets:
        file_targets = _created_file_targets(command, targets)
        if file_targets:
            return RollbackPlan(
                "AVAILABLE",
                protected_targets=file_targets,
                instructions=(
                    f"Recovery protection is available: delete the created file{'s' if len(file_targets) > 1 else ''} only if rollback is needed.",
                    "Review the created file before removing it.",
                ),
            )
        return RollbackPlan(
            "AVAILABLE",
            protected_targets=targets,
            instructions=(
                f"Recovery protection is available: remove the created folder{'s' if len(targets) > 1 else ''} only if rollback is needed.",
                "Verify the folder contains only the newly created content before removing it.",
            ),
        )
    if action == "package":
        packages = _package_targets(command)
        if packages:
            return RollbackPlan(
                "AVAILABLE",
                protected_targets=packages,
                instructions=(
                    f"Recovery protection is available: uninstall {', '.join(packages)} with the matching package manager if rollback is needed.",
                    "Review dependency changes before uninstalling a package.",
                ),
            )
    return None


def preview_action(command: str, assessment: RiskAssessment, rollback: RollbackPlan | None = None) -> ExecutionPreview:
    targets = command_targets(command)
    action = _command_action(command)
    files = _created_file_targets(command, targets) if action == "create" else tuple(target for target in targets if Path(target).suffix)
    directories = tuple(target for target in targets if target not in files)
    git_operations = _git_operations(command)
    network = _network_access(command)
    secrets_found = _secret_access(command)
    if rollback is None:
        rollback = _reversible_rollback(command, action, targets)
    if rollback is None:
        if assessment.category is RiskCategory.SAFE:
            rollback = RollbackPlan("NOT_REQUIRED", instructions=("No destructive recovery action is expected.",))
        elif targets:
            rollback = RollbackPlan("PLANNED", protected_targets=targets, instructions=("A local backup will be attempted before execution.",))
        elif git_operations:
            rollback = RollbackPlan("LIMITED", instructions=("A Git recovery reference will be captured when possible.",))
        else:
            rollback = RollbackPlan("UNAVAILABLE", instructions=("No reliable automatic rollback target was identified.",))
    summary = f"{action.capitalize()} action"
    if targets:
        summary += f" targeting {', '.join(targets)}"
    elif git_operations:
        summary += f" ({', '.join(git_operations)})"
    return ExecutionPreview(
        summary=summary,
        files_affected=files,
        directories_affected=directories,
        git_operations=git_operations,
        network_access=network,
        secret_access=secrets_found,
        estimated_impact=_impact(assessment.category, targets, network, secrets_found),
        risk_explanation=assessment.explanation,
        rollback=rollback,
    )


def enrich_assessment(assessment: RiskAssessment, user_request: str | None) -> RiskAssessment:
    """Return the original immutable assessment with deterministic verification evidence."""
    intent = verify_intent(user_request, assessment.command)
    preview = preview_action(assessment.command, assessment)
    return replace(assessment, verification=ActionVerification(intent=intent, preview=preview))


class RollbackGuardian:
    """Create bounded, local recovery artifacts without changing the requested action."""

    def __init__(self, root: str | Path | None = None, max_bytes: int | None = None) -> None:
        self.root = Path(root or os.getenv("SAFEAGENT_ROLLBACK_DIR", ".safeagent/rollback"))
        self.max_bytes = max_bytes if max_bytes is not None else int(os.getenv("SAFEAGENT_ROLLBACK_MAX_BYTES", str(50 * 1024 * 1024)))

    @staticmethod
    def _size(path: Path) -> int:
        if path.is_file():
            return path.stat().st_size
        total = 0
        for child in path.rglob("*"):
            if child.is_file() and not child.is_symlink():
                total += child.stat().st_size
        return total

    @staticmethod
    def _within_workspace(path: Path, workspace: Path) -> bool:
        try:
            path.relative_to(workspace)
            return path != workspace
        except ValueError:
            return False

    def _safe_targets(self, targets: Iterable[str]) -> tuple[Path, ...]:
        workspace = Path.cwd().resolve()
        result: list[Path] = []
        for raw_target in targets:
            candidate = Path(raw_target)
            resolved = (workspace / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
            if resolved.exists() and self._within_workspace(resolved, workspace) and ".safeagent" not in resolved.parts:
                result.append(resolved)
        return tuple(result)

    @staticmethod
    def _new_id() -> str:
        return f"rb-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"

    def _git_snapshot(self, destination: Path, command: str) -> RollbackPlan | None:
        try:
            root = subprocess.run(["git", "rev-parse", "--show-toplevel"], text=True, capture_output=True, check=False).stdout.strip()
            if not root:
                return None
            repository = Path(root)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, text=True, capture_output=True, check=False).stdout.strip()
            branch = subprocess.run(["git", "branch", "--show-current"], cwd=repository, text=True, capture_output=True, check=False).stdout.strip()
            status = subprocess.run(["git", "status", "--short"], cwd=repository, text=True, capture_output=True, check=False).stdout
            patch = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=repository, text=True, capture_output=True, check=False).stdout
            destination.mkdir(parents=True, exist_ok=False)
            (destination / "git-diff.patch").write_text(patch, encoding="utf-8")
            metadata = {"command": command, "repository": str(repository), "head": head, "branch": branch, "status": status}
            (destination / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            return RollbackPlan("LIMITED", destination.name, str(destination), (), ("Review git-diff.patch before applying it.", f"Reference commit: {head or 'unavailable'}."))
        except OSError:
            return None

    def prepare(self, command: str, preview: ExecutionPreview) -> RollbackPlan:
        """Create a recovery artifact for a dangerous local action when practical."""
        targets = self._safe_targets((*preview.files_affected, *preview.directories_affected))
        rollback_id = self._new_id()
        destination = self.root / rollback_id
        if targets:
            total_bytes = sum(self._size(target) for target in targets)
            if total_bytes > self.max_bytes:
                return RollbackPlan("UNAVAILABLE", protected_targets=tuple(str(target) for target in targets), instructions=(f"Backup skipped because {total_bytes} bytes exceeds the {self.max_bytes}-byte safety limit.", "Create a manual backup before retrying this action."))
            try:
                destination.mkdir(parents=True, exist_ok=False)
                payload = destination / "payload"
                payload.mkdir()
                for target in targets:
                    target_destination = payload / target.name
                    if target.is_dir():
                        shutil.copytree(target, target_destination, symlinks=True)
                    else:
                        shutil.copy2(target, target_destination, follow_symlinks=False)
                metadata = {"command": command, "created_at": datetime.now(timezone.utc).isoformat(), "targets": [str(target) for target in targets]}
                (destination / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
                return RollbackPlan("READY", rollback_id, str(destination), tuple(str(target) for target in targets), (f"Recovery copy is stored in {destination / 'payload'}.", "Restore only the affected target after inspecting the backup."))
            except OSError as error:
                return RollbackPlan("UNAVAILABLE", rollback_id, protected_targets=tuple(str(target) for target in targets), instructions=(f"SafeAgent could not create a local backup: {error}.", "Create a manual backup before retrying this action."))
        if preview.git_operations:
            git_plan = self._git_snapshot(destination, command)
            if git_plan is not None:
                return git_plan
        return RollbackPlan("UNAVAILABLE", rollback_id, instructions=("No workspace-local target could be backed up automatically.", "Review the command and create a manual backup if recovery is required."))
