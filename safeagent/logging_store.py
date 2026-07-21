from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import GateResult


class JsonlAuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.getenv("SAFEAGENT_LOG", "data/decisions.jsonl"))

    def append(self, result: GateResult) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operating_system": platform.platform(),
            **result.to_log_record(),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def probe(self) -> None:
        """Verify that audit storage is reachable before a command can run."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8"):
            pass

    def records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
