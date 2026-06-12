"""Audit logger: append-only JSONL record of every tool call."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        detail: str | None = None,
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "tool": tool,
            "args": args,
            "outcome": outcome,
        }
        if detail is not None:
            entry["detail"] = detail[:2000]

        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def tail(self, n: int = 50) -> list[dict]:
        """Return the last n entries (oldest first). Malformed lines are skipped."""
        if n <= 0:
            return []
        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as f:
                    lines = f.readlines()
            except FileNotFoundError:
                return []
        entries: list[dict] = []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
