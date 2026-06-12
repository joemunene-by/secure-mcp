"""Policy engine: YAML-driven allow/deny, target allowlists, and rate limits."""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class PolicyViolation(Exception):
    """Raised when a tool call is denied by policy."""


@dataclass
class ToolPolicy:
    enabled: bool = True
    target_allowlist: list[str] = field(default_factory=list)
    rate_limit_per_minute: int | None = None
    max_ports: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolPolicy:
        rate = (data.get("rate_limit") or {}).get("per_minute")
        return cls(
            enabled=data.get("enabled", True),
            target_allowlist=list(data.get("target_allowlist") or []),
            rate_limit_per_minute=rate,
            max_ports=data.get("max_ports"),
            extra={
                k: v
                for k, v in data.items()
                if k not in {"enabled", "target_allowlist", "rate_limit", "max_ports"}
            },
        )


class Policy:
    def __init__(self, tools: dict[str, ToolPolicy]):
        self._tools = tools
        self._call_history: dict[str, deque[float]] = {name: deque() for name in tools}
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        raw_tools = data.get("tools", {}) or {}
        tools = {name: ToolPolicy.from_dict(cfg or {}) for name, cfg in raw_tools.items()}
        return cls(tools)

    def tool(self, name: str) -> ToolPolicy:
        if name not in self._tools:
            raise PolicyViolation(f"tool '{name}' not configured in policy")
        return self._tools[name]

    def check_enabled(self, name: str) -> None:
        if not self.tool(name).enabled:
            raise PolicyViolation(f"tool '{name}' is disabled by policy")

    def check_target(self, name: str, target: str) -> None:
        allowlist = self.tool(name).target_allowlist
        if not allowlist:
            raise PolicyViolation(
                f"tool '{name}' requires an explicit target_allowlist; '{target}' denied"
            )
        if not _target_matches(target, allowlist):
            raise PolicyViolation(
                f"target '{target}' is not permitted for tool '{name}'"
            )

    def check_rate_limit(self, name: str) -> None:
        limit = self.tool(name).rate_limit_per_minute
        if limit is None:
            return
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            history = self._call_history[name]
            while history and history[0] < cutoff:
                history.popleft()
            if len(history) >= limit:
                raise PolicyViolation(
                    f"rate limit exceeded for tool '{name}': {limit} calls/minute"
                )
            history.append(now)


def _target_matches(target: str, allowlist: list[str]) -> bool:
    target = target.strip()
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    for entry in allowlist:
        entry = entry.strip()
        if not entry:
            continue
        if entry == "*":
            return True
        if entry.startswith("/"):
            if _path_matches(target, entry):
                return True
            continue
        if target_ip is not None:
            try:
                if target_ip in ipaddress.ip_network(entry, strict=False):
                    return True
                continue
            except ValueError:
                pass
        if entry.startswith("*."):
            if target.lower().endswith(entry[1:].lower()):
                return True
            continue
        if target.lower() == entry.lower():
            return True
    return False


def _path_matches(target: str, entry: str) -> bool:
    """Filesystem allowlist entry: the entry is a directory; the target must be
    that directory or inside it. Both sides are resolved so `..` tricks and
    symlinked aliases can't escape the allowlisted root."""
    if not target.startswith("/") and not target.startswith("~"):
        return False
    try:
        target_path = Path(target).expanduser().resolve()
        entry_path = Path(entry).resolve()
    except OSError:
        return False
    return target_path == entry_path or entry_path in target_path.parents
