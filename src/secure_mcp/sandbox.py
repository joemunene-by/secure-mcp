"""Subprocess sandbox: timeout, output cap, restricted environment."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024  # 256 KiB
SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "HOME", "USER", "TZ")


class SandboxError(Exception):
    """Raised when sandboxed execution fails or exceeds limits."""


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool


def run(
    argv: list[str],
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    cwd: str | None = None,
    stdin: str | None = None,
) -> SandboxResult:
    """Run a subprocess with a timeout, output cap, and restricted environment."""
    if not argv:
        raise SandboxError("argv must not be empty")

    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_s,
            env=env,
            cwd=cwd,
            input=stdin,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return SandboxResult(
            returncode=-1,
            stdout=(e.stdout or "")[:max_output_bytes] if isinstance(e.stdout, str) else "",
            stderr=(e.stderr or "")[:max_output_bytes] if isinstance(e.stderr, str) else "",
            truncated=False,
            timed_out=True,
        )
    except FileNotFoundError as e:
        raise SandboxError(f"executable not found: {argv[0]}") from e

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    truncated = False
    if len(stdout) > max_output_bytes:
        stdout = stdout[:max_output_bytes]
        truncated = True
    if len(stderr) > max_output_bytes:
        stderr = stderr[:max_output_bytes]
        truncated = True

    return SandboxResult(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        timed_out=False,
    )
