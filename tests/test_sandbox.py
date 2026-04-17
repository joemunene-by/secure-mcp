from __future__ import annotations

import pytest

from secure_mcp.sandbox import SandboxError, run


def test_run_success():
    result = run(["echo", "hello"])
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert not result.timed_out


def test_run_timeout():
    result = run(["sleep", "2"], timeout_s=0.2)
    assert result.timed_out
    assert result.returncode == -1


def test_run_output_cap():
    result = run(["sh", "-c", "head -c 1000 /dev/urandom | base64"], max_output_bytes=100)
    assert result.truncated
    assert len(result.stdout) <= 100


def test_run_missing_binary():
    with pytest.raises(SandboxError, match="not found"):
        run(["/definitely/does/not/exist/binary-xyz"])


def test_run_empty_argv():
    with pytest.raises(SandboxError, match="argv"):
        run([])
