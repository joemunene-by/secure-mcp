"""Additional coverage for policy gating, sandbox limits, audit, and tool edges.

These tests assert on the documented, observable behavior of the public API and
do not change any runtime logic.
"""

from __future__ import annotations

import json
import socket
import struct

import pytest
import yaml

from secure_mcp.audit import AuditLog
from secure_mcp.policy import Policy, PolicyViolation, ToolPolicy, _target_matches
from secure_mcp.sandbox import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    SAFE_ENV_KEYS,
    run,
)
from secure_mcp.tools import file_hash, port_scan, vuln_scan


def _write_policy(tmp_path, data: dict) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(data))
    return str(p)


# --- policy ---------------------------------------------------------------

def test_check_target_allows_permitted_value(tmp_path):
    path = _write_policy(
        tmp_path,
        {"tools": {"port_scan": {"enabled": True, "target_allowlist": ["10.0.0.0/8"]}}},
    )
    policy = Policy.load(path)
    # A permitted target must not raise.
    policy.check_target("port_scan", "10.5.5.5")
    with pytest.raises(PolicyViolation, match="not permitted"):
        policy.check_target("port_scan", "8.8.8.8")


def test_check_enabled_default_true(tmp_path):
    path = _write_policy(tmp_path, {"tools": {"dns_lookup": {}}})
    policy = Policy.load(path)
    # enabled defaults to True, so this must not raise.
    policy.check_enabled("dns_lookup")


def test_rate_limit_none_never_blocks(tmp_path):
    path = _write_policy(
        tmp_path, {"tools": {"file_hash": {"enabled": True, "target_allowlist": ["*"]}}}
    )
    policy = Policy.load(path)
    for _ in range(50):
        policy.check_rate_limit("file_hash")  # no rate_limit configured -> unlimited


def test_empty_policy_file_yields_no_tools(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    policy = Policy.load(str(p))
    with pytest.raises(PolicyViolation, match="not configured"):
        policy.tool("anything")


def test_from_dict_defaults():
    tp = ToolPolicy.from_dict({})
    assert tp.enabled is True
    assert tp.target_allowlist == []
    assert tp.rate_limit_per_minute is None
    assert tp.max_ports is None


def test_target_matches_ipv6_and_bad_cidr_skipped():
    # A malformed allowlist entry must be skipped, not crash.
    assert not _target_matches("8.8.8.8", ["not-a-cidr/zz"])
    # Exact IPv6 match.
    assert _target_matches("::1", ["::1"])


def test_target_matches_case_insensitive_exact():
    assert _target_matches("Example.COM", ["example.com"])


# --- sandbox --------------------------------------------------------------

def test_sandbox_defaults_exposed():
    assert DEFAULT_TIMEOUT_S == 30.0
    assert DEFAULT_MAX_OUTPUT_BYTES == 256 * 1024
    assert "PATH" in SAFE_ENV_KEYS


def test_sandbox_nonzero_returncode():
    result = run(["sh", "-c", "exit 3"])
    assert result.returncode == 3
    assert not result.timed_out
    assert not result.truncated


def test_sandbox_stdin_is_forwarded():
    result = run(["cat"], stdin="piped-input\n")
    assert "piped-input" in result.stdout


def test_sandbox_restricted_env_drops_unlisted(monkeypatch):
    monkeypatch.setenv("SECURE_MCP_SECRET", "leak-me")
    result = run(["sh", "-c", "echo ${SECURE_MCP_SECRET:-EMPTY}"])
    assert "EMPTY" in result.stdout
    assert "leak-me" not in result.stdout


# --- audit ----------------------------------------------------------------

def test_audit_detail_truncated_to_2000(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.record(tool="x", args={}, outcome="error", detail="A" * 5000)
    entry = json.loads(log_path.read_text().strip())
    assert len(entry["detail"]) == 2000


def test_audit_appends_not_overwrites(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    AuditLog(log_path).record(tool="a", args={}, outcome="ok")
    AuditLog(log_path).record(tool="b", args={}, outcome="ok")
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2


def test_audit_non_serializable_args_use_default_str(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    AuditLog(log_path).record(tool="x", args={"obj": object()}, outcome="ok")
    entry = json.loads(log_path.read_text().strip())
    assert "object at" in entry["args"]["obj"]


# --- tools ----------------------------------------------------------------

def test_port_scan_closed_port():
    # Bind then close to obtain a port number that is (almost certainly) closed.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = port_scan.scan("127.0.0.1", [port], timeout=0.3)
    assert result["open_ports"] == []
    assert result["scanned"] == 1


def test_file_hash_directory_rejected(tmp_path):
    result = file_hash.hash_file(str(tmp_path))
    assert "not a regular file" in result["error"]


def test_file_hash_all_supported_algorithms(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"data")
    result = file_hash.hash_file(str(p), list(file_hash.SUPPORTED))
    assert set(result["hashes"]) == set(file_hash.SUPPORTED)


def test_vuln_scan_excludes_default_dirs(tmp_path):
    # A secret inside an excluded directory must not be reported.
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("ghp_" + "a" * 36 + "\n")
    result = vuln_scan.scan(str(tmp_path))
    assert result["findings_count"] == 0


def test_vuln_scan_reports_relative_paths(tmp_path):
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "leak.py").write_text("token = 'gho_" + "b" * 36 + "'\n")
    result = vuln_scan.scan(str(tmp_path))
    assert result["findings_count"] >= 1
    for f in result["findings"]:
        assert not f["path"].startswith("/")


def test_vuln_scan_path_is_file_not_dir(tmp_path):
    f = tmp_path / "single.py"
    f.write_text("x = 1\n")
    result = vuln_scan.scan(str(f))
    assert "not a directory" in result["error"]


def _synth_png_no_metadata() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    iend = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return sig + iend


def test_metadata_scrub_png_without_metadata_is_passthrough(tmp_path):
    from secure_mcp.tools import metadata_scrub

    src = tmp_path / "clean.png"
    dst = tmp_path / "out.png"
    src.write_bytes(_synth_png_no_metadata())
    result = metadata_scrub.scrub(str(src), str(dst))
    assert result["format"] == "png"
    assert result["segments_removed"] == []
    assert dst.read_bytes() == src.read_bytes()
