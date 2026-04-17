from __future__ import annotations

import json

from secure_mcp.audit import AuditLog


def test_audit_record_writes_jsonl(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)

    log.record(tool="port_scan", args={"host": "127.0.0.1"}, outcome="ok")
    log.record(tool="dns_lookup", args={"host": "localhost"}, outcome="denied", detail="nope")

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["tool"] == "port_scan"
    assert first["outcome"] == "ok"
    assert first["args"] == {"host": "127.0.0.1"}
    assert "ts" in first

    second = json.loads(lines[1])
    assert second["detail"] == "nope"


def test_audit_creates_parent_dir(tmp_path):
    log_path = tmp_path / "nested" / "deeper" / "audit.jsonl"
    AuditLog(log_path).record(tool="x", args={}, outcome="ok")
    assert log_path.exists()
