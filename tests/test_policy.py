from __future__ import annotations

import pytest
import yaml

from secure_mcp.policy import Policy, PolicyViolation, ToolPolicy, _target_matches


def _write_policy(tmp_path, data: dict) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(data))
    return str(p)


def test_tool_disabled_denies(tmp_path):
    path = _write_policy(tmp_path, {"tools": {"port_scan": {"enabled": False}}})
    policy = Policy.load(path)
    with pytest.raises(PolicyViolation, match="disabled"):
        policy.check_enabled("port_scan")


def test_unknown_tool_raises(tmp_path):
    path = _write_policy(tmp_path, {"tools": {}})
    policy = Policy.load(path)
    with pytest.raises(PolicyViolation, match="not configured"):
        policy.tool("ghost")


def test_target_allowlist_cidr():
    assert _target_matches("10.1.2.3", ["10.0.0.0/8"])
    assert not _target_matches("8.8.8.8", ["10.0.0.0/8"])


def test_target_allowlist_wildcard_and_suffix():
    assert _target_matches("example.com", ["*"])
    assert _target_matches("api.example.com", ["*.example.com"])
    assert not _target_matches("example.org", ["*.example.com"])


def test_target_denied_by_empty_allowlist(tmp_path):
    path = _write_policy(
        tmp_path, {"tools": {"vuln_scan": {"enabled": True, "target_allowlist": []}}}
    )
    policy = Policy.load(path)
    with pytest.raises(PolicyViolation, match="explicit target_allowlist"):
        policy.check_target("vuln_scan", "/some/path")


def test_rate_limit(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "tools": {
                "dns_lookup": {
                    "enabled": True,
                    "target_allowlist": ["*"],
                    "rate_limit": {"per_minute": 2},
                }
            }
        },
    )
    policy = Policy.load(path)
    policy.check_rate_limit("dns_lookup")
    policy.check_rate_limit("dns_lookup")
    with pytest.raises(PolicyViolation, match="rate limit"):
        policy.check_rate_limit("dns_lookup")


def test_tool_policy_from_dict_passthrough():
    tp = ToolPolicy.from_dict(
        {
            "enabled": True,
            "target_allowlist": ["127.0.0.1"],
            "rate_limit": {"per_minute": 7},
            "max_ports": 50,
            "custom_key": "custom_value",
        }
    )
    assert tp.rate_limit_per_minute == 7
    assert tp.max_ports == 50
    assert tp.extra["custom_key"] == "custom_value"
