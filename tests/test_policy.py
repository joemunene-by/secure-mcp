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


def test_target_allowlist_path_prefix(tmp_path):
    allowed = tmp_path / "projects"
    allowed.mkdir()
    inside = allowed / "repo" / "src"
    sibling = tmp_path / "projectsibling"
    entry = str(allowed)

    assert _target_matches(str(allowed), [entry])
    assert _target_matches(str(inside), [entry])
    assert not _target_matches(str(sibling), [entry])
    assert not _target_matches(str(tmp_path), [entry])
    # dotdot escape is resolved before matching
    assert not _target_matches(str(allowed / ".." / "elsewhere"), [entry])


def test_target_path_entry_does_not_match_hostnames():
    assert not _target_matches("example.com", ["/tmp"])


def test_default_policy_covers_all_registered_tools():
    """Every tool the server registers must have a matching policy entry,
    otherwise calls are denied as 'not configured' (regression: file_hash
    was shipped as 'hash_lookup' in 0.1)."""
    from pathlib import Path

    from secure_mcp import tools as tools_pkg

    default = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    data = yaml.safe_load(default.read_text())
    configured = set(data["tools"])
    registered = {getattr(tools_pkg, mod).NAME for mod in tools_pkg.__all__}
    assert registered <= configured, f"missing policy entries: {registered - configured}"


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
