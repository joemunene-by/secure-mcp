<div align="center">

# secure-mcp

**An MCP server that exposes security tools to AI agents, with policy gates, sandboxing, and audit trails.**

Drop it into Claude Desktop, Cursor, or any MCP-compatible client and give your agent a _constrained_ security toolbox.
Every call is checked against a YAML policy, run in a sandboxed subprocess when relevant, and written to an append-only audit log.

![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-1.0+-6C9CFF?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

> **Authorized use only.** These tools can probe, scan, and fingerprint systems. Only point them at targets you own or have explicit written permission to test. The default policy is intentionally strict (private networks + localhost only). Change it deliberately.

---

## Why

LLM agents with raw tool access are a liability. They can scan arbitrary hosts, exfiltrate files, or chain tools in unintended ways. `secure-mcp` puts a thin but real control plane between the model and the tools:

| Concern | How `secure-mcp` addresses it |
| --- | --- |
| Agent scans arbitrary IPs | `target_allowlist` per tool (CIDR + wildcard matching) |
| Agent spams tools | Per-tool rate limits (sliding window) |
| Tool hangs or floods output | Subprocess sandbox with timeout + output cap |
| "What did the agent do?" | Append-only JSONL audit log for every call |
| Hidden capability expansion | All tools are opt-in in policy; disable any with one line |

The policy is the source of truth. The LLM can't bypass what the runtime won't execute.

## What's included

Seven curated tools, each a clean reimplementation with no heavyweight dependencies:

| Tool | Purpose | Policy checks |
| --- | --- | --- |
| `sec_port_scan` | Async TCP connect scan | target allowlist, `max_ports`, rate limit |
| `sec_dns_lookup` | A/AAAA resolution via stdlib | target allowlist, rate limit |
| `sec_metadata_scrub` | Strip EXIF (JPEG) / tEXt (PNG) | rate limit |
| `sec_vuln_scan` | Static secret/anti-pattern scan of a source tree | target allowlist (paths), rate limit |
| `sec_file_hash` | md5/sha1/sha256/sha512/blake2b over a file | rate limit |
| `sec_tls_inspect` | TLS cert summary: subject, issuer, SANs, expiry, protocol, cipher | target allowlist, rate limit |
| `sec_http_headers` | Security header audit (HSTS, CSP, XFO, ...) with an A to F grade | target allowlist (URL hostname), rate limit |

Plus one MCP resource: `audit://recent` exposes the last 50 audit entries, so the agent (and you, from the client) can review what was actually executed.

## Quickstart

```bash
git clone https://github.com/joemunene-by/secure-mcp.git
cd secure-mcp
pip install -e .

# Sanity check
pytest -q

# Start the MCP server (stdio transport)
python -m secure_mcp.server
```

### Wire into Claude Desktop

Add `examples/claude_desktop_config.json` to your Claude Desktop config (update absolute paths):

```json
{
  "mcpServers": {
    "secure-mcp": {
      "command": "python",
      "args": ["-m", "secure_mcp.server"],
      "env": {
        "SECURE_MCP_POLICY": "/absolute/path/to/secure-mcp/policies/default.yaml",
        "SECURE_MCP_AUDIT": "/absolute/path/to/secure-mcp/audit.jsonl",
        "PYTHONPATH": "/absolute/path/to/secure-mcp/src"
      }
    }
  }
}
```

Restart Claude Desktop. The seven `sec_*` tools appear in the tools panel.

## Policy

Policy lives in `policies/default.yaml`. Example:

```yaml
tools:
  port_scan:
    enabled: true
    target_allowlist:
      - "127.0.0.1"
      - "10.0.0.0/8"
    max_ports: 100
    rate_limit:
      per_minute: 10
```

- `target_allowlist` supports IPv4/IPv6, CIDR (`10.0.0.0/8`), suffix wildcards (`*.example.com`), and, new in 0.2, absolute directory paths (`/home/me/projects`) for filesystem tools like `vuln_scan`. Path entries match the directory and anything inside it, with `..` and symlinks resolved before matching. `*` matches everything, so use it sparingly.
- An empty or missing `target_allowlist` for a target-requiring tool denies **all** targets. Fail closed.
- Point `SECURE_MCP_POLICY` at a different file to run multiple profiles (lab vs. prod-safe).

## Audit log

Every tool call writes one JSON object per line to `audit.jsonl`:

```json
{"ts":"2026-04-17T18:42:11+00:00","pid":1234,"tool":"port_scan","args":{"host":"127.0.0.1","ports":[22,80]},"outcome":"ok"}
{"ts":"2026-04-17T18:42:14+00:00","pid":1234,"tool":"port_scan","args":{"host":"8.8.8.8","ports":[22]},"outcome":"denied","detail":"policy: target '8.8.8.8' is not permitted for tool 'port_scan'"}
```

Outcomes: `ok`, `denied` (policy), `error` (execution). Tail with `jq -c` for a live view.

## Architecture

```
  LLM / Agent
      │  (MCP protocol)
      ▼
┌───────────────────────┐
│  FastMCP server       │   src/secure_mcp/server.py
│  ├─ policy guard      │   src/secure_mcp/policy.py
│  ├─ sandbox runner    │   src/secure_mcp/sandbox.py
│  └─ audit logger      │   src/secure_mcp/audit.py
└───────────────────────┘
      │
      ▼
  Tool implementations   src/secure_mcp/tools/
```

Each tool is gated by `_guard(name, target?)` → `check_enabled` → `check_target` → `check_rate_limit`. Violations raise `PolicyViolation` and are logged as `denied` without executing.

## Roadmap

- `v0.2` (shipped): MCP resource for the audit log tail, TLS inspection, HTTP security header audit, path allowlists.
- `v0.3`: Docker-based sandbox profile, policy DSL with per-role allowlists, time-of-day gates, and cost budgets.
- `v0.4`: Web dashboard for the audit log and policy editing, traffic capture tool.

## Related projects

Built by [@joemunene-by](https://github.com/joemunene-by). Companion repos:

- [`ghostguard`](https://github.com/joemunene-by/ghostguard): policy-pipeline proxy for LLM tool calls
- [`ghostsiem`](https://github.com/joemunene-by/ghostsiem): SIGMA-based detection and alerting
- [`ghostforensics`](https://github.com/joemunene-by/ghostforensics): memory forensics automation

## License

MIT. See [LICENSE](./LICENSE).
