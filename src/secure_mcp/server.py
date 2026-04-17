"""MCP server entrypoint. Wires policy, sandbox, audit, and tool wrappers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .audit import AuditLog
from .policy import Policy, PolicyViolation
from .tools import dns_lookup, file_hash, metadata_scrub, port_scan, vuln_scan


DEFAULT_POLICY_PATH = "policies/default.yaml"
DEFAULT_AUDIT_PATH = "audit.jsonl"


def _resolve(env_var: str, default: str) -> Path:
    return Path(os.environ.get(env_var, default)).resolve()


def build_server() -> FastMCP:
    policy_path = _resolve("SECURE_MCP_POLICY", DEFAULT_POLICY_PATH)
    audit_path = _resolve("SECURE_MCP_AUDIT", DEFAULT_AUDIT_PATH)

    if not policy_path.exists():
        raise FileNotFoundError(
            f"policy file not found at {policy_path}. "
            "Set SECURE_MCP_POLICY or create policies/default.yaml."
        )

    policy = Policy.load(policy_path)
    audit = AuditLog(audit_path)
    mcp = FastMCP("secure-mcp")

    def _guard(
        tool_name: str,
        args: dict[str, Any],
        *,
        target: str | None = None,
    ) -> None:
        policy.check_enabled(tool_name)
        if target is not None:
            policy.check_target(tool_name, target)
        policy.check_rate_limit(tool_name)

    def _run(tool_name: str, args: dict[str, Any], fn) -> dict:
        try:
            result = fn()
            audit.record(tool=tool_name, args=args, outcome="ok")
            return result
        except PolicyViolation as e:
            audit.record(tool=tool_name, args=args, outcome="denied", detail=str(e))
            return {"error": f"policy: {e}"}
        except Exception as e:
            audit.record(tool=tool_name, args=args, outcome="error", detail=repr(e))
            return {"error": f"execution: {e}"}

    @mcp.tool()
    def sec_port_scan(host: str, ports: list[int]) -> dict:
        """TCP connect scan against an allowlisted host. Returns open ports.

        Only targets in the policy's port_scan.target_allowlist are permitted.
        `ports` length is capped by policy.max_ports.
        """
        args = {"host": host, "ports": ports}

        def call() -> dict:
            _guard(port_scan.NAME, args, target=host)
            max_ports = policy.tool(port_scan.NAME).max_ports
            if max_ports is not None and len(ports) > max_ports:
                raise PolicyViolation(
                    f"requested {len(ports)} ports; policy max is {max_ports}"
                )
            return port_scan.scan(host, ports)

        return _run(port_scan.NAME, args, call)

    @mcp.tool()
    def sec_dns_lookup(host: str) -> dict:
        """Resolve A/AAAA records for a host via stdlib getaddrinfo."""
        args = {"host": host}

        def call() -> dict:
            _guard(dns_lookup.NAME, args, target=host)
            return dns_lookup.lookup(host)

        return _run(dns_lookup.NAME, args, call)

    @mcp.tool()
    def sec_metadata_scrub(input_path: str, output_path: str) -> dict:
        """Strip EXIF/metadata from a JPEG or PNG file. Returns removed segments."""
        args = {"input_path": input_path, "output_path": output_path}

        def call() -> dict:
            _guard(metadata_scrub.NAME, args)
            return metadata_scrub.scrub(input_path, output_path)

        return _run(metadata_scrub.NAME, args, call)

    @mcp.tool()
    def sec_vuln_scan(root: str) -> dict:
        """Static scan of a source tree for secrets and insecure patterns."""
        args = {"root": root}

        def call() -> dict:
            _guard(vuln_scan.NAME, args, target=root)
            return vuln_scan.scan(root)

        return _run(vuln_scan.NAME, args, call)

    @mcp.tool()
    def sec_file_hash(path: str, algorithms: list[str] | None = None) -> dict:
        """Compute cryptographic hashes (md5, sha1, sha256, sha512, blake2b) of a file."""
        args = {"path": path, "algorithms": algorithms or ["sha256"]}

        def call() -> dict:
            _guard(file_hash.NAME, args)
            return file_hash.hash_file(path, algorithms)

        return _run(file_hash.NAME, args, call)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
