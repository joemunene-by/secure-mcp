# Changelog

## 0.2.0 (2026-06-12)

### Added
- `sec_tls_inspect` tool: TLS certificate summary for an allowlisted host.
  Reports subject, issuer, SANs, validity window, days until expiry, and the
  negotiated protocol and cipher. Accepts self-signed and expired certs by
  design, since the goal is inspection rather than trust validation.
- `sec_http_headers` tool: security header audit covering HSTS, CSP,
  X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and
  Permissions-Policy, with an A to F grade. Also flags disclosure headers
  such as `Server` and `X-Powered-By`. Redirects are reported, never
  followed. The policy allowlist matches the URL hostname.
- `audit://recent` MCP resource: the last 50 audit log entries as JSONL, so
  the client can review what the agent actually executed.
- `AuditLog.tail(n)` for programmatic audit access.
- Path entries in `target_allowlist`. Absolute directory paths now match the
  directory and anything inside it, with `..` and symlinks resolved before
  matching. This makes per-directory allowlisting for `vuln_scan` actually
  usable.
- Port range validation (1 to 65535) in `port_scan`.

### Fixed
- The default policy named the hash tool `hash_lookup`, but the server
  registers it as `file_hash`, so every `sec_file_hash` call was denied as
  "not configured" with the shipped policy. Renamed the policy entry and
  added a regression test that asserts every registered tool has an entry in
  `default.yaml`.
- PNG metadata scrub no longer trips on a truncated trailing chunk. Leftover
  bytes are copied through as-is.

## 0.1.0 (2026-05-12)

Initial MVP: policy engine (allowlists, rate limits), subprocess sandbox,
JSONL audit log, and five tools (`port_scan`, `dns_lookup`, `metadata_scrub`,
`vuln_scan`, `file_hash`).
