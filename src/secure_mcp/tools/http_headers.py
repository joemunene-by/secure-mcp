"""Security-header audit: fetch response headers and grade the usual suspects."""

from __future__ import annotations

import http.client
import ssl
from urllib.parse import urlsplit


NAME = "http_headers"

DEFAULT_TIMEOUT_S = 10.0
MAX_REDIRECTS = 0  # never follow redirects; report them instead

# Header -> why it matters. Checked case-insensitively.
EXPECTED_HEADERS: dict[str, str] = {
    "strict-transport-security": "enforces HTTPS on returning visitors",
    "content-security-policy": "mitigates XSS and injection",
    "x-content-type-options": "blocks MIME sniffing (should be 'nosniff')",
    "x-frame-options": "mitigates clickjacking (or use CSP frame-ancestors)",
    "referrer-policy": "limits referrer leakage",
    "permissions-policy": "restricts powerful browser features",
}

# Headers that leak implementation details and are better removed.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def check(url: str, *, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    """HEAD-then-GET the URL and report present/missing security headers."""
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if parts.scheme not in ("http", "https"):
        return {"url": url, "error": f"unsupported scheme: {parts.scheme}"}
    if not parts.hostname:
        return {"url": url, "error": "could not parse a hostname from the URL"}

    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"

    try:
        status, reason, headers = _fetch(parts, path, timeout)
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        return {"url": url, "error": f"request failed: {e}"}

    lower = {k.lower(): v for k, v in headers}

    present = {h: lower[h] for h in EXPECTED_HEADERS if h in lower}
    missing = {h: why for h, why in EXPECTED_HEADERS.items() if h not in lower}
    disclosure = {h: lower[h] for h in DISCLOSURE_HEADERS if h in lower}

    notes: list[str] = []
    if parts.scheme == "http":
        notes.append("plain HTTP: headers like HSTS only count over HTTPS")
    if 300 <= status < 400 and "location" in lower:
        notes.append(f"redirects to {lower['location']}; headers below are the redirect's")
    nosniff = lower.get("x-content-type-options", "")
    if nosniff and nosniff.strip().lower() != "nosniff":
        notes.append(f"x-content-type-options is '{nosniff}', expected 'nosniff'")

    return {
        "url": url,
        "status": status,
        "reason": reason,
        "present": present,
        "missing": missing,
        "disclosure": disclosure,
        "notes": notes,
        "grade": _grade(len(present), len(EXPECTED_HEADERS)),
    }


def _fetch(parts, path: str, timeout: float) -> tuple[int, str, list[tuple[str, str]]]:
    host = parts.hostname
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # header audit, not trust validation
        conn = http.client.HTTPSConnection(host, parts.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "secure-mcp/0.2"})
        resp = conn.getresponse()
        # Drain a little so the connection closes cleanly, but never buffer a body.
        resp.read(0)
        return resp.status, resp.reason, resp.getheaders()
    finally:
        conn.close()


def _grade(present: int, total: int) -> str:
    ratio = present / total if total else 0.0
    if ratio >= 0.99:
        return "A"
    if ratio >= 0.8:
        return "B"
    if ratio >= 0.5:
        return "C"
    if ratio > 0:
        return "D"
    return "F"
