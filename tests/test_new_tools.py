"""Tests for the v0.2 tools: tls_inspect and http_headers."""

from __future__ import annotations

import http.server
import socket
import threading
from datetime import datetime, timezone

from secure_mcp.tools import http_headers, tls_inspect


# --- tls_inspect -------------------------------------------------------------

def test_tls_inspect_invalid_port():
    result = tls_inspect.inspect("127.0.0.1", 0)
    assert "error" in result


def test_tls_inspect_non_tls_endpoint():
    # A plain TCP listener that immediately closes; the handshake must fail cleanly.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        result = tls_inspect.inspect("127.0.0.1", port, timeout=2.0)
    assert "error" in result
    assert "handshake" in result["error"]


def test_tls_inspect_connection_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = tls_inspect.inspect("127.0.0.1", port, timeout=2.0)
    assert "error" in result


def test_parse_cert_date():
    parsed = tls_inspect._parse_cert_date("Jan  1 00:00:00 2030 GMT")
    assert parsed == datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert tls_inspect._parse_cert_date("garbage") is None
    assert tls_inspect._parse_cert_date(None) is None


# --- http_headers ------------------------------------------------------------

class _BareHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _HardenedHandler(_BareHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        self.end_headers()


def _serve(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_http_headers_all_missing():
    server = _serve(_BareHandler)
    try:
        port = server.server_address[1]
        result = http_headers.check(f"http://127.0.0.1:{port}/")
    finally:
        server.shutdown()
    assert result["status"] == 200
    assert result["present"] == {}
    assert set(result["missing"]) == set(http_headers.EXPECTED_HEADERS)
    assert result["grade"] == "F"
    # BaseHTTPRequestHandler sends a Server header, which should be flagged.
    assert "server" in result["disclosure"]
    assert any("plain HTTP" in n for n in result["notes"])


def test_http_headers_all_present():
    server = _serve(_HardenedHandler)
    try:
        port = server.server_address[1]
        result = http_headers.check(f"http://127.0.0.1:{port}/")
    finally:
        server.shutdown()
    assert result["missing"] == {}
    assert result["grade"] == "A"


def test_http_headers_bad_scheme():
    result = http_headers.check("ftp://example.com/file")
    assert "unsupported scheme" in result["error"]


def test_http_headers_connection_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = http_headers.check(f"http://127.0.0.1:{port}/")
    assert "error" in result
