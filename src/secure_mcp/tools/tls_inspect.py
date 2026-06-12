"""TLS certificate inspection: connect, pull the leaf cert, summarize it."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone


NAME = "tls_inspect"

DEFAULT_TIMEOUT_S = 5.0
CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def inspect(host: str, port: int = 443, *, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    """Handshake with host:port and return certificate + connection details.

    Verification is disabled on purpose: the point is to inspect whatever cert
    the server presents, including expired or self-signed ones.
    """
    if not 1 <= port <= 65535:
        return {"host": host, "error": f"invalid port: {port}"}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                protocol = tls.version()
                cipher = tls.cipher()
    except (OSError, ssl.SSLError) as e:
        return {"host": host, "port": port, "error": f"could not complete TLS handshake: {e}"}

    if der is None:
        return {"host": host, "port": port, "error": "server presented no certificate"}

    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        **_summarize_cert(der),
    }


def _summarize_cert(der: bytes) -> dict:
    decoded = _decode_der(der)
    if decoded is None:
        return {"certificate": "presented but could not be decoded"}

    not_before = _parse_cert_date(decoded.get("notBefore"))
    not_after = _parse_cert_date(decoded.get("notAfter"))
    days_left = None
    if not_after is not None:
        days_left = (not_after - datetime.now(timezone.utc)).days

    return {
        "subject": _flatten_name(decoded.get("subject", ())),
        "issuer": _flatten_name(decoded.get("issuer", ())),
        "serial_number": decoded.get("serialNumber"),
        "not_before": not_before.isoformat() if not_before else decoded.get("notBefore"),
        "not_after": not_after.isoformat() if not_after else decoded.get("notAfter"),
        "days_until_expiry": days_left,
        "expired": days_left is not None and days_left < 0,
        "san": [v for k, v in decoded.get("subjectAltName", ()) if k == "DNS"],
        "self_signed": decoded.get("subject") == decoded.get("issuer"),
    }


def _decode_der(der: bytes) -> dict | None:
    # getpeercert() returns {} when verify_mode is CERT_NONE, so decode the DER
    # ourselves. CPython's _test_decode_cert is private but has been stable for
    # years and avoids pulling in a third-party ASN.1 dependency.
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return decode(path)
    except Exception:
        return None
    finally:
        os.unlink(path)


def _flatten_name(name: tuple) -> dict:
    out: dict[str, str] = {}
    for rdn in name:
        for key, value in rdn:
            out[key] = value
    return out


def _parse_cert_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw, CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
