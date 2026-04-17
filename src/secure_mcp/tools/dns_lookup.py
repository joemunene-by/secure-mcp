"""DNS lookup via stdlib socket. Returns A/AAAA records and canonical name."""

from __future__ import annotations

import socket


NAME = "dns_lookup"


def lookup(host: str) -> dict:
    results = {"host": host, "a": [], "aaaa": [], "canonical": None}

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return {"host": host, "error": str(e)}

    seen_a: set[str] = set()
    seen_aaaa: set[str] = set()
    for family, _type, _proto, canon, sockaddr in infos:
        if canon and not results["canonical"]:
            results["canonical"] = canon
        addr = sockaddr[0]
        if family == socket.AF_INET and addr not in seen_a:
            seen_a.add(addr)
            results["a"].append(addr)
        elif family == socket.AF_INET6 and addr not in seen_aaaa:
            seen_aaaa.add(addr)
            results["aaaa"].append(addr)
    return results
