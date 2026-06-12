"""Async TCP connect scan against an allowlisted host."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass


NAME = "port_scan"


@dataclass
class PortResult:
    port: int
    open: bool


async def _probe(host: str, port: int, timeout: float) -> PortResult:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(port=port, open=True)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False)


async def _scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)

    async def bounded(p: int) -> PortResult:
        async with sem:
            return await _probe(host, p, timeout)

    return await asyncio.gather(*(bounded(p) for p in ports))


def scan(host: str, ports: list[int], *, timeout: float = 1.0, concurrency: int = 50) -> dict:
    """Run a TCP connect scan. Returns a dict with open_ports and resolved address."""
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        return {"host": host, "error": f"invalid ports (must be 1-65535): {invalid[:10]}"}

    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"host": host, "error": f"could not resolve host: {e}"}

    results = asyncio.run(_scan(resolved, ports, timeout, concurrency))
    open_ports = sorted(r.port for r in results if r.open)
    return {
        "host": host,
        "resolved": resolved,
        "scanned": len(ports),
        "open_ports": open_ports,
    }
