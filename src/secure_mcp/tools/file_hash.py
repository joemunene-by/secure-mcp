"""Compute cryptographic hashes of a file. Useful for IOC generation and integrity checks."""

from __future__ import annotations

import hashlib
from pathlib import Path


NAME = "file_hash"

SUPPORTED = ("md5", "sha1", "sha256", "sha512", "blake2b")
CHUNK = 1024 * 1024


def hash_file(path: str, algorithms: list[str] | None = None) -> dict:
    algs = algorithms or ["sha256"]
    for a in algs:
        if a not in SUPPORTED:
            return {"error": f"unsupported algorithm: {a}. supported: {list(SUPPORTED)}"}

    p = Path(path)
    if not p.exists():
        return {"error": f"file not found: {path}"}
    if not p.is_file():
        return {"error": f"not a regular file: {path}"}

    hashers = {a: hashlib.new(a) for a in algs}
    size = 0
    with open(p, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            for h in hashers.values():
                h.update(chunk)

    return {
        "path": str(p),
        "size_bytes": size,
        "hashes": {a: h.hexdigest() for a, h in hashers.items()},
    }
