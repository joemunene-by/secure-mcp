"""Strip EXIF/metadata from images without external dependencies.

Supports JPEG (APPn segments) and PNG (tEXt/iTXt/zTXt/tIME chunks).
Writes the cleaned bytes to an output path and returns a summary of what was removed.
"""

from __future__ import annotations

import struct
from pathlib import Path


NAME = "metadata_scrub"

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_METADATA_CHUNKS = {b"tEXt", b"iTXt", b"zTXt", b"tIME", b"eXIf"}


def scrub(input_path: str, output_path: str) -> dict:
    src = Path(input_path)
    dst = Path(output_path)
    if not src.exists():
        return {"error": f"input not found: {input_path}"}

    data = src.read_bytes()
    if data.startswith(JPEG_SOI):
        cleaned, removed = _scrub_jpeg(data)
        fmt = "jpeg"
    elif data.startswith(PNG_SIG):
        cleaned, removed = _scrub_png(data)
        fmt = "png"
    else:
        return {"error": "unsupported format (expected JPEG or PNG)"}

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(cleaned)
    return {
        "format": fmt,
        "input": str(src),
        "output": str(dst),
        "input_bytes": len(data),
        "output_bytes": len(cleaned),
        "segments_removed": removed,
    }


def _scrub_jpeg(data: bytes) -> tuple[bytes, list[str]]:
    out = bytearray(data[:2])  # SOI
    i = 2
    removed: list[str] = []
    while i < len(data):
        if data[i] != 0xFF:
            out.extend(data[i:])
            break
        marker = data[i + 1]
        if marker == 0xD9:  # EOI
            out.extend(data[i : i + 2])
            i += 2
            out.extend(data[i:])
            break
        if marker == 0xDA:  # SOS — copy rest verbatim (compressed scan data)
            out.extend(data[i:])
            break
        seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
        seg_end = i + 2 + seg_len
        if 0xE0 <= marker <= 0xEF:  # APPn — drop it
            removed.append(f"APP{marker - 0xE0}")
            i = seg_end
            continue
        if marker == 0xFE:  # COM — comment, drop it
            removed.append("COM")
            i = seg_end
            continue
        out.extend(data[i:seg_end])
        i = seg_end
    return bytes(out), removed


def _scrub_png(data: bytes) -> tuple[bytes, list[str]]:
    out = bytearray(data[:8])  # signature
    i = 8
    removed: list[str] = []
    while i < len(data):
        length = struct.unpack(">I", data[i : i + 4])[0]
        chunk_type = data[i + 4 : i + 8]
        chunk_end = i + 8 + length + 4  # length + type + data + CRC
        if chunk_type in PNG_METADATA_CHUNKS:
            removed.append(chunk_type.decode("ascii", errors="replace"))
            i = chunk_end
            continue
        out.extend(data[i:chunk_end])
        i = chunk_end
        if chunk_type == b"IEND":
            break
    return bytes(out), removed
