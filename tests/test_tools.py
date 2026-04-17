from __future__ import annotations

import hashlib
import socket
import struct

import pytest

from secure_mcp.tools import dns_lookup, file_hash, metadata_scrub, port_scan, vuln_scan


# --- port_scan -------------------------------------------------------------

def test_port_scan_open_port(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        result = port_scan.scan("127.0.0.1", [port], timeout=0.5)
    assert port in result["open_ports"]
    assert result["resolved"] == "127.0.0.1"


def test_port_scan_unresolvable():
    result = port_scan.scan("this.host.should.not.resolve.invalid", [80])
    assert "error" in result


# --- dns_lookup ------------------------------------------------------------

def test_dns_lookup_localhost():
    result = dns_lookup.lookup("localhost")
    assert "error" not in result
    assert "127.0.0.1" in result["a"] or result["aaaa"]


def test_dns_lookup_bad_host():
    result = dns_lookup.lookup("totally.invalid.nonexistent.tld.example")
    assert "error" in result


# --- metadata_scrub --------------------------------------------------------

def _synth_jpeg_with_exif() -> bytes:
    # SOI + APP1(EXIF-ish) + SOS-free COM + EOI (not a fully valid JPEG, but parseable)
    soi = b"\xff\xd8"
    app1_payload = b"Exif\x00\x00" + b"FAKE_EXIF_METADATA"
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    com_payload = b"secret comment"
    com = b"\xff\xfe" + struct.pack(">H", len(com_payload) + 2) + com_payload
    eoi = b"\xff\xd9"
    return soi + app1 + com + eoi


def _synth_png_with_text() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    text_data = b"Comment\x00this is metadata"
    text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + b"\x00\x00\x00\x00"
    iend = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return sig + text_chunk + iend


def test_metadata_scrub_jpeg_removes_app1_and_com(tmp_path):
    src = tmp_path / "in.jpg"
    dst = tmp_path / "out.jpg"
    src.write_bytes(_synth_jpeg_with_exif())
    result = metadata_scrub.scrub(str(src), str(dst))
    assert result["format"] == "jpeg"
    assert "APP1" in result["segments_removed"]
    assert "COM" in result["segments_removed"]
    cleaned = dst.read_bytes()
    assert b"FAKE_EXIF_METADATA" not in cleaned
    assert b"secret comment" not in cleaned


def test_metadata_scrub_png_removes_text(tmp_path):
    src = tmp_path / "in.png"
    dst = tmp_path / "out.png"
    src.write_bytes(_synth_png_with_text())
    result = metadata_scrub.scrub(str(src), str(dst))
    assert result["format"] == "png"
    assert "tEXt" in result["segments_removed"]
    assert b"this is metadata" not in dst.read_bytes()


def test_metadata_scrub_unsupported(tmp_path):
    src = tmp_path / "in.txt"
    src.write_bytes(b"not an image")
    result = metadata_scrub.scrub(str(src), str(tmp_path / "out"))
    assert "unsupported" in result["error"]


# --- vuln_scan -------------------------------------------------------------

def test_vuln_scan_finds_aws_key(tmp_path):
    (tmp_path / "leaky.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "def bad():\n"
        "    eval(user_input)\n"
    )
    result = vuln_scan.scan(str(tmp_path))
    patterns_found = {f["pattern"] for f in result["findings"]}
    assert "aws_access_key" in patterns_found
    assert "eval_exec_usage" in patterns_found


def test_vuln_scan_missing_path(tmp_path):
    result = vuln_scan.scan(str(tmp_path / "nope"))
    assert "error" in result


# --- file_hash -------------------------------------------------------------

def test_file_hash_sha256(tmp_path):
    payload = b"hello world"
    p = tmp_path / "f.bin"
    p.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    result = file_hash.hash_file(str(p))
    assert result["hashes"]["sha256"] == expected
    assert result["size_bytes"] == len(payload)


def test_file_hash_multi_alg(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    result = file_hash.hash_file(str(p), ["md5", "sha1"])
    assert set(result["hashes"]) == {"md5", "sha1"}


def test_file_hash_unsupported(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    result = file_hash.hash_file(str(p), ["rot13"])
    assert "unsupported" in result["error"]


def test_file_hash_missing(tmp_path):
    result = file_hash.hash_file(str(tmp_path / "missing"))
    assert "not found" in result["error"]
