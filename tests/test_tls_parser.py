"""
tests/test_tls_parser.py
=========================
Unit tests for parser/tls_parser.py — JA3 fingerprint implementation.
Constructs synthetic TLS ClientHello bytes to verify correctness.
No live network access or elevated privileges required.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from parser.tls_parser import TlsParser, TlsClientHello, _GREASE


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic TLS ClientHello builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_sni_extension(hostname: str) -> bytes:
    name = hostname.encode()
    # host_name entry: type(1) + name_len(2) + name
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    # sni_list: list_len(2) + entry
    sni_list = struct.pack("!H", len(entry)) + entry
    return sni_list


def _build_supported_groups_ext(groups: list) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in groups)
    return struct.pack("!H", len(body)) + body


def _build_ec_point_formats_ext(fmts: list) -> bytes:
    return bytes([len(fmts)] + fmts)


def _build_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _build_client_hello(
    version: int = 0x0303,
    ciphers: list = None,
    extensions_list: list = None,
    groups: list = None,
    point_fmts: list = None,
    sni: str = "",
) -> bytes:
    """Build a minimal TLS ClientHello handshake record."""
    if ciphers is None:
        ciphers = [0x002F, 0x0035]  # RSA AES128/256
    if groups is None:
        groups = [0x0017, 0x0018]  # secp256r1, secp384r1
    if point_fmts is None:
        point_fmts = [0]

    # Cipher suite bytes
    cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)

    # Build extensions
    exts = b""
    if sni:
        exts += _build_extension(0x0000, _build_sni_extension(sni))
    if groups:
        exts += _build_extension(0x000A, _build_supported_groups_ext(groups))
    if point_fmts:
        exts += _build_extension(0x000B, _build_ec_point_formats_ext(point_fmts))
    if extensions_list:
        for ext_type, ext_data in extensions_list:
            exts += _build_extension(ext_type, ext_data)

    ext_block = struct.pack("!H", len(exts)) + exts

    # ClientHello body
    body = (
        struct.pack("!H", version) +   # client_version
        b"\x00" * 32 +                 # random
        b"\x00" +                      # session_id length = 0
        struct.pack("!H", len(cs_bytes)) + cs_bytes +
        b"\x01\x00" +                  # compression methods: 1 byte, null
        ext_block
    )

    # Handshake header: type(1) + length(3)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body

    # TLS record: content_type(1) + version(2) + length(2) + hs
    record = b"\x16" + struct.pack("!HH", 0x0301, len(hs)) + hs
    return record


# ─────────────────────────────────────────────────────────────────────────────
# TlsParser tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_basic_client_hello():
    raw = _build_client_hello(ciphers=[0x002F, 0x0035], sni="example.com")
    parser = TlsParser()
    hello = parser.parse_bytes(raw)
    assert hello is not None
    assert hello.tls_version == 0x0303
    assert 0x002F in hello.cipher_suites
    assert 0x0035 in hello.cipher_suites
    assert hello.sni == "example.com"


def test_parse_elliptic_curves():
    raw = _build_client_hello(groups=[0x0017, 0x0018], sni="")
    hello = TlsParser().parse_bytes(raw)
    assert hello is not None
    assert 0x0017 in hello.elliptic_curves
    assert 0x0018 in hello.elliptic_curves


def test_parse_ec_point_formats():
    raw = _build_client_hello(point_fmts=[0])
    hello = TlsParser().parse_bytes(raw)
    assert hello is not None
    assert 0 in hello.ec_point_formats


def test_grease_values_excluded():
    grease_val = 0x0A0A
    raw = _build_client_hello(ciphers=[grease_val, 0x002F])
    hello = TlsParser().parse_bytes(raw)
    assert hello is not None
    assert grease_val not in hello.cipher_suites
    assert 0x002F in hello.cipher_suites


def test_grease_in_groups_excluded():
    grease_val = 0x0A0A
    raw = _build_client_hello(groups=[grease_val, 0x0017])
    hello = TlsParser().parse_bytes(raw)
    assert grease_val not in hello.elliptic_curves
    assert 0x0017 in hello.elliptic_curves


def test_non_tls_data_returns_none():
    parser = TlsParser()
    assert parser.parse_bytes(b"HTTP/1.1 200 OK\r\n") is None
    assert parser.parse_bytes(b"") is None
    assert parser.parse_bytes(b"\x00\x00\x00") is None


def test_ja3_string_format():
    hello = TlsClientHello(
        tls_version=0x0303,
        cipher_suites=[0x002F, 0x0035],
        extensions=[0, 10, 11],
        elliptic_curves=[0x0017],
        ec_point_formats=[0],
    )
    parts = hello.ja3_string.split(",")
    assert len(parts) == 5
    assert parts[0] == str(0x0303)


def test_ja3_fingerprint_is_md5():
    hello = TlsClientHello(
        tls_version=0x0303,
        cipher_suites=[0x002F, 0x0035],
        extensions=[0, 10, 11],
        elliptic_curves=[0x0017],
        ec_point_formats=[0],
    )
    expected = hashlib.md5(hello.ja3_string.encode()).hexdigest()
    assert hello.ja3 == expected
    assert len(hello.ja3) == 32


def test_ja3_deterministic():
    """Same inputs → same JA3 fingerprint every time."""
    hello1 = TlsClientHello(tls_version=0x0303, cipher_suites=[0x002F])
    hello2 = TlsClientHello(tls_version=0x0303, cipher_suites=[0x002F])
    assert hello1.ja3 == hello2.ja3


def test_ja3_different_ciphers_different_fingerprint():
    hello1 = TlsClientHello(tls_version=0x0303, cipher_suites=[0x002F])
    hello2 = TlsClientHello(tls_version=0x0303, cipher_suites=[0x0035])
    assert hello1.ja3 != hello2.ja3
