"""
parser/tls_parser.py
====================
TLS ClientHello parser + JA3 fingerprint computation.

JA3 spec: https://github.com/salesforce/ja3
Fingerprint = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )

All fields are decimal integers joined by "-" within a group, groups joined by ",".
GREASE values (RFC 8701) are excluded from all fields before hashing.

Does NOT decrypt TLS traffic — purely passive analysis of the handshake.
Cross-platform: pure Python stdlib + scapy.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    from scapy.layers.inet import TCP
    from scapy.packet import Packet, Raw
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# GREASE values (RFC 8701)
# ─────────────────────────────────────────────────────────────────────────────

_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TlsClientHello:
    """Parsed TLS ClientHello fields and JA3 fingerprint."""

    tls_version: int                       # Handshake legacy version
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)  # extension type IDs
    elliptic_curves: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    sni: str = ""

    @property
    def ja3_string(self) -> str:
        """The raw JA3 string before hashing."""
        cs = "-".join(str(c) for c in self.cipher_suites if c not in _GREASE)
        exts = "-".join(str(e) for e in self.extensions if e not in _GREASE)
        curves = "-".join(str(c) for c in self.elliptic_curves if c not in _GREASE)
        fmts = "-".join(str(f) for f in self.ec_point_formats)
        return f"{self.tls_version},{cs},{exts},{curves},{fmts}"

    @property
    def ja3(self) -> str:
        """MD5 of the JA3 string (the canonical JA3 fingerprint)."""
        return hashlib.md5(self.ja3_string.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"TlsClientHello(sni={self.sni!r}, ja3={self.ja3})"


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

class TlsParser:
    """
    Detect and parse TLS ClientHello records from raw TCP payload bytes.

    Usage::

        parser = TlsParser()
        hello = parser.parse_bytes(raw_tcp_payload)
        if hello:
            print(hello.ja3)
    """

    # TLS content type for Handshake
    _TLS_HANDSHAKE = 0x16
    _TLS_CLIENT_HELLO = 0x01

    def parse_packet(self, pkt: "Packet") -> Optional[TlsClientHello]:
        """Extract TLS ClientHello from a scapy packet's TCP payload."""
        if not _SCAPY_OK:
            return None
        if not pkt.haslayer(TCP):
            return None
        payload = bytes(pkt[TCP].payload)
        return self.parse_bytes(payload)

    def parse_bytes(self, data: bytes) -> Optional[TlsClientHello]:
        """
        Parse a TLS ClientHello from raw bytes.
        Returns ``None`` if *data* is not a TLS ClientHello record.
        """
        if len(data) < 5:
            return None

        # TLS record header: content_type(1) + version(2) + length(2)
        content_type = data[0]
        if content_type != self._TLS_HANDSHAKE:
            return None

        record_len = struct.unpack("!H", data[3:5])[0]
        record = data[5: 5 + record_len]
        if len(record) < record_len:
            return None  # incomplete

        return self._parse_handshake(record)

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _parse_handshake(self, data: bytes) -> Optional[TlsClientHello]:
        if len(data) < 4:
            return None
        hs_type = data[0]
        if hs_type != self._TLS_CLIENT_HELLO:
            return None

        # Handshake length is 3 bytes big-endian
        hs_len = struct.unpack("!I", b"\x00" + data[1:4])[0]
        body = data[4: 4 + hs_len]
        if len(body) < hs_len:
            return None

        offset = 0

        # Client version (2 bytes)
        if offset + 2 > len(body):
            return None
        client_version = struct.unpack("!H", body[offset: offset + 2])[0]
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= len(body):
            return None
        sid_len = body[offset]
        offset += 1 + sid_len

        # Cipher suites
        if offset + 2 > len(body):
            return None
        cs_len = struct.unpack("!H", body[offset: offset + 2])[0]
        offset += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 > len(body):
                break
            cs = struct.unpack("!H", body[offset + i: offset + i + 2])[0]
            if cs not in _GREASE:
                cipher_suites.append(cs)
        offset += cs_len

        # Compression methods
        if offset >= len(body):
            return None
        comp_len = body[offset]
        offset += 1 + comp_len

        hello = TlsClientHello(
            tls_version=client_version,
            cipher_suites=cipher_suites,
        )

        # Extensions
        if offset + 2 > len(body):
            return hello
        ext_total = struct.unpack("!H", body[offset: offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end and offset + 4 <= len(body):
            ext_type = struct.unpack("!H", body[offset: offset + 2])[0]
            ext_len = struct.unpack("!H", body[offset + 2: offset + 4])[0]
            ext_data = body[offset + 4: offset + 4 + ext_len]
            offset += 4 + ext_len

            if ext_type not in _GREASE:
                hello.extensions.append(ext_type)

            # SNI (type 0)
            if ext_type == 0x0000 and len(ext_data) >= 5:
                sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
                if len(ext_data) >= 3 and ext_data[2] == 0x00:  # host_name type
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    hello.sni = ext_data[5: 5 + name_len].decode("utf-8", errors="replace")

            # Supported Groups / Elliptic Curves (type 10)
            elif ext_type == 0x000A and len(ext_data) >= 2:
                gl = struct.unpack("!H", ext_data[0:2])[0]
                for i in range(0, gl, 2):
                    if 2 + i + 2 > len(ext_data):
                        break
                    curve = struct.unpack("!H", ext_data[2 + i: 2 + i + 2])[0]
                    if curve not in _GREASE:
                        hello.elliptic_curves.append(curve)

            # EC Point Formats (type 11)
            elif ext_type == 0x000B and len(ext_data) >= 1:
                fmts_len = ext_data[0]
                for i in range(fmts_len):
                    if 1 + i < len(ext_data):
                        hello.ec_point_formats.append(ext_data[1 + i])

        return hello
