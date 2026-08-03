"""
detection/dns_detectors.py
===========================
DNS-layer detection helpers used by the engine.
Stand-alone functions testable without live packets.
"""
from __future__ import annotations

import math
import re
from typing import Optional

from parser.dns_parser import DnsQuery


_DGA_RE = re.compile(r"^[a-z0-9]{15,}\.")
_LONG_QNAME_RE = re.compile(r"^.{50,}\.")
_ONION_RE = re.compile(r"\.onion\.?$", re.IGNORECASE)
_DDNS_RE = re.compile(
    r"(?i)(dyndns|no-ip|ddns|servebeer|servegame|hopto|zapto|sytes|"
    r"myftp|ddnsking|duckdns)\.(org|net|com|info)",
)


def check_high_entropy(query: DnsQuery, threshold: float = 3.8) -> Optional[str]:
    """Return detail string if first QNAME label entropy exceeds *threshold*."""
    ent = query.entropy
    if ent >= threshold:
        return f"entropy={ent:.2f} qname={query.qname[:60]}"
    return None


def check_long_qname(query: DnsQuery, threshold: int = 50) -> Optional[str]:
    if len(query.qname) >= threshold:
        return f"qname_len={len(query.qname)}"
    return None


def check_excessive_txt(query: DnsQuery, threshold: int = 5) -> Optional[str]:
    if query.txt_records >= threshold:
        return f"txt_count={query.txt_records}"
    return None


def check_onion(query: DnsQuery) -> Optional[str]:
    if _ONION_RE.search(query.qname):
        return query.qname[:80]
    return None


def check_dga_pattern(query: DnsQuery) -> Optional[str]:
    if _DGA_RE.match(query.qname):
        return query.qname[:80]
    return None


def check_ddns_abuse(query: DnsQuery) -> Optional[str]:
    m = _DDNS_RE.search(query.qname)
    return m.group(0)[:80] if m else None
