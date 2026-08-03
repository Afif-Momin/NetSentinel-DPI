"""
tests/test_dns_parser.py
=========================
Unit tests for parser/dns_parser.py and detection/dns_detectors.py
Uses scapy-generated synthetic packets. No live network required.
"""
from __future__ import annotations

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.all import Ether
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SCAPY_AVAILABLE, reason="scapy not installed"
)

from parser.dns_parser import DnsParser, DnsQuery, _shannon_entropy
from detection.dns_detectors import (
    check_high_entropy,
    check_long_qname,
    check_onion,
    check_dga_pattern,
    check_ddns_abuse,
)


def _make_dns_query_pkt(qname: str, qtype: str = "A") -> "Ether":
    return (
        Ether() /
        IP(src="192.168.1.1", dst="8.8.8.8") /
        UDP(sport=12345, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )


def _make_dns_response_pkt(qname: str, answer: str = "1.2.3.4") -> "Ether":
    return (
        Ether() /
        IP(src="8.8.8.8", dst="192.168.1.1") /
        UDP(sport=53, dport=12345) /
        DNS(
            qr=1, aa=1,
            qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, ttl=300, rdata=answer),
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# DnsParser tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_normal_query():
    pkt = _make_dns_query_pkt("example.com")
    parser = DnsParser()
    query = parser.parse(pkt)
    assert query is not None
    assert "example" in query.qname
    assert query.qtype == "A"
    assert query.is_response is False


def test_parse_response():
    pkt = _make_dns_response_pkt("example.com", "93.184.216.34")
    parser = DnsParser()
    query = parser.parse(pkt)
    assert query is not None
    assert query.is_response is True


def test_non_dns_packet_returns_none():
    from scapy.layers.inet import TCP
    pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP()
    parser = DnsParser()
    assert parser.parse(pkt) is None


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

def test_shannon_entropy_uniform():
    # "abcd" — each char once, maximum entropy for 4 chars = log2(4) = 2.0
    ent = _shannon_entropy("abcd")
    assert abs(ent - 2.0) < 0.01


def test_shannon_entropy_single_char():
    assert _shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_high_entropy_base64_label():
    # base64-encoded random data will have high entropy
    import base64, os
    rand = base64.b64encode(os.urandom(20)).decode().replace("=", "")
    query = DnsQuery(qname=f"{rand}.tunnel.evil.com", qtype="A")
    result = check_high_entropy(query, threshold=3.5)
    assert result is not None


def test_low_entropy_normal_label():
    query = DnsQuery(qname="example.com", qtype="A")
    result = check_high_entropy(query, threshold=3.8)
    # "example" has moderate entropy, should not trigger
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# DNS detector checks
# ─────────────────────────────────────────────────────────────────────────────

def test_check_long_qname():
    long_name = "a" * 55 + ".evil.com"
    query = DnsQuery(qname=long_name, qtype="A")
    assert check_long_qname(query, threshold=50) is not None


def test_check_short_qname_no_trigger():
    query = DnsQuery(qname="short.com", qtype="A")
    assert check_long_qname(query) is None


def test_check_onion():
    query = DnsQuery(qname="3g2upl4pq6kufc4m.onion", qtype="A")
    assert check_onion(query) is not None


def test_check_dga_pattern():
    query = DnsQuery(qname="xkcd1234567890abcdef.evil.com", qtype="A")
    assert check_dga_pattern(query) is not None


def test_check_ddns_abuse():
    query = DnsQuery(qname="malware-c2.duckdns.org", qtype="A")
    assert check_ddns_abuse(query) is not None


def test_check_normal_domain_no_false_positive():
    query = DnsQuery(qname="google.com", qtype="A")
    assert check_onion(query) is None
    assert check_dga_pattern(query) is None
    assert check_ddns_abuse(query) is None
