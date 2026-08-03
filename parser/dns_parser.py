"""
parser/dns_parser.py
====================
Parse DNS queries and responses from scapy packets.

Extracts: QNAME, QTYPE, response code, answer TTLs, TXT record data.
Cross-platform: pure Python + scapy.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Packet
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DnsQuery:
    """Represents a single DNS query (and optionally its response)."""
    qname: str
    qtype: str            # "A", "AAAA", "MX", "TXT", …
    is_response: bool = False
    rcode: int = 0        # 0 = NOERROR
    ttls: List[int] = field(default_factory=list)
    txt_records: int = 0  # count of TXT answers
    answers: List[str] = field(default_factory=list)

    @property
    def entropy(self) -> float:
        """Shannon entropy of the first label of the QNAME."""
        first_label = self.qname.split(".")[0]
        return _shannon_entropy(first_label)

    def __repr__(self) -> str:
        return f"DnsQuery({self.qtype} {self.qname!r})"


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

class DnsParser:
    """
    Parse DNS data from a scapy packet.

    Usage::

        parser = DnsParser()
        query = parser.parse(pkt)
        if query:
            print(query.qname, query.entropy)
    """

    def parse(self, pkt: "Packet") -> Optional[DnsQuery]:
        """
        Extract a :class:`DnsQuery` from *pkt*.
        Returns ``None`` if *pkt* is not a DNS packet.
        """
        if not _SCAPY_OK or not pkt.haslayer(DNS):
            return None

        dns = pkt[DNS]
        if dns.qd is None:
            return None

        # Raw QNAME sometimes has trailing dot or b'' wrapper from scapy
        raw_qname = dns.qd.qname
        if isinstance(raw_qname, bytes):
            qname = raw_qname.decode("utf-8", errors="replace").rstrip(".")
        else:
            qname = str(raw_qname).rstrip(".")

        qtype_int = getattr(dns.qd, "qtype", 1)
        qtype = _qtype_name(qtype_int)

        query = DnsQuery(
            qname=qname,
            qtype=qtype,
            is_response=bool(dns.qr),
            rcode=int(getattr(dns, "rcode", 0)),
        )

        # Parse answers if this is a response
        if dns.qr and dns.an:
            rr = dns.an
            while rr:
                ttl = getattr(rr, "ttl", None)
                if ttl is not None:
                    query.ttls.append(int(ttl))
                rtype = getattr(rr, "type", 0)
                if rtype == 16:  # TXT
                    query.txt_records += 1
                    rdata = getattr(rr, "rdata", b"")
                    if isinstance(rdata, bytes):
                        query.answers.append(rdata.decode("utf-8", errors="replace"))
                    elif isinstance(rdata, list):
                        for part in rdata:
                            if isinstance(part, bytes):
                                query.answers.append(part.decode("utf-8", errors="replace"))
                elif rtype in (1, 28):  # A / AAAA
                    query.answers.append(str(getattr(rr, "rdata", "")))
                try:
                    rr = rr.payload
                    if not rr.haslayer(DNSRR):
                        break
                except Exception:
                    break

        return query


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _qtype_name(n: int) -> str:
    return _QTYPE_MAP.get(n, f"TYPE{n}")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
