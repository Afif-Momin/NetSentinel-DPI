"""
detection/flow_tracker.py
=========================
5-tuple flow tracking with direction-independent canonical keys,
basic TCP state machine, and per-flow byte/packet counters.

Cross-platform: pure Python stdlib + scapy, no OS calls.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Iterator, Optional, Tuple

# Scapy layer aliases (imported lazily in functions to keep module importable
# without scapy for unit tests that mock at packet level).
try:
    from scapy.packet import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore[misc,assignment]


# ─────────────────────────────────────────────────────────────────────────────
# Types
# ─────────────────────────────────────────────────────────────────────────────

#: (proto, src_ip, src_port, dst_ip, dst_port)  — always low → high IP pair
FlowKey = Tuple[str, str, int, str, int]


class Protocol(str, Enum):
    """High-level protocol label for a flow."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class TcpState(Enum):
    """Simplified TCP state machine states."""
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT = auto()
    CLOSED = auto()
    UNKNOWN = auto()


# ─────────────────────────────────────────────────────────────────────────────
# Flow record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Flow:
    """Represents a bidirectional network flow (connection)."""

    key: FlowKey
    """Canonical 5-tuple (proto, lo_ip, lo_port, hi_ip, hi_port)."""

    proto: Protocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Packet / byte counters per direction
    fwd_packets: int = 0          # initiator → responder
    fwd_bytes: int = 0
    bwd_packets: int = 0          # responder → initiator
    bwd_bytes: int = 0

    tcp_state: TcpState = TcpState.UNKNOWN

    # Payload reassembly buffers (filled by tcp_reassembly module)
    fwd_payload: bytes = b""
    bwd_payload: bytes = b""

    # Parsed application-layer data (filled by parsers)
    http_requests: list = field(default_factory=list)   # list[HttpRequest]
    dns_queries: list = field(default_factory=list)     # list[DnsQuery]
    tls_hellos: list = field(default_factory=list)      # list[TlsClientHello]

    # Detection engine annotations
    alerts: list = field(default_factory=list)          # list[Alert]
    tags: list = field(default_factory=list)            # list[str]

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def __repr__(self) -> str:
        return (
            f"Flow({self.proto.value} {self.src_ip}:{self.src_port} → "
            f"{self.dst_ip}:{self.dst_port}, "
            f"pkts={self.total_packets}, bytes={self.total_bytes})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Flow tracker
# ─────────────────────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a table of active :class:`Flow` objects keyed by their canonical
    5-tuple.  Direction-independent: packets in either direction map to the
    same flow.

    Parameters
    ----------
    timeout_tcp : float
        Seconds of inactivity before a TCP flow is considered expired.
    timeout_udp : float
        Seconds of inactivity before a UDP/ICMP flow is considered expired.
    """

    def __init__(
        self,
        timeout_tcp: float = 300.0,
        timeout_udp: float = 60.0,
    ) -> None:
        self._flows: Dict[FlowKey, Flow] = {}
        self.timeout_tcp = timeout_tcp
        self.timeout_udp = timeout_udp
        # Stats
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.expired_flows: int = 0

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def process_packet(self, pkt: "Packet") -> Optional[Flow]:
        """
        Extract flow metadata from *pkt* and update (or create) the matching
        :class:`Flow`.

        Returns the updated :class:`Flow`, or ``None`` if the packet carries
        no network-layer information we can track.
        """
        if not _SCAPY_OK:
            return None

        info = _extract_packet_info(pkt)
        if info is None:
            return None

        src_ip, dst_ip, src_port, dst_port, proto, payload_len, tcp_flags = info
        self.total_packets += 1
        self.total_bytes += payload_len

        key = _make_key(proto, src_ip, src_port, dst_ip, dst_port)
        is_forward = _is_forward(key, src_ip, src_port)

        if key not in self._flows:
            flow = Flow(
                key=key,
                proto=Protocol(proto),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                start_time=float(getattr(pkt, "time", time.time())),
                last_seen=float(getattr(pkt, "time", time.time())),
            )
            self._flows[key] = flow
        else:
            flow = self._flows[key]

        # Update counters
        now = float(getattr(pkt, "time", time.time()))
        flow.last_seen = now

        if is_forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += payload_len
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += payload_len

        # TCP state machine
        if proto == "TCP" and tcp_flags is not None:
            _update_tcp_state(flow, tcp_flags)

        # TCP Reassembly and App-layer Parsers
        if proto == "TCP":
            from parser.tcp_reassembly import TcpReassembler
            from parser.http_parser import HttpParser
            from parser.tls_parser import TlsParser

            # TCP Reassembly
            if not hasattr(self, "_reassemblers"):
                self._reassemblers: Dict[FlowKey, TcpReassembler] = {}
            if key not in self._reassemblers:
                self._reassemblers[key] = TcpReassembler()
            
            reassembler = self._reassemblers[key]
            is_c2s = (src_ip == flow.src_ip and src_port == flow.src_port)
            fwd_payload, bwd_payload = reassembler.add_packet(pkt, is_c2s)
            flow.fwd_payload = fwd_payload
            flow.bwd_payload = bwd_payload

            # HTTP Parsing (from reassembled stream)
            if flow.fwd_payload:
                try:
                    flow.http_requests = HttpParser(flow.fwd_payload).parse_requests()
                except Exception:
                    pass

            # TLS ClientHello / JA3 Parsing
            try:
                hello = TlsParser().parse_packet(pkt)
                if hello and hello.ja3 not in [h.ja3 for h in flow.tls_hellos]:
                    flow.tls_hellos.append(hello)
            except Exception:
                pass

        elif proto == "UDP":
            from parser.dns_parser import DnsParser
            try:
                query = DnsParser().parse(pkt)
                if query:
                    # Avoid duplicate DNS queries from duplicate packets if needed, or just append
                    flow.dns_queries.append(query)
            except Exception:
                pass

        return flow

    def flows(self) -> Iterator[Flow]:
        """Iterate over all tracked flows (active and expired)."""
        yield from self._flows.values()

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Look up a flow by its canonical key."""
        return self._flows.get(key)

    def expire_old_flows(self, now: Optional[float] = None) -> int:
        """
        Remove flows that have been idle longer than their protocol timeout.

        Returns the number of flows removed.
        """
        if now is None:
            now = time.time()
        to_remove = []
        for key, flow in self._flows.items():
            timeout = (
                self.timeout_tcp
                if flow.proto == Protocol.TCP
                else self.timeout_udp
            )
            if (now - flow.last_seen) > timeout:
                to_remove.append(key)
        for key in to_remove:
            del self._flows[key]
        self.expired_flows += len(to_remove)
        return len(to_remove)

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def protocol_breakdown(self) -> Dict[str, int]:
        """Return {proto_name: flow_count} dict."""
        breakdown: Dict[str, int] = {}
        for flow in self._flows.values():
            breakdown[flow.proto.value] = breakdown.get(flow.proto.value, 0) + 1
        return breakdown

    @property
    def top_talkers(self) -> list:
        """Return top 10 source IPs by total bytes, as list of (ip, bytes)."""
        tally: Dict[str, int] = {}
        for flow in self._flows.values():
            tally[flow.src_ip] = tally.get(flow.src_ip, 0) + flow.total_bytes
        return sorted(tally.items(), key=lambda x: x[1], reverse=True)[:10]


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_packet_info(
    pkt: "Packet",
) -> Optional[Tuple[str, str, int, int, str, int, Optional[int]]]:
    """
    Pull (src_ip, dst_ip, src_port, dst_port, proto_str, payload_len, tcp_flags)
    from a scapy packet.  Returns None for non-IP packets.
    """
    # Determine IP layer
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip: str = ip.src
        dst_ip: str = ip.dst
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip = ip6.src
        dst_ip = ip6.dst
    else:
        return None

    src_port = dst_port = 0
    tcp_flags: Optional[int] = None
    payload_len: int = len(pkt)

    if pkt.haslayer(TCP):
        proto = "TCP"
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        tcp_flags = int(tcp.flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    else:
        proto = "OTHER"

    return src_ip, dst_ip, src_port, dst_port, proto, payload_len, tcp_flags


def _make_key(
    proto: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> FlowKey:
    """
    Build a direction-independent canonical 5-tuple key.
    The IP/port pair that compares lower (lexicographically) is placed first.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (proto, lo[0], lo[1], hi[0], hi[1])


def _is_forward(key: FlowKey, src_ip: str, src_port: int) -> bool:
    """
    Return True if (src_ip, src_port) is the *low* side of the canonical key
    (i.e., the forward / initiator direction).
    """
    _, lo_ip, lo_port, _, _ = key
    return (src_ip, src_port) == (lo_ip, lo_port)


# TCP flag bit masks (RFC 793 / scapy integer representation)
_F_SYN = 0x02
_F_ACK = 0x10
_F_FIN = 0x01
_F_RST = 0x04


def _update_tcp_state(flow: Flow, flags: int) -> None:
    """Advance the TCP state machine based on observed flags."""
    state = flow.tcp_state

    if flags & _F_RST:
        flow.tcp_state = TcpState.CLOSED
        return

    if state == TcpState.UNKNOWN:
        if (flags & _F_SYN) and not (flags & _F_ACK):
            flow.tcp_state = TcpState.SYN_SENT
    elif state == TcpState.SYN_SENT:
        if (flags & _F_SYN) and (flags & _F_ACK):
            flow.tcp_state = TcpState.SYN_RECEIVED
    elif state == TcpState.SYN_RECEIVED:
        if (flags & _F_ACK) and not (flags & _F_SYN):
            flow.tcp_state = TcpState.ESTABLISHED
    elif state == TcpState.ESTABLISHED:
        if flags & _F_FIN:
            flow.tcp_state = TcpState.FIN_WAIT
    elif state == TcpState.FIN_WAIT:
        if flags & _F_FIN:
            flow.tcp_state = TcpState.CLOSED
