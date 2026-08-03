"""
tests/test_flow_tracker.py
===========================
Unit tests for detection/flow_tracker.py
Does NOT require elevated privileges or live network access.
"""
from __future__ import annotations

import sys
from pathlib import Path
import pytest

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.all import Ether
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SCAPY_AVAILABLE, reason="scapy not installed"
)

from detection.flow_tracker import FlowTracker, Protocol, TcpState, _make_key, _is_forward


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_pkt(src_ip, dst_ip, sport, dport, flags="S", seq=1000, ack=0):
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    )


def _udp_pkt(src_ip, dst_ip, sport, dport):
    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)


# ─────────────────────────────────────────────────────────────────────────────
# Canonical key tests
# ─────────────────────────────────────────────────────────────────────────────

def test_make_key_direction_independent():
    key_a = _make_key("TCP", "10.0.0.1", 54321, "192.168.1.1", 80)
    key_b = _make_key("TCP", "192.168.1.1", 80, "10.0.0.1", 54321)
    assert key_a == key_b


def test_make_key_different_protocols():
    tcp_key = _make_key("TCP", "1.2.3.4", 100, "5.6.7.8", 200)
    udp_key = _make_key("UDP", "1.2.3.4", 100, "5.6.7.8", 200)
    assert tcp_key != udp_key


def test_is_forward():
    key = _make_key("TCP", "10.0.0.1", 54321, "192.168.1.1", 80)
    # whichever side sorts lower is "forward"
    _, lo_ip, lo_port, hi_ip, hi_port = key
    assert _is_forward(key, lo_ip, lo_port) is True
    assert _is_forward(key, hi_ip, hi_port) is False


# ─────────────────────────────────────────────────────────────────────────────
# Flow creation tests
# ─────────────────────────────────────────────────────────────────────────────

def test_process_tcp_packet_creates_flow():
    tracker = FlowTracker()
    pkt = _tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="S")
    flow = tracker.process_packet(pkt)
    assert flow is not None
    assert flow.proto == Protocol.TCP
    assert tracker.flow_count == 1


def test_bidirectional_same_flow():
    tracker = FlowTracker()
    pkt_fwd = _tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="S")
    pkt_bwd = _tcp_pkt("93.184.216.34", "10.0.0.1", 80, 54321, flags="SA", seq=2000, ack=1001)
    tracker.process_packet(pkt_fwd)
    tracker.process_packet(pkt_bwd)
    assert tracker.flow_count == 1


def test_udp_flow():
    tracker = FlowTracker()
    pkt = _udp_pkt("172.16.0.1", "8.8.8.8", 53000, 53)
    flow = tracker.process_packet(pkt)
    assert flow is not None
    assert flow.proto == Protocol.UDP


def test_separate_flows_for_different_ports():
    tracker = FlowTracker()
    tracker.process_packet(_tcp_pkt("10.0.0.1", "192.168.1.1", 5001, 80))
    tracker.process_packet(_tcp_pkt("10.0.0.1", "192.168.1.1", 5002, 443))
    assert tracker.flow_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# Packet counters
# ─────────────────────────────────────────────────────────────────────────────

def test_packet_counters():
    tracker = FlowTracker()
    pkt_fwd = _tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="PA")
    pkt_bwd = _tcp_pkt("93.184.216.34", "10.0.0.1", 80, 54321, flags="PA")
    tracker.process_packet(pkt_fwd)
    tracker.process_packet(pkt_bwd)
    flow = list(tracker.flows())[0]
    assert flow.total_packets == 2


# ─────────────────────────────────────────────────────────────────────────────
# TCP state machine
# ─────────────────────────────────────────────────────────────────────────────

def test_tcp_state_machine():
    tracker = FlowTracker()
    # SYN
    tracker.process_packet(_tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="S", seq=1000))
    flow = list(tracker.flows())[0]
    assert flow.tcp_state == TcpState.SYN_SENT

    # SYN-ACK
    tracker.process_packet(_tcp_pkt("93.184.216.34", "10.0.0.1", 80, 54321, flags="SA", seq=2000, ack=1001))
    assert flow.tcp_state == TcpState.SYN_RECEIVED

    # ACK
    tracker.process_packet(_tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="A", seq=1001, ack=2001))
    assert flow.tcp_state == TcpState.ESTABLISHED


def test_tcp_rst_closes_flow():
    tracker = FlowTracker()
    tracker.process_packet(_tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="S"))
    tracker.process_packet(_tcp_pkt("10.0.0.1", "93.184.216.34", 54321, 80, flags="R"))
    flow = list(tracker.flows())[0]
    assert flow.tcp_state == TcpState.CLOSED


# ─────────────────────────────────────────────────────────────────────────────
# Protocol breakdown
# ─────────────────────────────────────────────────────────────────────────────

def test_protocol_breakdown():
    tracker = FlowTracker()
    tracker.process_packet(_tcp_pkt("10.0.0.1", "192.168.1.1", 1000, 80))
    tracker.process_packet(_tcp_pkt("10.0.0.1", "192.168.1.1", 1001, 443))
    tracker.process_packet(_udp_pkt("10.0.0.1", "8.8.8.8", 53000, 53))
    bd = tracker.protocol_breakdown
    assert bd["TCP"] == 2
    assert bd["UDP"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Non-IP packets return None
# ─────────────────────────────────────────────────────────────────────────────

def test_non_ip_packet_returns_none():
    from scapy.layers.l2 import ARP
    tracker = FlowTracker()
    pkt = Ether() / ARP()
    result = tracker.process_packet(pkt)
    assert result is None
    assert tracker.flow_count == 0
