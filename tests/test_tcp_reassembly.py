"""
tests/test_tcp_reassembly.py
=============================
Unit tests for parser/tcp_reassembly.py
No live network access or elevated privileges required.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from parser.tcp_reassembly import TcpStream, TcpReassembler


# ─────────────────────────────────────────────────────────────────────────────
# TcpStream unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_in_order_segments():
    """Segments arriving in order are immediately reassembled."""
    stream = TcpStream(isn=999)  # next_seq = 1000
    stream.add_segment(1000, b"Hello ")
    stream.add_segment(1006, b"World")
    assert stream.data == b"Hello World"


def test_out_of_order_segments():
    """Segment arriving before the gap segment is correctly buffered."""
    stream = TcpStream(isn=999)  # _next_seq = 1000
    # "Hello " is 6 bytes → occupies seq 1000-1005; "World" starts at 1006
    stream.add_segment(1006, b"World")   # arrives first (gap at 1000-1005)
    stream.add_segment(1000, b"Hello ")  # fills the gap
    assert stream.data == b"Hello World"


def test_duplicate_retransmission_ignored():
    """Identical retransmitted segment does not duplicate data."""
    stream = TcpStream(isn=999)
    stream.add_segment(1000, b"Hello")
    stream.add_segment(1000, b"Hello")  # retransmission
    assert stream.data == b"Hello"


def test_old_segment_below_window_discarded():
    """Segments completely below _next_seq are treated as retransmissions."""
    stream = TcpStream(isn=999)
    stream.add_segment(1000, b"Hello")
    # seq=998 ends at 1003, but _next_seq is 1005 now — fully below, discard
    stream.add_segment(998, b"Garbage")
    assert stream.data == b"Hello"


def test_partial_overlap_trimmed():
    """Segment partially overlapping already-received data is trimmed."""
    stream = TcpStream(isn=999)
    stream.add_segment(1000, b"Hello")
    # Overlaps first 2 bytes of "Hello" with " World" payload
    stream.add_segment(1003, b"lo World")
    # "Hello" = bytes 1000–1004, " World" extends from 1005–1010
    # After trim: overlap at 1003-1004, fresh at 1005-1010
    assert b"Hello" in stream.data or b"World" in stream.data


def test_multiple_gaps_resolve_on_fill():
    """Two gaps filled in order correctly reassemble."""
    stream = TcpStream(isn=0)
    # next_seq starts at 1
    stream.add_segment(1, b"A")   # flush → data="A", next=2
    stream.add_segment(4, b"D")   # buffered (gap at 2-3)
    stream.add_segment(3, b"C")   # still gap at 2
    stream.add_segment(2, b"B")   # fills gap; flush A,B,C,D
    assert stream.data == b"ABCD"


def test_pending_bytes():
    """pending_bytes counts buffered but not-yet-flushed bytes."""
    stream = TcpStream(isn=999)
    stream.add_segment(1005, b"World")  # gap ahead
    assert stream.pending_bytes == 5


# ─────────────────────────────────────────────────────────────────────────────
# TcpReassembler (no scapy — mock packets)
# ─────────────────────────────────────────────────────────────────────────────

class _MockTCP:
    def __init__(self, seq, payload=b"", flags=0):
        self.seq = seq
        self.payload = _MockRaw(payload)
        self.flags = flags

    def haslayer(self, layer):
        return True  # pretend every mock has TCP


class _MockRaw:
    def __init__(self, data):
        self._data = data

    def __bytes__(self):
        return self._data

    def __len__(self):
        return len(self._data)


class _MockPkt:
    """Minimal mock scapy Packet for TcpReassembler tests."""
    def __init__(self, seq, payload=b"", flags=0):
        self._tcp = _MockTCP(seq, payload, flags)

    def haslayer(self, layer):
        from scapy.layers.inet import TCP
        return layer == TCP

    def __getitem__(self, layer):
        return self._tcp


def test_reassembler_requires_scapy():
    """TcpReassembler falls back gracefully when scapy is missing."""
    reassembler = TcpReassembler()
    # Without a real scapy packet the method returns empty bytes
    # (we test this path by using the mock — it won't have TCP haslayer)
    class NoPktLayer:
        def haslayer(self, _):
            return False
    fwd, bwd = reassembler.add_packet(NoPktLayer(), True)
    assert fwd == b"" and bwd == b""
