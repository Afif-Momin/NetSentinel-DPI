"""
parser/tcp_reassembly.py
========================
TCP stream reassembly: buffer segments per flow direction, stitch on
contiguous sequence numbers, handle out-of-order and duplicate segments.

Limitations (see README):
- 32-bit sequence wraparound (PAWS) is not handled.
- Overlapping segment payload ambiguity uses first-writer-wins policy.
- Zero-window probes and urgent data are not specially handled.

Cross-platform: pure Python, no OS calls.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from scapy.layers.inet import TCP
    from scapy.packet import Packet
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Segment:
    """A buffered TCP payload segment."""
    seq: int          # sequence number of first byte
    data: bytes


@dataclass
class TcpStream:
    """
    One-directional TCP byte stream reassembler.

    Parameters
    ----------
    isn : int
        Initial sequence number (from the SYN packet).
    """

    isn: int
    _next_seq: int = field(init=False)
    _buffer: List[Segment] = field(default_factory=list, repr=False)
    data: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        self._next_seq = self.isn + 1  # SYN consumes one seq number

    # ------------------------------------------------------------------ #

    def add_segment(self, seq: int, payload: bytes) -> None:
        """
        Add a TCP segment with *seq* and *payload*.
        Segments that are completely below the expected next sequence number
        are treated as retransmissions and ignored.
        """
        if not payload:
            return
        end_seq = seq + len(payload)

        # Completely below expected window → retransmission, discard
        if end_seq <= self._next_seq:
            return

        # Trim leading overlap (partial retransmission)
        if seq < self._next_seq:
            trim = self._next_seq - seq
            payload = payload[trim:]
            seq = self._next_seq

        # Check if we already have this segment (dedup)
        for seg in self._buffer:
            if seg.seq == seq and seg.data == payload:
                return

        self._buffer.append(Segment(seq=seq, data=payload))
        self._flush()

    def _flush(self) -> None:
        """Flush contiguous segments into self.data."""
        self._buffer.sort(key=lambda s: s.seq)
        while self._buffer:
            seg = self._buffer[0]
            if seg.seq == self._next_seq:
                self._buffer.pop(0)
                self.data += seg.data
                self._next_seq += len(seg.data)
            elif seg.seq < self._next_seq:
                # Overlap — trim and re-check
                trim = self._next_seq - seg.seq
                if trim >= len(seg.data):
                    self._buffer.pop(0)  # fully covered
                else:
                    self._buffer[0] = Segment(
                        seq=self._next_seq,
                        data=seg.data[trim:],
                    )
            else:
                break  # gap — wait for missing segment

    @property
    def pending_bytes(self) -> int:
        """Number of bytes buffered but not yet flushed (gap ahead)."""
        return sum(len(s.data) for s in self._buffer)


# ─────────────────────────────────────────────────────────────────────────────
# Flow-level reassembler
# ─────────────────────────────────────────────────────────────────────────────

class TcpReassembler:
    """
    Manages :class:`TcpStream` objects for both directions of a TCP flow.

    Usage::

        reassembler = TcpReassembler()
        for pkt in packets:
            fwd_data, bwd_data = reassembler.add_packet(pkt, is_forward)
    """

    def __init__(self) -> None:
        self._fwd: Optional[TcpStream] = None
        self._bwd: Optional[TcpStream] = None

    def add_packet(self, pkt: "Packet", is_forward: bool) -> Tuple[bytes, bytes]:
        """
        Feed a scapy packet into the reassembler.

        Returns
        -------
        (fwd_payload_so_far, bwd_payload_so_far)
        """
        if not _SCAPY_OK or not pkt.haslayer(TCP):
            return b"", b""

        tcp = pkt[TCP]
        flags = int(tcp.flags)
        seq = tcp.seq

        # Initialise streams on SYN
        _F_SYN = 0x02
        _F_ACK = 0x10
        if flags & _F_SYN and not (flags & _F_ACK):
            if is_forward:
                self._fwd = TcpStream(isn=seq)
            else:
                self._bwd = TcpStream(isn=seq)
        elif flags & _F_SYN and (flags & _F_ACK):
            if not is_forward:
                self._bwd = TcpStream(isn=seq)

        # Extract payload
        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            return self._fwd_data, self._bwd_data

        if is_forward:
            if self._fwd is None:
                self._fwd = TcpStream(isn=seq - 1)
            self._fwd.add_segment(seq, payload)
        else:
            if self._bwd is None:
                self._bwd = TcpStream(isn=seq - 1)
            self._bwd.add_segment(seq, payload)

        return self._fwd_data, self._bwd_data

    @property
    def _fwd_data(self) -> bytes:
        return self._fwd.data if self._fwd else b""

    @property
    def _bwd_data(self) -> bytes:
        return self._bwd.data if self._bwd else b""
