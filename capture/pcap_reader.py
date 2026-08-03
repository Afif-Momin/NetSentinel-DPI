"""
capture/pcap_reader.py
======================
Read packets from an existing PCAP / PCAPNG file using scapy.

Cross-platform: scapy's rdpcap works identically on Windows and Linux.
No elevated privileges required for reading a file.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

try:
    from scapy.utils import rdpcap, PcapReader as _ScapyPcapReader
    from scapy.packet import Packet
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore[misc,assignment]


class PcapReader:
    """
    Lazy packet reader for PCAP files.

    Parameters
    ----------
    path : Path
        Path to the .pcap or .pcapng file.

    Examples
    --------
    >>> reader = PcapReader(Path("traffic.pcap"))
    >>> for pkt in reader.read():
    ...     print(pkt.summary())
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.path}")
        if not _SCAPY_OK:
            raise ImportError("scapy is required: pip install scapy")

    def read(self) -> Iterator["Packet"]:
        """
        Yield scapy :class:`Packet` objects one at a time.

        Uses scapy's streaming ``PcapReader`` so even large files don't
        require loading everything into memory at once.
        """
        with _ScapyPcapReader(str(self.path)) as reader:
            for pkt in reader:
                yield pkt

    def packet_count(self) -> int:
        """Return total number of packets (reads the file once)."""
        return sum(1 for _ in self.read())
