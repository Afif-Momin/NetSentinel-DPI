"""
capture/live_capture.py
=======================
Live packet capture using scapy's ``sniff()`` — wraps libpcap on Linux
and Npcap on Windows.  Requires elevated privileges on both platforms.

Raises :class:`PermissionError` (re-exported) when capture fails due to
insufficient privileges so the CLI can print a platform-specific message.

Cross-platform: no OS-specific shell-outs.  Threading via stdlib ``threading``.
"""
from __future__ import annotations

import queue
import threading
from typing import Iterator, Optional

try:
    from scapy.all import sniff, conf
    from scapy.packet import Packet
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    Packet = object  # type: ignore[misc,assignment]


# Re-export so CLI can catch it by a single name
class PermissionError(Exception):  # noqa: A001
    """Raised when live capture cannot open the network interface."""


class LiveCapture:
    """
    Stream packets from a live network interface.

    Parameters
    ----------
    interface : str
        Interface name (e.g. ``"eth0"``, ``"\\Device\\NPF_{GUID}"``).
    timeout : int | None
        Stop capture after *timeout* seconds.  ``None`` → run indefinitely.
    buffer_size : int
        Maximum number of packets to queue before the consumer falls behind.

    Examples
    --------
    >>> cap = LiveCapture("eth0", timeout=10)
    >>> for pkt in cap.stream():
    ...     print(pkt.summary())
    """

    def __init__(
        self,
        interface: str,
        timeout: Optional[int] = None,
        buffer_size: int = 4096,
    ) -> None:
        if not _SCAPY_OK:
            raise ImportError("scapy is required: pip install scapy")
        self.interface = interface
        self.timeout = timeout
        self._queue: queue.Queue = queue.Queue(maxsize=buffer_size)
        self._stop_event = threading.Event()
        self._error: Optional[Exception] = None

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def stream(self) -> Iterator["Packet"]:
        """
        Yield captured packets.  Blocks until the capture thread pushes a
        packet or signals completion.

        Raises :class:`PermissionError` if the interface cannot be opened.
        """
        thread = threading.Thread(target=self._capture_thread, daemon=True)
        thread.start()

        while True:
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                if not thread.is_alive():
                    break
                continue

            if item is None:  # sentinel
                break
            yield item

        thread.join(timeout=5.0)

        if self._error is not None:
            raise self._error

    def stop(self) -> None:
        """Signal the capture thread to stop."""
        self._stop_event.set()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _capture_thread(self) -> None:
        """Run in a background thread; push packets onto the queue."""
        try:
            sniff(
                iface=self.interface,
                timeout=self.timeout,
                store=False,
                prn=self._enqueue,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:  # OS-level
            self._error = PermissionError(str(exc))
        except OSError as exc:
            # Npcap / libpcap errors surface as OSError with messages like
            # "You don't have permission to capture on that device"
            msg = str(exc).lower()
            if any(kw in msg for kw in ("permission", "access", "privilege", "administrator")):
                self._error = PermissionError(str(exc))
            else:
                self._error = exc
        finally:
            self._queue.put(None)  # sentinel

    def _enqueue(self, pkt: "Packet") -> None:
        """Callback from scapy's sniff; put packet on queue (non-blocking)."""
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            pass  # drop packet if consumer is too slow
