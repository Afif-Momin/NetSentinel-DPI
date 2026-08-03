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
            resolved = _resolve_interface_name(self.interface)
            sniff(
                iface=resolved,
                timeout=self.timeout,
                store=False,
                prn=self._enqueue,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
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


def _resolve_interface_name(name: str) -> str:
    """
    Resolve a user-provided interface name to the actual Scapy interface name.
    Supports case-insensitive exact, normalized, and substring matches.
    If no match is found, raises ValueError listing all available interfaces.
    """
    if not _SCAPY_OK:
        return name

    def _normalize(s: str) -> str:
        return "".join(c for c in s.lower() if c.isalnum())

    norm_name = _normalize(name)

    # 1. Exact match (case-insensitive)
    for iface in conf.ifaces.values():
        if iface.name.lower() == name.lower() or (iface.description and iface.description.lower() == name.lower()):
            return iface.name

    # 2. Normalized match (exact match after removing punctuation/spaces)
    for iface in conf.ifaces.values():
        if _normalize(iface.name) == norm_name or (iface.description and _normalize(iface.description) == norm_name):
            return iface.name

    # 3. Substring match
    matches = []
    for iface in conf.ifaces.values():
        desc = iface.description or ""
        if (name.lower() in iface.name.lower() or name.lower() in desc.lower() or
                norm_name in _normalize(iface.name) or norm_name in _normalize(desc)):
            matches.append(iface.name)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        # Prefer matches that start with the search name
        starts_with = [m for m in matches if m.lower().startswith(name.lower()) or _normalize(m).startswith(norm_name)]
        return starts_with[0] if starts_with else matches[0]

    # No match found - raise ValueError with list of interfaces
    ifaces_list = []
    for iface in conf.ifaces.values():
        desc = f" ({iface.description})" if iface.description else ""
        ifaces_list.append(f"  * '{iface.name}'{desc}")

    available_str = "\n".join(ifaces_list)
    raise ValueError(
        f"Interface '{name}' not found.\n\nAvailable interfaces:\n{available_str}"
    )
