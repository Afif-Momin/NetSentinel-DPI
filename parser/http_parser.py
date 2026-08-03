"""
parser/http_parser.py
=====================
Parse HTTP/1.x requests and responses from raw TCP stream bytes.

Handles:
- Method / URI / HTTP version extraction
- Request headers (including User-Agent, Content-Length, Transfer-Encoding)
- Basic chunked-encoding stitching
- HTTP request body extraction

Does NOT handle:
- HTTP/2 or HTTP/3
- HTTPS (TLS termination)
- Persistent connections with multiple requests in one stream (iterates all)

Cross-platform: pure Python, no OS calls.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HttpRequest:
    """A parsed HTTP request."""
    method: str
    uri: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def user_agent(self) -> str:
        return self.headers.get("user-agent", "")

    @property
    def host(self) -> str:
        return self.headers.get("host", "")

    @property
    def content_length(self) -> Optional[int]:
        raw = self.headers.get("content-length")
        return int(raw) if raw and raw.isdigit() else None

    def __repr__(self) -> str:
        return f"HttpRequest({self.method} {self.uri[:60]})"


@dataclass
class HttpResponse:
    """A parsed HTTP response."""
    version: str
    status_code: int
    reason: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __repr__(self) -> str:
        return f"HttpResponse({self.status_code} {self.reason})"


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

_REQUEST_LINE_RE = re.compile(
    rb"([A-Z]+) ([^\r\n]+) HTTP/(\d\.\d)\r?\n"
)
_RESPONSE_LINE_RE = re.compile(
    rb"HTTP/(\d\.\d) (\d{3}) ([^\r\n]*)\r?\n"
)
# No ^ anchor: used with match(data, pos) which needs to match at pos, not BOF
_HEADER_RE = re.compile(rb"([^:\r\n]+):\s*([^\r\n]*)\r?\n")
_CHUNK_SIZE_RE = re.compile(rb"([0-9a-fA-F]+)[^\n]*\n")


class HttpParser:
    """
    Parse one or more HTTP/1.x request messages from a raw byte stream.

    Parameters
    ----------
    data : bytes
        Raw TCP stream payload (may contain multiple pipelined requests).
    """

    def __init__(self, data: bytes) -> None:
        self.data = data

    def parse_requests(self) -> List[HttpRequest]:
        """Return a list of all HTTP requests found in the byte stream."""
        results: List[HttpRequest] = []
        offset = 0
        while offset < len(self.data):
            req, consumed = self._parse_one_request(self.data[offset:])
            if req is None:
                break
            results.append(req)
            offset += consumed
        return results

    def parse_responses(self) -> List[HttpResponse]:
        """Return a list of all HTTP responses found in the byte stream."""
        results: List[HttpResponse] = []
        offset = 0
        while offset < len(self.data):
            resp, consumed = self._parse_one_response(self.data[offset:])
            if resp is None:
                break
            results.append(resp)
            offset += consumed
        return results

    # ------------------------------------------------------------------ #

    def _parse_one_request(
        self, data: bytes
    ) -> tuple[Optional[HttpRequest], int]:
        m = _REQUEST_LINE_RE.match(data)
        if not m:
            return None, len(data)

        method = m.group(1).decode("latin-1")
        uri = m.group(2).decode("latin-1", errors="replace")
        version = m.group(3).decode()
        offset = m.end()

        headers, offset = _parse_headers(data, offset)
        body, offset = _parse_body(data, offset, headers)

        return HttpRequest(
            method=method,
            uri=uri,
            version=version,
            headers=headers,
            body=body,
        ), offset

    def _parse_one_response(
        self, data: bytes
    ) -> tuple[Optional[HttpResponse], int]:
        m = _RESPONSE_LINE_RE.match(data)
        if not m:
            return None, len(data)

        version = m.group(1).decode()
        status_code = int(m.group(2))
        reason = m.group(3).decode("latin-1", errors="replace")
        offset = m.end()

        headers, offset = _parse_headers(data, offset)
        body, offset = _parse_body(data, offset, headers)

        return HttpResponse(
            version=version,
            status_code=status_code,
            reason=reason,
            headers=headers,
            body=body,
        ), offset


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_headers(data: bytes, offset: int) -> tuple[Dict[str, str], int]:
    """Parse HTTP headers from *data* starting at *offset*."""
    headers: Dict[str, str] = {}
    while offset < len(data):
        # Blank line (\r\n alone, or bare \n alone) signals end of headers
        if data[offset] == ord("\r") and data[offset + 1 : offset + 2] == b"\n":
            offset += 2
            break
        if data[offset] == ord("\n"):
            offset += 1
            break
        m = _HEADER_RE.match(data, offset)
        if not m:
            # Try to skip a malformed line
            nl = data.find(b"\n", offset)
            if nl == -1:
                break
            offset = nl + 1
            continue
        name = m.group(1).decode("latin-1").lower().strip()
        value = m.group(2).decode("latin-1", errors="replace").strip()
        headers[name] = value
        offset = m.end()
    return headers, offset


def _parse_body(
    data: bytes,
    offset: int,
    headers: Dict[str, str],
) -> tuple[bytes, int]:
    """Extract HTTP body, handling Content-Length and chunked encoding."""
    transfer = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer:
        body, consumed = _decode_chunked(data[offset:])
        return body, offset + consumed

    cl_raw = headers.get("content-length")
    if cl_raw and cl_raw.isdigit():
        cl = int(cl_raw)
        body = data[offset: offset + cl]
        return body, offset + cl

    # No body signalled
    return b"", offset


def _decode_chunked(data: bytes) -> tuple[bytes, int]:
    """Decode chunked transfer encoding.  Returns (body, bytes_consumed)."""
    body = b""
    offset = 0
    while offset < len(data):
        m = _CHUNK_SIZE_RE.match(data, offset)
        if not m:
            break
        chunk_size = int(m.group(1), 16)
        offset = m.end()  # now points right after the chunk-size line
        if chunk_size == 0:
            break  # last-chunk; trailing headers ignored
        if offset + chunk_size > len(data):
            break  # incomplete chunk
        body += data[offset: offset + chunk_size]
        offset += chunk_size
        # Each chunk data is followed by CRLF
        if data[offset: offset + 2] == b"\r\n":
            offset += 2
        elif offset < len(data) and data[offset] == ord("\n"):
            offset += 1
    return body, offset
