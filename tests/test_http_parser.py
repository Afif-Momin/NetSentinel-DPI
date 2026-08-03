"""
tests/test_http_parser.py
==========================
Unit tests for parser/http_parser.py
No live network access or elevated privileges required.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from parser.http_parser import HttpParser, HttpRequest, _decode_chunked


# ─────────────────────────────────────────────────────────────────────────────
# Basic request parsing
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_simple_get():
    data = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"\r\n"
    )
    reqs = HttpParser(data).parse_requests()
    assert len(reqs) == 1
    r = reqs[0]
    assert r.method == "GET"
    assert r.uri == "/index.html"
    assert r.version == "1.1"
    assert r.host == "example.com"
    assert r.user_agent == "Mozilla/5.0"
    assert r.body == b""


def test_parse_post_with_body():
    body_data = b"username=admin&password=secret"
    data = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: " + str(len(body_data)).encode() + b"\r\n"
        b"\r\n" + body_data
    )
    reqs = HttpParser(data).parse_requests()
    assert len(reqs) == 1
    r = reqs[0]
    assert r.method == "POST"
    assert r.uri == "/login"
    assert r.body == body_data


def test_parse_sqli_uri():
    data = (
        b"GET /search?q=1'+UNION+SELECT+null-- HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"User-Agent: sqlmap/1.7\r\n"
        b"\r\n"
    )
    reqs = HttpParser(data).parse_requests()
    assert len(reqs) == 1
    assert "UNION" in reqs[0].uri


def test_parse_directory_traversal():
    data = (
        b"GET /../../../../etc/passwd HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"\r\n"
    )
    reqs = HttpParser(data).parse_requests()
    assert "../" in reqs[0].uri or ".." in reqs[0].uri


def test_parse_trace_method():
    data = b"TRACE / HTTP/1.1\r\nHost: target.local\r\n\r\n"
    reqs = HttpParser(data).parse_requests()
    assert reqs[0].method == "TRACE"


def test_content_length_property():
    body = b"test"
    data = (
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Length: 4\r\n\r\n" + body
    )
    reqs = HttpParser(data).parse_requests()
    assert reqs[0].content_length == 4


# ─────────────────────────────────────────────────────────────────────────────
# Chunked encoding
# ─────────────────────────────────────────────────────────────────────────────

def test_decode_chunked_basic():
    chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n"
    body, consumed = _decode_chunked(chunked)
    assert body == b"Hello World"


def test_decode_chunked_empty():
    body, _ = _decode_chunked(b"0\r\n\r\n")
    assert body == b""


# ─────────────────────────────────────────────────────────────────────────────
# Empty / malformed input
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_input():
    reqs = HttpParser(b"").parse_requests()
    assert reqs == []


def test_partial_request():
    reqs = HttpParser(b"GET /foo HTTP").parse_requests()
    assert reqs == []
