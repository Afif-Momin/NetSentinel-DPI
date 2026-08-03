"""
detection/http_detectors.py
============================
HTTP-layer detection helpers used by the engine.
Provides stand-alone functions testable without live packets.
"""
from __future__ import annotations

import re
from typing import List, Optional

from parser.http_parser import HttpRequest


# Patterns that never belong in legitimate URIs
_SQLI_RE = re.compile(
    r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|"
    r"drop\s+table|exec\s*\(|xp_cmdshell|;\s*--|'\s+or\s+'1'\s*=\s*'1)",
)
_XSS_RE = re.compile(
    r"(?i)(<script[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|"
    r"alert\s*\(|document\.cookie|eval\s*\()",
)
_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)")
_SCANNER_UA_RE = re.compile(
    r"(?i)(nikto|nmap|masscan|sqlmap|burpsuite|dirbuster|gobuster|"
    r"wfuzz|hydra|medusa|acunetix|nessus|openvas|nuclei|zgrab|"
    r"shodan|censys|python-requests/2\.[01])",
)
_CMD_INJ_RE = re.compile(
    r"(?i)(;\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|cmd|powershell)\b|"
    r"\|\s*(ls|cat|id|whoami|wget|curl)|`[^`]+`|\$\([^)]+\))",
)
_RFI_LFI_RE = re.compile(
    r"(?i)(php://|file://|expect://|data://|zip://|phar://)",
)

_SUSPICIOUS_METHODS = frozenset(
    ["TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
     "COPY", "MOVE", "LOCK", "UNLOCK"]
)


def check_sqli(req: HttpRequest) -> Optional[str]:
    """Return matched SQLi fragment or None."""
    m = _SQLI_RE.search(req.uri)
    if m:
        return m.group(0)[:80]
    body_text = req.body.decode("utf-8", errors="replace")
    m = _SQLI_RE.search(body_text)
    return m.group(0)[:80] if m else None


def check_xss(req: HttpRequest) -> Optional[str]:
    m = _XSS_RE.search(req.uri)
    return m.group(0)[:80] if m else None


def check_traversal(req: HttpRequest) -> Optional[str]:
    m = _TRAVERSAL_RE.search(req.uri)
    return m.group(0)[:80] if m else None


def check_scanner_ua(req: HttpRequest) -> Optional[str]:
    m = _SCANNER_UA_RE.search(req.user_agent)
    return m.group(0)[:80] if m else None


def check_command_injection(req: HttpRequest) -> Optional[str]:
    m = _CMD_INJ_RE.search(req.uri)
    return m.group(0)[:80] if m else None


def check_rfi_lfi(req: HttpRequest) -> Optional[str]:
    m = _RFI_LFI_RE.search(req.uri)
    return m.group(0)[:80] if m else None


def check_suspicious_method(req: HttpRequest) -> Optional[str]:
    if req.method.upper() in _SUSPICIOUS_METHODS:
        return req.method
    return None
