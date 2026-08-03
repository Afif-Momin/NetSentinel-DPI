"""
tests/fixtures/generate_fixtures.py
====================================
Generate synthetic PCAP fixture files using scapy.
Run this script once to populate tests/fixtures/*.pcap

Usage:
    python tests/fixtures/generate_fixtures.py

Cross-platform: scapy wrpcap works identically on Windows and Linux.
Does NOT require elevated privileges (file write only).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.packet import Raw
    from scapy.utils import wrpcap
    from scapy.all import Ether
except ImportError:
    print("ERROR: scapy not installed.  Run: pip install scapy")
    sys.exit(1)

FIXTURES_DIR = Path(__file__).parent


def _save(packets: list, name: str) -> None:
    path = FIXTURES_DIR / name
    wrpcap(str(path), packets)
    print(f"  wrote {path}  ({len(packets)} packets)")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Simple HTTP GET + Response (plain text, port 80)
# ─────────────────────────────────────────────────────────────────────────────

def gen_http_get() -> None:
    """Normal HTTP GET and 200 OK response."""
    pkts = []
    base_seq = 1000
    base_ack = 2000

    # TCP SYN
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="S", seq=base_seq)
    )
    # SYN-ACK
    pkts.append(
        Ether() / IP(src="93.184.216.34", dst="10.0.0.1") /
        TCP(sport=80, dport=54321, flags="SA", seq=base_ack, ack=base_seq + 1)
    )
    # ACK
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="A", seq=base_seq + 1, ack=base_ack + 1)
    )
    # HTTP GET
    http_req = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html\r\n"
        b"Connection: close\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="PA", seq=base_seq + 1, ack=base_ack + 1) /
        Raw(load=http_req)
    )
    # HTTP 200 OK
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 13\r\n\r\n"
        b"Hello, World!"
    )
    pkts.append(
        Ether() / IP(src="93.184.216.34", dst="10.0.0.1") /
        TCP(sport=80, dport=54321, flags="PA", seq=base_ack + 1, ack=base_seq + 1 + len(http_req)) /
        Raw(load=http_resp)
    )
    # FIN
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="FA", seq=base_seq + 1 + len(http_req), ack=base_ack + 1 + len(http_resp))
    )
    _save(pkts, "http_get.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# 2. SQL Injection attempt in HTTP GET URI
# ─────────────────────────────────────────────────────────────────────────────

def gen_sqli() -> None:
    """HTTP GET request with SQL injection payload in URI."""
    pkts = []
    sqli_req = (
        b"GET /search?q=1'+UNION+SELECT+null,table_name+FROM+information_schema.tables--+- HTTP/1.1\r\n"
        b"Host: vulnerable-app.local\r\n"
        b"User-Agent: sqlmap/1.7.9\r\n"
        b"Accept: */*\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="192.168.1.50", dst="10.10.10.100") /
        TCP(sport=44444, dport=80, flags="PA", seq=5000, ack=6000) /
        Raw(load=sqli_req)
    )
    _save(pkts, "sqli_attempt.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# 3. DNS query burst (tunneling simulation)
# ─────────────────────────────────────────────────────────────────────────────

def gen_dns_burst() -> None:
    """60 DNS queries for long, high-entropy labels simulating DNS tunneling."""
    import base64, os
    pkts = []
    for i in range(60):
        # Simulate base64-encoded data in the subdomain label
        random_data = base64.b64encode(os.urandom(24)).decode().replace("=", "").replace("+", "").replace("/", "")
        qname = f"{random_data}.tunnel.evil.com"
        pkts.append(
            Ether() / IP(src="172.16.0.5", dst="8.8.8.8") /
            UDP(sport=53000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        )
        # Response with TXT record
        pkts.append(
            Ether() / IP(src="8.8.8.8", dst="172.16.0.5") /
            UDP(sport=53, dport=53000 + i) /
            DNS(
                id=i, qr=1, aa=1, qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, type="TXT", rdata="cmVzcG9uc2VkYXRh"),
            )
        )
    _save(pkts, "dns_tunnel_burst.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Port scan simulation
# ─────────────────────────────────────────────────────────────────────────────

def gen_port_scan() -> None:
    """SYN scan from one source to many ports on a single target."""
    pkts = []
    target_ports = list(range(20, 100)) + [443, 8080, 8443, 3389, 5900, 6379, 27017, 5432, 3306]
    for port in target_ports:
        pkts.append(
            Ether() / IP(src="10.0.0.99", dst="192.168.1.1") /
            TCP(sport=12345, dport=port, flags="S", seq=1000)
        )
        # Some ports reply RST (closed), some SYN-ACK (open)
        if port in [22, 80, 443]:
            pkts.append(
                Ether() / IP(src="192.168.1.1", dst="10.0.0.99") /
                TCP(sport=port, dport=12345, flags="SA", seq=9000, ack=1001)
            )
        else:
            pkts.append(
                Ether() / IP(src="192.168.1.1", dst="10.0.0.99") /
                TCP(sport=port, dport=12345, flags="RA", seq=0, ack=1001)
            )
    _save(pkts, "port_scan.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Mixed traffic (for the main demo)
# ─────────────────────────────────────────────────────────────────────────────

def gen_mixed() -> None:
    """Combined pcap with HTTP, SQLi, DNS tunneling, and port scan packets."""
    import base64, os
    pkts = []

    # Normal HTTP
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="S", seq=1000)
    )
    pkts.append(
        Ether() / IP(src="93.184.216.34", dst="10.0.0.1") /
        TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001)
    )
    req = b"GET /page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
        TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=2001) /
        Raw(load=req)
    )

    # SQLi
    sqli_req = (
        b"GET /login?user=admin'--&pass=x HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"User-Agent: sqlmap/1.7\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="192.168.1.50", dst="10.10.10.100") /
        TCP(sport=55000, dport=80, flags="PA", seq=100, ack=200) /
        Raw(load=sqli_req)
    )

    # Directory traversal
    trav_req = (
        b"GET /../../../../etc/passwd HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"User-Agent: curl/7.88\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="192.168.1.51", dst="10.10.10.100") /
        TCP(sport=55001, dport=80, flags="PA", seq=300, ack=400) /
        Raw(load=trav_req)
    )

    # DNS tunneling
    for i in range(10):
        rand = base64.b64encode(os.urandom(18)).decode().replace("=", "").replace("+", "a").replace("/", "b")
        qname = f"{rand}.c2.attacker.io"
        pkts.append(
            Ether() / IP(src="172.16.0.5", dst="8.8.8.8") /
            UDP(sport=53100 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        )

    # Port scan
    for port in [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 5900, 8080, 8443, 3306, 5432, 6379, 27017]:
        pkts.append(
            Ether() / IP(src="10.0.0.99", dst="192.168.1.200") /
            TCP(sport=12345, dport=port, flags="S", seq=1000)
        )

    _save(pkts, "mixed_traffic.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating PCAP fixtures...")
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    gen_http_get()
    gen_sqli()
    gen_dns_burst()
    gen_port_scan()
    gen_mixed()
    print("Done.")
