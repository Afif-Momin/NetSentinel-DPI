"""
detection/engine.py
===================
YAML-driven detection engine.  Evaluates every loaded rule against each
updated flow and emits :class:`Alert` objects.

Rule YAML schema
----------------
.. code-block:: yaml

    - id: HTTP-001
      name: Suspicious HTTP Method
      severity: medium        # low | medium | high | critical
      mitre: T1071.001
      description: "Detects use of TRACE/CONNECT/PROPFIND methods"
      match:
        type: http_method
        values: [TRACE, CONNECT, PROPFIND, PUT, DELETE]

Supported match types
---------------------
* ``http_method``      — HTTP request method in blacklist
* ``http_ua_regex``    — User-Agent header matches regex
* ``http_uri_regex``   — URI matches regex
* ``http_body_regex``  — Request body matches regex
* ``http_body_size``   — Payload body exceeds threshold bytes
* ``dns_query_regex``  — DNS QNAME matches regex
* ``dns_txt_volume``   — DNS TXT answer count above threshold
* ``port_scan``        — (evaluated at finalize time) many dst ports
* ``dns_entropy``      — QNAME Shannon entropy above threshold
* ``dns_query_rate``   — Many DNS queries per flow
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import yaml

from detection.flow_tracker import Flow, FlowTracker


# ─────────────────────────────────────────────────────────────────────────────
# Alert
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """A single detection alert produced by a rule match."""

    timestamp: float
    rule_id: str
    rule_name: str
    severity: str          # low | medium | high | critical
    mitre: str             # ATT&CK technique ID
    description: str
    flow_key: tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    detail: str = ""       # Extra context (matched value, etc.)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre": self.mitre,
            "description": self.description,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "proto": self.proto,
            "detail": self.detail,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Rule model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    """A single detection rule loaded from YAML."""

    id: str
    name: str
    severity: str
    mitre: str
    description: str
    match: Dict[str, Any]

    # Compiled regex (if applicable)
    _regex: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        pattern = self.match.get("regex") or self.match.get("pattern")
        if pattern:
            self._regex = re.compile(pattern, re.IGNORECASE)

    def regex(self) -> Optional[re.Pattern]:
        return self._regex


# ─────────────────────────────────────────────────────────────────────────────
# Detection engine
# ─────────────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Loads rules from a directory of YAML files and evaluates them against
    flow/packet data.

    Parameters
    ----------
    rules_dir : Path
        Directory containing ``*.yaml`` rule files.
    """

    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = Path(rules_dir)
        self.rules: List[Rule] = []
        self.alerts: List[Alert] = []
        self._load_rules()

    # ------------------------------------------------------------------ #
    # Rule loading                                                         #
    # ------------------------------------------------------------------ #

    def _load_rules(self) -> None:
        """Load all ``*.yaml`` files from *rules_dir*."""
        if not self.rules_dir.exists():
            return
        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            self._load_yaml_file(yaml_file)

    def _load_yaml_file(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            return
        for entry in data:
            try:
                rule = Rule(
                    id=entry["id"],
                    name=entry["name"],
                    severity=entry.get("severity", "medium"),
                    mitre=entry.get("mitre", ""),
                    description=entry.get("description", ""),
                    match=entry.get("match", {}),
                )
                self.rules.append(rule)
            except (KeyError, TypeError):
                pass  # Skip malformed rules

    # ------------------------------------------------------------------ #
    # Per-packet evaluation                                                #
    # ------------------------------------------------------------------ #

    def evaluate(self, flow: Flow, pkt: Any) -> None:
        """
        Run all applicable per-packet rules against *flow* and *pkt*.
        Appends any fired :class:`Alert` objects to ``flow.alerts`` and
        ``self.alerts``.
        """
        for rule in self.rules:
            match_type = rule.match.get("type", "")
            alert = None

            if match_type == "http_method":
                alert = self._check_http_method(rule, flow)
            elif match_type == "http_ua_regex":
                alert = self._check_http_ua(rule, flow)
            elif match_type == "http_uri_regex":
                alert = self._check_http_uri(rule, flow)
            elif match_type == "http_body_regex":
                alert = self._check_http_body_regex(rule, flow)
            elif match_type == "http_body_size":
                alert = self._check_http_body_size(rule, flow)
            elif match_type == "dns_query_regex":
                alert = self._check_dns_query(rule, flow)
            elif match_type == "dns_txt_volume":
                alert = self._check_dns_txt_volume(rule, flow)
            elif match_type == "dns_entropy":
                alert = self._check_dns_entropy(rule, flow)
            elif match_type == "dns_query_rate":
                alert = self._check_dns_query_rate(rule, flow)
            # port_scan is handled in finalize()

            if alert and not self._is_duplicate(alert, flow):
                flow.alerts.append(alert)
                self.alerts.append(alert)

    # ------------------------------------------------------------------ #
    # Post-capture / finalize rules                                        #
    # ------------------------------------------------------------------ #

    def finalize(self, tracker: "FlowTracker") -> None:
        """
        Run rules that require the full flow table (e.g., port scan detection).
        Call this once after all packets have been processed.
        """
        self._check_port_scan(tracker)

    # ------------------------------------------------------------------ #
    # Match helpers                                                        #
    # ------------------------------------------------------------------ #

    def _make_alert(self, rule: Rule, flow: Flow, detail: str = "") -> Alert:
        return Alert(
            timestamp=flow.last_seen,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            mitre=rule.mitre,
            description=rule.description,
            flow_key=flow.key,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            proto=flow.proto.value,
            detail=detail,
        )

    def _is_duplicate(self, alert: Alert, flow: Flow) -> bool:
        """Avoid emitting the same rule alert more than once per flow."""
        for existing in flow.alerts:
            if existing.rule_id == alert.rule_id:
                return True
        return False

    # HTTP ----------------------------------------------------------------

    def _check_http_method(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        allowed = [v.upper() for v in rule.match.get("values", [])]
        for req in flow.http_requests:
            method = getattr(req, "method", "").upper()
            if method in allowed:
                return self._make_alert(rule, flow, f"method={method}")
        return None

    def _check_http_ua(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        rx = rule.regex()
        if not rx:
            return None
        for req in flow.http_requests:
            ua = getattr(req, "user_agent", "") or ""
            if rx.search(ua):
                return self._make_alert(rule, flow, f"user_agent={ua[:120]}")
        return None

    def _check_http_uri(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        rx = rule.regex()
        if not rx:
            return None
        for req in flow.http_requests:
            uri = getattr(req, "uri", "") or ""
            if rx.search(uri):
                return self._make_alert(rule, flow, f"uri={uri[:200]}")
        return None

    def _check_http_body_regex(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        rx = rule.regex()
        if not rx:
            return None
        try:
            body_text = flow.fwd_payload.decode("utf-8", errors="replace")
        except Exception:
            return None
        m = rx.search(body_text)
        if m:
            return self._make_alert(rule, flow, f"match={m.group(0)[:80]}")
        return None

    def _check_http_body_size(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        threshold = int(rule.match.get("threshold_bytes", 1_000_000))
        if flow.fwd_bytes > threshold:
            return self._make_alert(
                rule, flow,
                f"fwd_bytes={flow.fwd_bytes} > threshold={threshold}",
            )
        return None

    # DNS -----------------------------------------------------------------

    def _check_dns_query(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        rx = rule.regex()
        if not rx:
            return None
        for q in flow.dns_queries:
            qname = getattr(q, "qname", "") or ""
            if rx.search(qname):
                return self._make_alert(rule, flow, f"qname={qname[:120]}")
        return None

    def _check_dns_txt_volume(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        threshold = int(rule.match.get("threshold", 5))
        txt_count = sum(
            getattr(q, "txt_records", 0) for q in flow.dns_queries
        )
        if txt_count >= threshold:
            return self._make_alert(rule, flow, f"txt_records={txt_count}")
        return None

    def _check_dns_entropy(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        threshold = float(rule.match.get("threshold", 3.5))
        for q in flow.dns_queries:
            qname = getattr(q, "qname", "") or ""
            ent = _shannon_entropy(qname.split(".")[0])  # first label only
            if ent >= threshold:
                return self._make_alert(
                    rule, flow, f"entropy={ent:.2f} qname={qname[:60]}"
                )
        return None

    def _check_dns_query_rate(self, rule: Rule, flow: Flow) -> Optional[Alert]:
        threshold = int(rule.match.get("threshold", 50))
        count = len(flow.dns_queries)
        if count >= threshold:
            return self._make_alert(rule, flow, f"query_count={count}")
        return None

    # Port scan -----------------------------------------------------------

    def _check_port_scan(self, tracker: "FlowTracker") -> None:
        """
        Detect horizontal port scans: one source IP contacting many distinct
        destination ports within the observation window.
        """
        port_scan_rules = [r for r in self.rules if r.match.get("type") == "port_scan"]
        if not port_scan_rules:
            return

        # Aggregate: src_ip → set of dst_ports
        src_to_ports: Dict[str, set] = {}
        src_to_flow: Dict[str, Flow] = {}
        for flow in tracker.flows():
            src = flow.src_ip
            if src not in src_to_ports:
                src_to_ports[src] = set()
            src_to_ports[src].add(flow.dst_port)
            src_to_flow[src] = flow  # keep last flow for alert context

        for rule in port_scan_rules:
            threshold = int(rule.match.get("threshold_ports", 15))
            window = float(rule.match.get("window_seconds", 60.0))
            for src_ip, ports in src_to_ports.items():
                if len(ports) >= threshold:
                    representative_flow = src_to_flow[src_ip]
                    alert = Alert(
                        timestamp=time.time(),
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        mitre=rule.mitre,
                        description=rule.description,
                        flow_key=representative_flow.key,
                        src_ip=src_ip,
                        dst_ip="*",
                        src_port=0,
                        dst_port=0,
                        proto="TCP",
                        detail=f"distinct_ports={len(ports)} threshold={threshold}",
                    )
                    self.alerts.append(alert)

    # ------------------------------------------------------------------ #
    # Stats                                                                #
    # ------------------------------------------------------------------ #

    def alert_count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in self.alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
        return counts

    def alerts_iter(
        self,
        severity_filter: Optional[str] = None,
    ) -> Iterator[Alert]:
        for a in self.alerts:
            if severity_filter is None or a.severity == severity_filter:
                yield a


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    import math
    if not s:
        return 0.0
    length = len(s)
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
