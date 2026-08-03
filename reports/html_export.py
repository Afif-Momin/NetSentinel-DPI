"""
reports/html_export.py
======================
Export analysis results as a styled HTML incident report.
Self-contained single-file HTML — no external CDN dependencies.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from detection.flow_tracker import FlowTracker
from detection.engine import DetectionEngine, Alert

_SEVERITY_BADGE = {
    "low": "badge-low",
    "medium": "badge-medium",
    "high": "badge-high",
    "critical": "badge-critical",
}

_CSS = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e;
  --cyan: #58a6ff; --green: #3fb950; --yellow: #e3b341;
  --orange: #d29922; --red: #f85149; --purple: #bc8cff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
header { background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
  border-bottom: 2px solid var(--cyan); padding: 24px 40px; }
header h1 { font-size: 24px; color: var(--cyan); letter-spacing: 1px; }
header p { color: var(--muted); margin-top: 4px; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px 40px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 20px; text-align: center; }
.card .value { font-size: 32px; font-weight: 700; color: var(--cyan); }
.card .label { color: var(--muted); margin-top: 4px; font-size: 12px; text-transform: uppercase; }
h2 { color: var(--cyan); font-size: 16px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
section { margin-bottom: 40px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: var(--surface); color: var(--muted); text-align: left;
  padding: 8px 12px; border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: rgba(88,166,255,0.04); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
.badge-low    { background: #1b4d1e; color: var(--green); }
.badge-medium { background: #3d2f00; color: var(--yellow); }
.badge-high   { background: #3d1f00; color: var(--orange); }
.badge-critical { background: #3d0000; color: var(--red); }
.mono { font-family: 'Consolas', 'Monaco', monospace; }
footer { text-align: center; padding: 24px; color: var(--muted); border-top: 1px solid var(--border); font-size: 12px; }
"""


class HtmlExporter:
    """
    Generate a self-contained HTML incident report.

    Parameters
    ----------
    tracker : FlowTracker
    engine  : DetectionEngine
    """

    def __init__(self, tracker: FlowTracker, engine: DetectionEngine) -> None:
        self.tracker = tracker
        self.engine = engine

    def export(self, path: Path) -> None:
        """Write the HTML report to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            fh.write(self._render())

    def _render(self) -> str:
        counts = self.engine.alert_count_by_severity()
        total_alerts = sum(counts.values())
        breakdown = self.tracker.protocol_breakdown
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        # Collect JA3 fingerprints
        ja3_seen: Dict[str, str] = {}  # ja3 → sni
        for flow in self.tracker.flows():
            for hello in flow.tls_hellos:
                ja3_seen[hello.ja3] = hello.sni

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetSentinel-DPI — Incident Report</title>
  <style>{_CSS}</style>
</head>
<body>
<header>
  <h1>🛡 NetSentinel-DPI — Incident Report</h1>
  <p>Generated {generated} | Rules loaded: {len(self.engine.rules)}</p>
</header>
<div class="container">

  <!-- Summary cards -->
  <div class="grid">
    {self._card(str(self.tracker.total_packets), "Packets")}
    {self._card(_fmt_bytes(self.tracker.total_bytes), "Traffic Volume")}
    {self._card(str(self.tracker.flow_count), "Flows")}
    {self._card(str(total_alerts), "Alerts")}
    {self._card(str(counts.get("critical", 0)), "Critical")}
    {self._card(str(counts.get("high", 0)), "High")}
  </div>

  <!-- Protocol breakdown -->
  <section>
    <h2>Protocol Breakdown</h2>
    <table>
      <tr><th>Protocol</th><th>Flows</th><th>Share</th></tr>
      {''.join(
        f'<tr><td>{p}</td><td>{c}</td><td>{c/max(1,sum(breakdown.values()))*100:.1f}%</td></tr>'
        for p, c in sorted(breakdown.items(), key=lambda x: -x[1])
      )}
    </table>
  </section>

  <!-- Alerts table -->
  <section>
    <h2>Alerts ({total_alerts})</h2>
    {self._alerts_table()}
  </section>

  <!-- JA3 fingerprints -->
  <section>
    <h2>TLS JA3 Fingerprints ({len(ja3_seen)})</h2>
    {self._ja3_table(ja3_seen)}
  </section>

  <!-- DNS stats -->
  <section>
    <h2>DNS Statistics</h2>
    {self._dns_table()}
  </section>

  <!-- Top talkers -->
  <section>
    <h2>Top Talkers</h2>
    <table>
      <tr><th>Source IP</th><th>Bytes</th></tr>
      {''.join(f'<tr><td class="mono">{html.escape(ip)}</td><td>{_fmt_bytes(b)}</td></tr>' for ip, b in self.tracker.top_talkers)}
    </table>
  </section>

</div>
<footer>NetSentinel-DPI — Portfolio Deep Packet Inspection Tool</footer>
</body>
</html>"""

    def _card(self, value: str, label: str) -> str:
        return (
            f'<div class="card">'
            f'<div class="value">{html.escape(value)}</div>'
            f'<div class="label">{html.escape(label)}</div>'
            f'</div>'
        )

    def _alerts_table(self) -> str:
        alerts = list(self.engine.alerts)
        if not alerts:
            return "<p style='color:var(--green)'>No alerts detected.</p>"
        rows = []
        for a in sorted(alerts, key=lambda x: (
            ["critical", "high", "medium", "low"].index(x.severity), x.timestamp
        )):
            badge_cls = _SEVERITY_BADGE.get(a.severity, "badge-low")
            rows.append(
                f"<tr>"
                f"<td>{datetime.fromtimestamp(a.timestamp).strftime('%H:%M:%S')}</td>"
                f"<td class='mono'>{html.escape(a.rule_id)}</td>"
                f"<td><span class='badge {badge_cls}'>{html.escape(a.severity)}</span></td>"
                f"<td class='mono'>{html.escape(a.mitre)}</td>"
                f"<td class='mono'>{html.escape(a.src_ip)}:{a.src_port}</td>"
                f"<td class='mono'>{html.escape(a.dst_ip)}:{a.dst_port}</td>"
                f"<td>{html.escape(a.detail[:100])}</td>"
                f"</tr>"
            )
        header = "<tr><th>Time</th><th>Rule ID</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Destination</th><th>Detail</th></tr>"
        return f"<table>{header}{''.join(rows)}</table>"

    def _ja3_table(self, ja3_seen: Dict[str, str]) -> str:
        if not ja3_seen:
            return "<p style='color:var(--muted)'>No TLS ClientHellos captured.</p>"
        rows = "".join(
            f"<tr><td class='mono'>{html.escape(fingerprint)}</td><td>{html.escape(sni)}</td></tr>"
            for fingerprint, sni in ja3_seen.items()
        )
        return f"<table><tr><th>JA3 Fingerprint</th><th>SNI</th></tr>{rows}</table>"

    def _dns_table(self) -> str:
        all_queries: List[Any] = []
        for flow in self.tracker.flows():
            all_queries.extend(flow.dns_queries)
        if not all_queries:
            return "<p style='color:var(--muted)'>No DNS traffic captured.</p>"
        rows = "".join(
            f"<tr><td class='mono'>{html.escape(q.qname[:60])}</td>"
            f"<td>{html.escape(q.qtype)}</td>"
            f"<td>{q.txt_records}</td>"
            f"<td>{q.entropy:.2f}</td></tr>"
            for q in all_queries[:100]
        )
        return (
            f"<table>"
            f"<tr><th>QNAME</th><th>Type</th><th>TXT Records</th><th>Label Entropy</th></tr>"
            f"{rows}"
            f"</table>"
            f"<p style='color:var(--muted);margin-top:8px'>Showing up to 100 queries. Total: {len(all_queries)}</p>"
        )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
