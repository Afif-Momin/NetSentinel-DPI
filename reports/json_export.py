"""
reports/json_export.py
======================
Export analysis results to a structured JSON report.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from detection.flow_tracker import FlowTracker
from detection.engine import DetectionEngine


class JsonExporter:
    """
    Serialize the full analysis (flows + alerts) to a JSON file.

    Parameters
    ----------
    tracker : FlowTracker
    engine  : DetectionEngine
    """

    def __init__(self, tracker: FlowTracker, engine: DetectionEngine) -> None:
        self.tracker = tracker
        self.engine = engine

    def export(self, path: Path) -> None:
        """Write the JSON report to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self._build()
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    def _build(self) -> Dict[str, Any]:
        flows_data = []
        for flow in self.tracker.flows():
            flows_data.append({
                "proto": flow.proto.value,
                "src": f"{flow.src_ip}:{flow.src_port}",
                "dst": f"{flow.dst_ip}:{flow.dst_port}",
                "total_packets": flow.total_packets,
                "total_bytes": flow.total_bytes,
                "duration_s": round(flow.duration, 3),
                "tcp_state": flow.tcp_state.name,
                "alert_count": len(flow.alerts),
                "tls_ja3": [h.ja3 for h in flow.tls_hellos],
                "dns_queries": [
                    {"qname": q.qname, "qtype": q.qtype}
                    for q in flow.dns_queries
                ],
                "http_requests": [
                    {
                        "method": r.method,
                        "uri": r.uri[:200],
                        "user_agent": r.user_agent[:200],
                    }
                    for r in flow.http_requests
                ],
            })

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_packets": self.tracker.total_packets,
                "total_bytes": self.tracker.total_bytes,
                "total_flows": self.tracker.flow_count,
                "total_alerts": len(self.engine.alerts),
                "rules_loaded": len(self.engine.rules),
                "protocol_breakdown": self.tracker.protocol_breakdown,
            },
            "alert_counts_by_severity": self.engine.alert_count_by_severity(),
            "alerts": [a.to_dict() for a in self.engine.alerts],
            "flows": flows_data,
        }
