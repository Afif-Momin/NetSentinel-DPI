"""
reports/dashboard.py
====================
Rich terminal dashboard — summary, alerts table, and full stats view.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule as RichRule

from detection.flow_tracker import FlowTracker, Protocol
from detection.engine import DetectionEngine, Alert

console = Console()

_SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "orange1",
    "critical": "bold red",
}


class Dashboard:
    """
    Renders terminal output using Rich.

    Parameters
    ----------
    tracker : FlowTracker
        The populated flow tracker after processing packets.
    engine : DetectionEngine
        The detection engine after running evaluations.
    """

    def __init__(self, tracker: FlowTracker, engine: DetectionEngine) -> None:
        self.tracker = tracker
        self.engine = engine

    # ------------------------------------------------------------------ #
    # Summary (Step 1 output)                                              #
    # ------------------------------------------------------------------ #

    def print_summary(self) -> None:
        """Print a concise summary: flow counts, protocol breakdown, top talkers, alert counts."""
        console.print()
        console.print(RichRule("[bold cyan]NetSentinel-DPI  -  Analysis Complete[/bold cyan]"))

        # Flow table
        flow_table = Table(title="Protocol Breakdown", box=box.ROUNDED, border_style="cyan")
        flow_table.add_column("Protocol", style="bold white")
        flow_table.add_column("Flows", justify="right")
        breakdown = self.tracker.protocol_breakdown
        total_flows = sum(breakdown.values())
        for proto, count in sorted(breakdown.items(), key=lambda x: -x[1]):
            pct = (count / total_flows * 100) if total_flows else 0
            flow_table.add_row(proto, f"{count:,}  ({pct:.1f}%)")
        flow_table.add_row("[bold]TOTAL[/bold]", f"[bold]{total_flows:,}[/bold]")

        # Alert severity table
        alert_table = Table(title="Alerts by Severity", box=box.ROUNDED, border_style="red")
        alert_table.add_column("Severity", style="bold")
        alert_table.add_column("Count", justify="right")
        counts = self.engine.alert_count_by_severity()
        total_alerts = sum(counts.values())
        for sev in ["critical", "high", "medium", "low"]:
            color = _SEVERITY_COLORS[sev]
            alert_table.add_row(
                f"[{color}]{sev.capitalize()}[/{color}]",
                f"[{color}]{counts.get(sev, 0):,}[/{color}]",
            )
        alert_table.add_row("[bold]TOTAL[/bold]", f"[bold]{total_alerts:,}[/bold]")

        # Top talkers table
        talker_table = Table(title="Top Talkers (by bytes)", box=box.ROUNDED, border_style="blue")
        talker_table.add_column("Source IP", style="cyan")
        talker_table.add_column("Bytes", justify="right")
        for ip, byt in self.tracker.top_talkers:
            talker_table.add_row(ip, _fmt_bytes(byt))

        console.print(Columns([flow_table, alert_table, talker_table], equal=False, expand=False))

        # Quick stats panel
        stats_lines = [
            f"  Total packets : [cyan]{self.tracker.total_packets:,}[/cyan]",
            f"  Total bytes   : [cyan]{_fmt_bytes(self.tracker.total_bytes)}[/cyan]",
            f"  Total flows   : [cyan]{self.tracker.flow_count:,}[/cyan]",
            f"  Alerts fired  : [red]{total_alerts:,}[/red]",
            f"  Rules loaded  : [yellow]{len(self.engine.rules):,}[/yellow]",
        ]
        console.print(Panel("\n".join(stats_lines), title="Stats", border_style="dim"))
        console.print()

        if total_alerts:
            console.print("[bold yellow][!] Alerts detected - run [cyan]dpi alerts --pcap <file>[/cyan] for details[/bold yellow]")

    # ------------------------------------------------------------------ #
    # Alerts table                                                         #
    # ------------------------------------------------------------------ #

    def print_alerts_table(self, severity_filter: Optional[str] = None) -> None:
        """Print all alerts (optionally filtered by severity) as a Rich table."""
        alerts = list(self.engine.alerts_iter(severity_filter=severity_filter))

        if not alerts:
            console.print("[green]No alerts found.[/green]" + (
                f" (filter: {severity_filter})" if severity_filter else ""
            ))
            return

        table = Table(
            title=f"Alerts ({len(alerts)} total)" + (f" - severity: {severity_filter}" if severity_filter else ""),
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Time", style="dim", no_wrap=True)
        table.add_column("Rule ID", style="bold cyan")
        table.add_column("Severity", justify="center")
        table.add_column("MITRE", style="dim")
        table.add_column("Source", style="yellow")
        table.add_column("Destination", style="yellow")
        table.add_column("Detail")

        for alert in sorted(alerts, key=lambda a: (
            ["critical", "high", "medium", "low"].index(a.severity),
            a.timestamp,
        )):
            color = _SEVERITY_COLORS.get(alert.severity, "white")
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
            table.add_row(
                ts,
                alert.rule_id,
                f"[{color}]{alert.severity.upper()}[/{color}]",
                alert.mitre,
                f"{alert.src_ip}:{alert.src_port}",
                f"{alert.dst_ip}:{alert.dst_port}",
                alert.detail[:80],
            )

        console.print(table)

    # ------------------------------------------------------------------ #
    # Full dashboard                                                        #
    # ------------------------------------------------------------------ #

    def print_full_dashboard(self) -> None:
        """Extended dashboard with per-flow listing."""
        self.print_summary()

        # Per-flow table (first 50)
        flow_detail = Table(
            title="Flow Details (top 50 by bytes)",
            box=box.SIMPLE,
            border_style="dim",
            show_lines=False,
        )
        flow_detail.add_column("Proto")
        flow_detail.add_column("Source")
        flow_detail.add_column("Destination")
        flow_detail.add_column("Pkts", justify="right")
        flow_detail.add_column("Bytes", justify="right")
        flow_detail.add_column("Duration", justify="right")
        flow_detail.add_column("State")
        flow_detail.add_column("Alerts", justify="right")

        flows = sorted(
            self.tracker.flows(), key=lambda f: f.total_bytes, reverse=True
        )[:50]
        for flow in flows:
            alert_count = len(flow.alerts)
            alert_cell = (
                f"[red]{alert_count}[/red]" if alert_count else "[dim]0[/dim]"
            )
            flow_detail.add_row(
                flow.proto.value,
                f"{flow.src_ip}:{flow.src_port}",
                f"{flow.dst_ip}:{flow.dst_port}",
                str(flow.total_packets),
                _fmt_bytes(flow.total_bytes),
                f"{flow.duration:.1f}s",
                flow.tcp_state.name if flow.proto.value == "TCP" else "—",
                alert_cell,
            )
        console.print(flow_detail)

        # Alerts
        self.print_alerts_table()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
