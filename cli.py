"""
NetSentinel-DPI – Deep Packet Inspection CLI Tool
Entry point / CLI definition.
"""
from __future__ import annotations

import sys
import platform
from pathlib import Path

import click
from rich.console import Console

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Helper: safe import guard
# ─────────────────────────────────────────────────────────────────────────────

def _import_pipeline():
    """Lazily import the pipeline so we get a nice error if deps are missing."""
    try:
        from capture.pcap_reader import PcapReader
        from detection.flow_tracker import FlowTracker
        from detection.engine import DetectionEngine
        from reports.dashboard import Dashboard
        return PcapReader, FlowTracker, DetectionEngine, Dashboard
    except ImportError as exc:
        console.print(f"[bold red]Import error:[/bold red] {exc}")
        console.print("Run: [cyan]pip install -r requirements.txt[/cyan]")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    \b
    ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                       DPI — Deep Packet Inspection
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ─────────────────────────────────────────────────────────────────────────────
# Sub-commands
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("pcap")
@click.argument("pcap_file", type=click.Path(exists=True, path_type=Path))
@click.option("--rules-dir", type=click.Path(path_type=Path), default=None,
              help="Directory containing YAML rule files (default: ./rules)")
@click.option("--export-json", type=click.Path(path_type=Path), default=None,
              help="Export full report to JSON file")
@click.option("--export-html", type=click.Path(path_type=Path), default=None,
              help="Export full report to HTML file")
@click.option("--quiet", is_flag=True, help="Suppress per-packet output")
def cmd_pcap(
    pcap_file: Path,
    rules_dir: Path | None,
    export_json: Path | None,
    export_html: Path | None,
    quiet: bool,
) -> None:
    """Analyse a PCAP file offline (no elevated privileges required)."""
    PcapReader, FlowTracker, DetectionEngine, Dashboard = _import_pipeline()

    if rules_dir is None:
        rules_dir = Path(__file__).parent / "rules"

    console.print(f"[bold cyan]NetSentinel-DPI[/bold cyan] - analysing [green]{pcap_file}[/green]")

    tracker = FlowTracker()
    engine = DetectionEngine(rules_dir=rules_dir)
    reader = PcapReader(pcap_file)

    packet_count = 0
    for packet in reader.read():
        flow = tracker.process_packet(packet)
        if flow:
            engine.evaluate(flow, packet)
        packet_count += 1

    engine.finalize(tracker)

    dash = Dashboard(tracker=tracker, engine=engine)
    dash.print_summary()

    if export_json:
        from reports.json_export import JsonExporter
        JsonExporter(tracker=tracker, engine=engine).export(export_json)
        console.print(f"[green]JSON report written to:[/green] {export_json}")

    if export_html:
        from reports.html_export import HtmlExporter
        HtmlExporter(tracker=tracker, engine=engine).export(export_html)
        console.print(f"[green]HTML report written to:[/green] {export_html}")


@cli.command("live")
@click.argument("interface")
@click.option("--rules-dir", type=click.Path(path_type=Path), default=None,
              help="Directory containing YAML rule files (default: ./rules)")
@click.option("--duration", type=int, default=0,
              help="Stop after N seconds (0 = run until Ctrl-C)")
def cmd_live(interface: str, rules_dir: Path | None, duration: int) -> None:
    """Capture packets live from INTERFACE (requires elevated privileges)."""
    PcapReader, FlowTracker, DetectionEngine, Dashboard = _import_pipeline()
    from capture.live_capture import LiveCapture, PermissionError as CapturePermissionError

    if rules_dir is None:
        rules_dir = Path(__file__).parent / "rules"

    console.print(f"[bold cyan]NetSentinel-DPI[/bold cyan] - live capture on [green]{interface}[/green]")

    tracker = FlowTracker()
    engine = DetectionEngine(rules_dir=rules_dir)

    try:
        capture = LiveCapture(interface=interface, timeout=duration or None)
        for packet in capture.stream():
            flow = tracker.process_packet(packet)
            if flow:
                engine.evaluate(flow, packet)
    except CapturePermissionError as exc:
        _print_permission_error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped.[/yellow]")

    engine.finalize(tracker)
    dash = Dashboard(tracker=tracker, engine=engine)
    dash.print_summary()


@cli.command("stats")
@click.option("--pcap", "pcap_file", type=click.Path(exists=True, path_type=Path),
              default=None, help="Analyse this PCAP instead of a live session dump")
def cmd_stats(pcap_file: Path | None) -> None:
    """Show Rich terminal dashboard of flow/protocol/alert statistics."""
    PcapReader, FlowTracker, DetectionEngine, Dashboard = _import_pipeline()

    if pcap_file is None:
        console.print("[red]Provide a --pcap file for offline stats.[/red]")
        sys.exit(1)

    tracker = FlowTracker()
    engine = DetectionEngine(rules_dir=Path(__file__).parent / "rules")
    reader = PcapReader(pcap_file)
    for packet in reader.read():
        flow = tracker.process_packet(packet)
        if flow:
            engine.evaluate(flow, packet)
    engine.finalize(tracker)
    Dashboard(tracker=tracker, engine=engine).print_full_dashboard()


@cli.command("alerts")
@click.option("--pcap", "pcap_file", type=click.Path(exists=True, path_type=Path),
              default=None, help="PCAP file to analyse")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]),
              default=None, help="Filter by severity")
def cmd_alerts(pcap_file: Path | None, severity: str | None) -> None:
    """Display detected alerts as a Rich table (filterable by severity)."""
    PcapReader, FlowTracker, DetectionEngine, Dashboard = _import_pipeline()

    if pcap_file is None:
        console.print("[red]Provide a --pcap file.[/red]")
        sys.exit(1)

    tracker = FlowTracker()
    engine = DetectionEngine(rules_dir=Path(__file__).parent / "rules")
    reader = PcapReader(pcap_file)
    for packet in reader.read():
        flow = tracker.process_packet(packet)
        if flow:
            engine.evaluate(flow, packet)
    engine.finalize(tracker)
    Dashboard(tracker=tracker, engine=engine).print_alerts_table(severity_filter=severity)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_permission_error(detail: str) -> None:
    """Print a platform-specific error message for capture permission failures."""
    os_name = platform.system()
    console.print("\n[bold red][!] Insufficient privileges for live capture[/bold red]")
    console.print(f"    Detail: {detail}\n")
    if os_name == "Windows":
        console.print("    [yellow]Windows fix:[/yellow]")
        console.print("      1. Install Npcap from [link=https://npcap.com]https://npcap.com[/link]")
        console.print("      2. Re-run this command from an [bold]Administrator[/bold] terminal")
        console.print("         (right-click PowerShell → 'Run as administrator')")
    else:
        console.print("    [yellow]Linux/macOS fix:[/yellow]")
        console.print("      • Run with sudo:  [cyan]sudo dpi live <interface>[/cyan]")
        console.print("      • Or grant cap:   [cyan]sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)[/cyan]")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
