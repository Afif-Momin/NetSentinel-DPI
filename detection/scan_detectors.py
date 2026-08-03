"""
detection/scan_detectors.py
============================
Port-scan detection helpers used by the engine.
Stand-alone functions testable without live packets.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from detection.flow_tracker import Flow, FlowTracker


def detect_port_scans(
    tracker: FlowTracker,
    threshold_ports: int = 15,
    window_seconds: float = 120.0,
) -> List[Tuple[str, int, Set[int]]]:
    """
    Return a list of (src_ip, distinct_port_count, port_set) tuples
    for sources exceeding *threshold_ports* distinct destination ports.

    Parameters
    ----------
    tracker         : FlowTracker already populated.
    threshold_ports : Minimum distinct ports to flag as scan.
    window_seconds  : Not enforced here (no timestamps in aggregated data);
                      documented for the rule YAML field.
    """
    src_to_ports: Dict[str, Set[int]] = {}
    for flow in tracker.flows():
        src = flow.src_ip
        if src not in src_to_ports:
            src_to_ports[src] = set()
        src_to_ports[src].add(flow.dst_port)

    results = []
    for src_ip, ports in src_to_ports.items():
        if len(ports) >= threshold_ports:
            results.append((src_ip, len(ports), ports))
    return results
