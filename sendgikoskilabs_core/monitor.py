"""
sendgikoskilabs_core.monitor
==============================
MonitorState — per-host monitoring history, baselines, and change detection.
Shared across all SendgikoskiLabs tools that implement continuous monitoring.
"""

import statistics
from collections import defaultdict
from typing import Dict, List, Optional

from .models import HostCheckResult
from .subnet import same_subnet

PACKET_LOSS_THRESHOLD = 20   # %
LATENCY_SPIKE_MULTIPLIER = 2.0


class MonitorState:
    """
    Holds per-host monitoring history, adaptive baselines, and
    last-known values for change detection.

    Usage:
        state = MonitorState()
        state.record(result)
        stats = state.analyze(host)
        alert = state.check_ip_change(host, new_ip)
    """

    def __init__(self):
        self.history: Dict[str, List[HostCheckResult]] = defaultdict(list)
        self.baseline: Dict[str, float] = {}
        self.last_ip: Dict[str, Optional[str]] = {}
        self.last_asn: Dict[str, Optional[str]] = {}
        self.last_route: Dict[str, List[str]] = {}
        self.last_spike: Dict[str, float] = {}

    def record(self, result: HostCheckResult) -> None:
        """Append a result to the host's history."""
        self.history[result.host].append(result)

    def analyze(self, host: str) -> Optional[dict]:
        """
        Compute latency statistics over the last 5 samples for a host.

        Returns None if fewer than 3 samples have been collected.

        Returns:
            dict with keys: avg, min, max, jitter, loss
        """
        samples = self.history[host]
        if len(samples) < 3:
            return None
        recent = samples[-5:]
        valid_tcp = [
            s.tcp_ms for s in recent
            if s.tcp_ms is not None and s.tcp_ms > 0
        ]
        if not valid_tcp:
            return None
        failures = sum(
            1 for s in recent if s.tcp_ms is None or s.tcp_ms == 0
        )
        return {
            "avg":    statistics.mean(valid_tcp),
            "min":    min(valid_tcp),
            "max":    max(valid_tcp),
            "jitter": max(valid_tcp) - min(valid_tcp),
            "loss":   (failures / len(recent)) * 100,
        }

    def check_ip_change(self, host: str, new_ip: Optional[str],
                        anycast_prefix: int = 24) -> Optional[str]:
        """
        Detect meaningful IP changes, suppressing anycast rotation within
        the same /<anycast_prefix> subnet (default /24).

        Returns:
            Alert string if a genuine re-route is detected, else None.
        """
        prev = self.last_ip.get(host)
        self.last_ip[host] = new_ip
        if not prev or not new_ip or prev == new_ip:
            return None
        if same_subnet(prev, new_ip, anycast_prefix):
            return None  # Routine anycast rotation — suppress
        return (
            f"IP change: {prev} → {new_ip} "
            f"(crossed /{anycast_prefix} boundary)"
        )

    def check_asn_change(self, host: str, new_asn: str) -> Optional[str]:
        """
        Detect ASN changes (different provider / upstream).

        Returns:
            Alert string if ASN changed, else None.
        """
        prev = self.last_asn.get(host)
        self.last_asn[host] = new_asn
        if prev and new_asn != "Unknown" and prev != new_asn:
            return f"ASN change: {prev} → {new_asn}"
        return None

    def check_route_change(self, host: str,
                           new_route: List[str]) -> List[str]:
        """
        Detect traceroute hop sequence changes between cycles.

        Returns:
            List of change description strings (empty if no changes).
        """
        prev = self.last_route.get(host)
        self.last_route[host] = new_route
        changes = []
        if prev and new_route and prev != new_route:
            for i, (old, new) in enumerate(zip(prev, new_route)):
                if old != new:
                    changes.append(f"Hop {i+1}: {old} → {new}")
        return changes
