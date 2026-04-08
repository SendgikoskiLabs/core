"""
sendgikoskilabs_core.models
============================
Shared dataclasses used across all SendgikoskiLabs tools.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict


@dataclass
class PingResult:
    host: str
    packets_sent: int
    packets_received: int
    packet_loss: float
    min_time: float
    max_time: float
    avg_time: float
    std_dev: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HostCheckResult:
    host: str
    ip: Optional[str]
    asn: str
    provider: str
    location: str
    dns_ms: Optional[float]
    tcp_ms: Optional[float]
    tls_ms: Optional[float]
    http_status: Optional[int]
    http_redirect: Optional[str]
    total_ms: float
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TracerouteResult:
    host: str
    hops: List[Dict]
    filtered_hops: int
    slowest_hop: Optional[str]
    slowest_ms: float
    success: bool
    nat_warning: bool = False   # True when path appears obscured by NAT/firewall
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
