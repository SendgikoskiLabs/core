"""
sendgikoskilabs_core
=====================
Shared library for the SendgikoskiLabs network tooling suite.

Public API — import directly from this package:

    from sendgikoskilabs_core import (
        # Data models
        PingResult, HostCheckResult, TracerouteResult,

        # Network diagnostics
        dns_resolve, tcp_connect, tls_handshake, http_check, asn_lookup,
        parse_tracert_windows, parse_traceroute_linux,

        # Subnet helpers
        ip_to_int, same_subnet,

        # InfluxDB
        load_influx_config, build_line_protocol,
        write_to_influx, test_connection,

        # Formatters
        http_label, format_ping, format_check, format_traceroute,

        # CSV logging
        log_check, ensure_log_dir,

        # Monitor state
        MonitorState,
    )
"""

# ── Models ────────────────────────────────────────────────────────────────────
from .models import PingResult, HostCheckResult, TracerouteResult

# ── Network utilities ─────────────────────────────────────────────────────────
from .net_utils import (
    dns_resolve,
    tcp_connect,
    tls_handshake,
    http_check,
    asn_lookup,
    parse_tracert_windows,
    parse_traceroute_linux,
)

# ── Subnet helpers ────────────────────────────────────────────────────────────
from .subnet import ip_to_int, same_subnet

# ── InfluxDB ──────────────────────────────────────────────────────────────────
from .influx import (
    load_influx_config,
    build_line_protocol,
    write_to_influx,
    test_connection,
)

# ── Formatters ────────────────────────────────────────────────────────────────
from .formatters import http_label, format_ping, format_check, format_traceroute

# ── CSV logging ───────────────────────────────────────────────────────────────
from .logging_utils import log_check, ensure_log_dir

# ── Monitor state ─────────────────────────────────────────────────────────────
from .monitor import MonitorState

__version__ = "1.0.0"
__all__ = [
    # Models
    "PingResult", "HostCheckResult", "TracerouteResult",
    # Net utils
    "dns_resolve", "tcp_connect", "tls_handshake", "http_check", "asn_lookup",
    "parse_tracert_windows", "parse_traceroute_linux",
    # Subnet
    "ip_to_int", "same_subnet",
    # InfluxDB
    "load_influx_config", "build_line_protocol",
    "write_to_influx", "test_connection",
    # Formatters
    "http_label", "format_ping", "format_check", "format_traceroute",
    # Logging
    "log_check", "ensure_log_dir",
    # Monitor
    "MonitorState",
]
