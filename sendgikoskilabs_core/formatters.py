"""
sendgikoskilabs_core.formatters
================================
CLI output formatters shared across all SendgikoskiLabs tools.
"""

from typing import Optional
from .models import PingResult, HostCheckResult, TracerouteResult

SLOW_HOP_THRESHOLD = 120  # ms


def http_label(code: Optional[int]) -> str:
    """Convert an HTTP status code to a human-readable label."""
    if code is None:
        return "N/A"
    if 200 <= code < 300:
        return f"{code} [OK]"
    if 300 <= code < 400:
        return f"{code} [REDIRECT]"
    if 400 <= code < 500:
        return f"{code} [CLIENT ERROR]"
    if 500 <= code < 600:
        return f"{code} [SERVER ERROR]"
    return f"{code} [UNKNOWN]"


def format_ping(r: PingResult) -> str:
    status = "✓ Success" if r.success else "✗ Failed"
    return f"""
╔══════════════════════════════════════════════════════════╗
║         PING RESULTS  —  {status:<30}║
╚══════════════════════════════════════════════════════════╝
  Host             : {r.host}
  Packets Sent     : {r.packets_sent}
  Packets Received : {r.packets_received}
  Packet Loss      : {r.packet_loss:.1f}%
  Min / Avg / Max  : {r.min_time:.2f} / {r.avg_time:.2f} / {r.max_time:.2f} ms
  Std Dev (Jitter) : {r.std_dev:.2f} ms
  Timestamp        : {r.timestamp}
"""


def format_check(r: HostCheckResult) -> str:
    status  = "✓ OK" if r.success else "✗ FAILED"
    tcp_str = f"{r.tcp_ms:.2f} ms  [OK]" if r.tcp_ms else "FAILED"
    tls_str = f"{r.tls_ms:.2f} ms" if r.tls_ms else "N/A"
    dns_str = f"{r.dns_ms:.2f} ms" if r.dns_ms else "N/A"
    return f"""
╔══════════════════════════════════════════════════════════╗
║      HOST CHECK  —  {status:<37}║
╚══════════════════════════════════════════════════════════╝
  Host             : {r.host}
  Resolved IP      : {r.ip or 'N/A'}
  ASN              : {r.asn}
  Provider         : {r.provider}
  Location         : {r.location}
  DNS Resolve      : {dns_str}
  TCP Connect      : {tcp_str}
  TLS Handshake    : {tls_str}
  HTTP Status      : {http_label(r.http_status)}
  Redirect To      : {r.http_redirect or 'N/A'}
  Total Time       : {r.total_ms:.2f} ms
  Timestamp        : {r.timestamp}
"""


def format_traceroute(r: TracerouteResult) -> str:
    status = "✓ Success" if r.success else "✗ Failed"
    lines = [
        f"\n╔══════════════════════════════════════════════════════════╗",
        f"║   TRACEROUTE  —  {status:<40}║",
        f"╚══════════════════════════════════════════════════════════╝",
        f"  Host  : {r.host}",
        f"  Hops  : {len(r.hops)}   Filtered: {r.filtered_hops}",
    ]
    if not r.success and r.slowest_hop and not r.hops:
        lines.append(f"\n  ✗  Error: {r.slowest_hop}")
        lines.append(f"\n  Timestamp: {r.timestamp}")
        return "\n".join(lines)
    lines += [
        "",
        f"  {'HOP':<5} {'IP':<18} {'AVG ms':>8}",
        f"  {'─'*5} {'─'*18} {'─'*8}",
    ]
    for hop in r.hops:
        avg = f"{hop['avg_ms']:.2f}" if hop["avg_ms"] is not None else "  *"
        lines.append(f"  {hop['hop']:<5} {hop['ip']:<18} {avg:>8}")
    if r.filtered_hops:
        lines.append(
            f"\n  ⚠  {r.filtered_hops} hop(s) did not respond (filtered by ISP)"
        )
    if r.nat_warning:
        lines.append(f"\n  ╔══════════════════════════════════════════════════════╗")
        lines.append(f"  ║  ⚠  PATH OBSCURATION WARNING                        ║")
        lines.append(f"  ╠══════════════════════════════════════════════════════╣")
        lines.append(f"  ║  Only {len(r.hops)} hop(s) visible before the path goes dark.  ║")
        lines.append(f"  ║  This typically means one or more of the following:  ║")
        lines.append(f"  ║    • Running inside WSL2 / Hyper-V / a VM            ║")
        lines.append(f"  ║    • Double-NAT (router behind router)               ║")
        lines.append(f"  ║    • ISP or corporate firewall blocking all probes   ║")
        lines.append(f"  ║  Traceroute results beyond hop {len(r.hops)} are unreliable.  ║")
        lines.append(f"  ║  For accurate path data, run from a bare-metal host  ║")
        lines.append(f"  ║  or a cloud VPS with direct internet routing.        ║")
        lines.append(f"  ╚══════════════════════════════════════════════════════╝")
    if r.slowest_hop and r.slowest_ms > SLOW_HOP_THRESHOLD:
        lines.append(f"\n  ⚠  Possible bottleneck detected at {r.slowest_ms:.1f} ms:")
        lines.append(f"     {r.slowest_hop}")
    lines.append(f"\n  Timestamp: {r.timestamp}")
    return "\n".join(lines)
