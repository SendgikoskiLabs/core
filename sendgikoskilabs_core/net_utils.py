"""
sendgikoskilabs_core.net_utils
================================
Network diagnostic primitives shared across all SendgikoskiLabs tools.

All functions are pure (no side effects) and return None / empty results
on failure rather than raising exceptions, making them safe to call in
monitoring loops.
"""

import socket
import ssl
import time
import platform
import subprocess
import re
import statistics
import sys
from typing import Optional, Tuple, List, Dict

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

IS_WINDOWS = platform.system() == "Windows"


# ── DNS ──────────────────────────────────────────────────────────────────────

def dns_resolve(host: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Resolve a hostname to an IPv4 address and measure the latency.

    Returns:
        (ip, latency_ms) on success
        (None, None) on failure
    """
    try:
        t0 = time.perf_counter()
        ip = socket.gethostbyname(host)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return ip, ms
    except Exception:
        return None, None


# ── TCP connect ───────────────────────────────────────────────────────────────

def tcp_connect(host: str, port: int = 443,
                timeout: int = 3) -> Optional[float]:
    """
    Measure TCP connection latency to host:port.

    Returns:
        latency_ms on success
        None on failure
    """
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((host, port), timeout)
        sock.close()
        return round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        return None


# ── TLS handshake ─────────────────────────────────────────────────────────────

def tls_handshake(host: str, timeout: int = 5) -> Optional[float]:
    """
    Measure TLS handshake latency to host:443.

    Returns:
        latency_ms on success
        None on failure
    """
    try:
        ctx = ssl.create_default_context()
        t0 = time.perf_counter()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        return round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        return None


# ── HTTP status ───────────────────────────────────────────────────────────────

def http_check(host: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Send an HTTP HEAD request and return the status code and redirect URL.

    Requires the 'requests' library.

    Returns:
        (status_code, redirect_url) on success
        (None, None) if requests is unavailable or request fails
    """
    if not HAS_REQUESTS:
        return None, None
    try:
        r = _requests.head(
            f"https://{host}", timeout=5, allow_redirects=False
        )
        return r.status_code, r.headers.get("Location")
    except Exception:
        return None, None


# ── ASN / Geo lookup ──────────────────────────────────────────────────────────

def asn_lookup(ip: Optional[str]) -> Tuple[str, str, str]:
    """
    Look up the ASN, provider name, and geographic location for an IP address
    using the ipinfo.io API.

    Requires the 'requests' library.

    Returns:
        (asn, provider, location) on success
        ("Unknown", "Unknown", "Unknown") on failure or missing requests
    """
    if not ip or not HAS_REQUESTS:
        return "Unknown", "Unknown", "Unknown"
    try:
        r = _requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = r.json()
        org = data.get("org", "Unknown")
        if org == "Unknown":
            return "Unknown", "Unknown", "Unknown"
        parts = org.split(None, 1)
        asn = parts[0]
        provider = parts[1] if len(parts) > 1 else "Unknown"
        location = ", ".join(
            filter(None, [
                data.get("city"),
                data.get("region"),
                data.get("country")
            ])
        )
        return asn, provider, location
    except Exception:
        return "Unknown", "Unknown", "Unknown"


# ── Traceroute parsers ────────────────────────────────────────────────────────

def parse_tracert_windows(output: str):
    """
    Parse Windows tracert output into a list of hop dicts.

    Windows format:
      Tracing route to google.com [64.233.177.138]
      over a maximum of 10 hops:
        1     4 ms     4 ms     3 ms  172.19.54.193
        2     *        *        *     Request timed out.

    Returns:
        (hops, filtered_hops, slowest_hop, slowest_ms)
    """
    hops = []
    filtered_hops = 0
    slowest_hop = None
    slowest_ms = 0.0

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if not parts:
            continue
        try:
            hop_num = int(parts[0])
        except ValueError:
            continue

        hop_num_str = str(hop_num)

        if "timed out" in stripped.lower():
            filtered_hops += 1
            continue

        latencies = [
            float(x)
            for x in re.findall(r"(\d+(?:\.\d+)?)\s+ms", stripped)
        ]
        hop_ip = None
        ip_matches = re.findall(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", stripped
        )
        if ip_matches:
            hop_ip = ip_matches[-1]

        if not latencies and not hop_ip:
            filtered_hops += 1
            continue

        avg = round(statistics.mean(latencies), 2) if latencies else None
        hop = {
            "hop": hop_num_str,
            "ip": hop_ip or "*",
            "latencies": latencies,
            "avg_ms": avg,
        }
        hops.append(hop)

        if latencies:
            peak = max(latencies)
            if peak > slowest_ms:
                slowest_ms = peak
                slowest_hop = stripped

    return hops, filtered_hops, slowest_hop, slowest_ms


def parse_traceroute_linux(output: str):
    """
    Parse Linux/macOS traceroute -n output into a list of hop dicts.

    Linux format:
      traceroute to google.com (...), 15 hops max, 60 byte packets
       1  172.28.128.1  0.470 ms  0.437 ms  0.421 ms
       2  172.19.54.193  7.042 ms  ...
       3  * * *

    Returns:
        (hops, filtered_hops, slowest_hop, slowest_ms)
    """
    hops = []
    filtered_hops = 0
    slowest_hop = None
    slowest_ms = 0.0

    for line in output.splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if not parts:
            continue
        if "* * *" in stripped:
            filtered_hops += 1
            continue
        if not parts[0].isdigit():
            continue

        hop_num = parts[0]
        latencies = [
            float(x)
            for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", stripped)
        ]
        hop_ip = None
        for p in parts[1:]:
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", p):
                hop_ip = p
                break

        avg = round(statistics.mean(latencies), 2) if latencies else None
        hop = {
            "hop": hop_num,
            "ip": hop_ip or "*",
            "latencies": latencies,
            "avg_ms": avg,
        }
        hops.append(hop)

        if latencies:
            peak = max(latencies)
            if peak > slowest_ms:
                slowest_ms = peak
                slowest_hop = stripped

    return hops, filtered_hops, slowest_hop, slowest_ms
