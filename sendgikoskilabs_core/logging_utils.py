"""
sendgikoskilabs_core.logging_utils
====================================
CSV logging utilities shared across all SendgikoskiLabs tools.
"""

import csv
from pathlib import Path
from .models import HostCheckResult


def ensure_log_dir(log_dir: Path) -> None:
    """Create the log directory if it does not exist."""
    log_dir.mkdir(parents=True, exist_ok=True)


def log_check(result: HostCheckResult, log_dir: Path) -> None:
    """
    Append a HostCheckResult to the netcheck CSV log.

    Creates the log file and writes a header row on first call.
    Appends on all subsequent calls.

    Args:
        result:  The HostCheckResult to log.
        log_dir: Directory where netcheck_log.csv is stored.
    """
    ensure_log_dir(log_dir)
    log_file = log_dir / "netcheck_log.csv"
    write_header = not log_file.exists()
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow([
                "timestamp", "host", "ip", "dns_ms", "tcp_ms",
                "tls_ms", "http_status", "total_ms"
            ])
        writer.writerow([
            result.timestamp,
            result.host,
            result.ip,
            result.dns_ms,
            result.tcp_ms,
            result.tls_ms,
            result.http_status,
            result.total_ms,
        ])
