"""
sendgikoskilabs_core.influx
============================
InfluxDB export utilities shared across all SendgikoskiLabs tools.

Supports InfluxDB v1.x and v2.x with auto-detection based on config.
Connection details loaded from (in priority order):
  1. CLI flags (caller passes values directly)
  2. influx.cfg file
  3. Environment variables

Usage:
    from sendgikoskilabs_core.influx import (
        load_influx_config,
        build_line_protocol,
        write_to_influx,
        test_connection,
    )
"""

import configparser
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Default measurement name — tools can override this
DEFAULT_MEASUREMENT = "netcheck"


def load_influx_config(cfg_file: Optional[Path] = None, args=None) -> dict:
    """
    Build the InfluxDB connection config by merging three sources.

    Priority (highest to lowest):
      1. Values in args namespace (CLI flags)
      2. influx.cfg file at cfg_file path
      3. Environment variables

    Args:
        cfg_file:  Path to influx.cfg. If None, no file is read.
        args:      argparse Namespace with influx_* attributes, or None.

    Returns:
        dict with keys: url, token, org, bucket,
                        username, password, database, version
    """
    # ── Step 1: Environment variables (lowest priority) ──────────────────────
    cfg = {
        "url":      os.environ.get("INFLUX_URL",      "http://localhost:8086"),
        "token":    os.environ.get("INFLUX_TOKEN",    ""),
        "org":      os.environ.get("INFLUX_ORG",      ""),
        "bucket":   os.environ.get("INFLUX_BUCKET",   "netcheck"),
        "username": os.environ.get("INFLUX_USERNAME", ""),
        "password": os.environ.get("INFLUX_PASSWORD", ""),
        "database": os.environ.get("INFLUX_DATABASE", "netcheck"),
    }

    # ── Step 2: influx.cfg file ───────────────────────────────────────────────
    if cfg_file and cfg_file.exists():
        parser = configparser.ConfigParser()
        parser.read(cfg_file)
        section = "influxdb"
        if parser.has_section(section):
            for key in cfg:
                if parser.has_option(section, key):
                    cfg[key] = parser.get(section, key).strip()

    # ── Step 3: CLI flags (highest priority) ─────────────────────────────────
    if args is not None:
        flag_map = {
            "influx_url":      "url",
            "influx_token":    "token",
            "influx_org":      "org",
            "influx_bucket":   "bucket",
            "influx_username": "username",
            "influx_password": "password",
            "influx_database": "database",
        }
        for flag, key in flag_map.items():
            val = getattr(args, flag, None)
            if val:
                cfg[key] = val

    # ── Auto-detect version ───────────────────────────────────────────────────
    cfg["version"] = "2" if cfg["token"] else "1"

    return cfg


def build_line_protocol(result, measurement: str = DEFAULT_MEASUREMENT) -> str:
    """
    Convert a HostCheckResult to InfluxDB line protocol.

    Format:
        measurement,tag=val field=val[,...] timestamp_ns

    Tags (indexed, low-cardinality):
        host, asn, provider

    Fields (numeric measurements):
        dns_ms, tcp_ms, tls_ms, http_status, total_ms, success

    Timestamp: nanoseconds since Unix epoch.

    Args:
        result:      A HostCheckResult instance.
        measurement: InfluxDB measurement name (default: "netcheck").

    Returns:
        Line protocol string, or "" if no fields are available.
    """
    try:
        dt = datetime.fromisoformat(result.timestamp)
        ts_ns = int(dt.timestamp() * 1_000_000_000)
    except Exception:
        ts_ns = int(time.time() * 1_000_000_000)

    def _tag(v: str) -> str:
        """Escape spaces, commas, and equals signs per line protocol spec."""
        return v.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")

    tags = (
        f"host={_tag(result.host)}"
        f",asn={_tag(result.asn or 'unknown')}"
        f",provider={_tag(result.provider or 'unknown')}"
    )

    fields = []
    if result.dns_ms    is not None: fields.append(f"dns_ms={result.dns_ms}")
    if result.tcp_ms    is not None: fields.append(f"tcp_ms={result.tcp_ms}")
    if result.tls_ms    is not None: fields.append(f"tls_ms={result.tls_ms}")
    if result.http_status is not None:
        fields.append(f"http_status={result.http_status}i")
    if result.total_ms  is not None: fields.append(f"total_ms={result.total_ms}")
    fields.append(f"success={'true' if result.success else 'false'}")

    if not fields:
        return ""

    return f"{measurement},{tags} {','.join(fields)} {ts_ns}"


def write_to_influx(line: str, cfg: dict) -> bool:
    """
    POST a single line protocol record to InfluxDB.

    Supports both v1.x (/write) and v2.x (/api/v2/write) automatically
    based on the 'version' key in cfg (set by load_influx_config).

    Non-fatal on failure — prints a warning to stderr but does not raise.

    Args:
        line: Line protocol string from build_line_protocol().
        cfg:  Config dict from load_influx_config().

    Returns:
        True on HTTP 200/204, False on any failure.
    """
    if not HAS_REQUESTS or not line:
        return False

    try:
        if cfg["version"] == "2":
            url = f"{cfg['url'].rstrip('/')}/api/v2/write"
            headers = {
                "Authorization": f"Token {cfg['token']}",
                "Content-Type":  "text/plain; charset=utf-8",
            }
            params = {
                "org":       cfg["org"],
                "bucket":    cfg["bucket"],
                "precision": "ns",
            }
        else:
            url = f"{cfg['url'].rstrip('/')}/write"
            headers = {"Content-Type": "text/plain; charset=utf-8"}
            params  = {"db": cfg["database"], "precision": "ns"}
            if cfg["username"]:
                import base64
                creds = base64.b64encode(
                    f"{cfg['username']}:{cfg['password']}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {creds}"

        response = _requests.post(
            url, params=params, headers=headers,
            data=line.encode("utf-8"), timeout=5
        )
        return response.status_code in (200, 204)

    except Exception as e:
        print(f"\n⚠️  InfluxDB write failed: {e}", file=sys.stderr)
        return False


def test_connection(cfg: dict) -> tuple:
    """
    Test the InfluxDB connection before starting a monitoring session.

    For v2.x: queries the /api/v2/buckets endpoint.
    For v1.x: pings the /ping endpoint.

    Args:
        cfg: Config dict from load_influx_config().

    Returns:
        (True, description_string) on success
        (False, error_string) on failure
    """
    if not HAS_REQUESTS:
        return False, "'requests' library required for InfluxDB export"

    try:
        if cfg["version"] == "2":
            url     = f"{cfg['url'].rstrip('/')}/api/v2/buckets"
            headers = {"Authorization": f"Token {cfg['token']}"}
            params  = {"org": cfg["org"]}
        else:
            url     = f"{cfg['url'].rstrip('/')}/ping"
            headers = {}
            params  = {}

        r = _requests.get(url, headers=headers, params=params, timeout=5)

        if cfg["version"] == "2" and r.status_code == 200:
            return True, (
                f"InfluxDB v2.x connected  "
                f"org={cfg['org']}  bucket={cfg['bucket']}"
            )
        elif cfg["version"] == "1" and r.status_code == 204:
            return True, f"InfluxDB v1.x connected  database={cfg['database']}"
        else:
            return False, (
                f"InfluxDB returned HTTP {r.status_code}: {r.text[:120]}"
            )

    except Exception as e:
        return False, f"InfluxDB connection failed: {e}"
