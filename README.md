# sendgikoskilabs-core

**Shared library for the SendgikoskiLabs network tooling suite.**

[![Version](https://img.shields.io/badge/version-1.0.0-89b4fa?style=flat-square)](https://github.com/SendgikoskiLabs/core)
[![Python](https://img.shields.io/badge/python-3.8%2B-cba6f7?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-f9e2af?style=flat-square)]()

---

## Overview

`sendgikoskilabs-core` is the shared foundation for all tools in the
SendgikoskiLabs suite. It provides the data models, network diagnostic
primitives, InfluxDB export utilities, CLI formatters, CSV logging, and
monitor state management used by every tool in the suite.

Tools import from core rather than duplicating code, ensuring that bug
fixes and improvements benefit the entire suite instantly.

---

## Modules

| Module | Contents |
|---|---|
| `models` | `PingResult`, `HostCheckResult`, `TracerouteResult` dataclasses |
| `net_utils` | `dns_resolve`, `tcp_connect`, `tls_handshake`, `http_check`, `asn_lookup`, traceroute parsers |
| `subnet` | `same_subnet`, `ip_to_int` — anycast-aware IP change detection |
| `influx` | `load_influx_config`, `build_line_protocol`, `write_to_influx`, `test_connection` |
| `formatters` | `format_ping`, `format_check`, `format_traceroute`, `http_label` |
| `logging_utils` | `log_check`, `ensure_log_dir` — CSV logging |
| `monitor` | `MonitorState` — per-host history, baselines, change detection |

---

## Installation

### For development (editable install)

```bash
git clone https://github.com/SendgikoskiLabs/core.git
cd core
pip install -e .
```

### As a dependency in another tool

```bash
pip install -e ../core   # from a sibling directory
```

### Optional dependency

ASN lookup, HTTP checks, and InfluxDB export require `requests`:

```bash
pip install requests
```

---

## Usage

```python
from sendgikoskilabs_core import (
    dns_resolve, tcp_connect, tls_handshake,
    http_check, asn_lookup,
    HostCheckResult,
    build_line_protocol, write_to_influx,
    format_check,
    MonitorState,
)

# DNS + TCP + TLS + HTTP + ASN in sequence
ip, dns_ms  = dns_resolve("github.com")
tcp_ms      = tcp_connect("github.com")
tls_ms      = tls_handshake("github.com")
status, loc = http_check("github.com")
asn, prov, loc = asn_lookup(ip)

result = HostCheckResult(
    host="github.com", ip=ip, asn=asn, provider=prov,
    location=loc, dns_ms=dns_ms, tcp_ms=tcp_ms, tls_ms=tls_ms,
    http_status=status, http_redirect=loc,
    total_ms=dns_ms + tcp_ms, success=bool(tcp_ms),
)

print(format_check(result))
```

---

## Part of the SendgikoskiLabs Suite

```
SendgikoskiLabs/
├── core/          ← you are here
├── netcheck/      # single-host network diagnostics
├── ispinsight/    # ISP analysis: BGP routes, peering
├── logsleuth/     # log analysis and anomaly detection
└── netwatch/      # unified platform with Grafana integration
```

---

## License

MIT License — free to use, modify, and distribute.

## Author

**Alan Sendgikoski** — SendgikoskiLabs
[LinkedIn](https://www.linkedin.com/in/alansendgikoski/) ·
[GitHub](https://github.com/SendgikoskiLabs)
