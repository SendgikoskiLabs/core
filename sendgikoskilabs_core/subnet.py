"""
sendgikoskilabs_core.subnet
============================
IPv4 subnet helpers used for anycast-aware IP change detection.
"""


def ip_to_int(ip: str) -> int:
    """Convert dotted-quad IPv4 string to a 32-bit integer."""
    try:
        parts = [int(x) for x in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return 0


def same_subnet(ip_a: str, ip_b: str, prefix: int = 24) -> bool:
    """
    Return True if two IPv4 addresses share the same /<prefix> subnet.

    Default /24 catches anycast rotation within a provider's block.
    Use prefix=16 for very broad suppression (e.g. entire GitHub range).

    Examples:
        same_subnet("140.82.112.3", "140.82.112.4")  → True  (same /24)
        same_subnet("140.82.112.3", "140.82.113.3")  → False (different /24)
        same_subnet("140.82.112.3", "140.82.113.3", prefix=16) → True
    """
    if not ip_a or not ip_b:
        return False
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_to_int(ip_a) & mask) == (ip_to_int(ip_b) & mask)
