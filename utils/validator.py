"""
M7 SSRF Validator — Input validation utilities.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import re
from urllib.parse import urlparse
from typing import Optional


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP(S) URL."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https", "ftp") and bool(parsed.netloc)
    except Exception:
        return False


def is_valid_ip(ip: str) -> bool:
    """Validate an IPv4 address."""
    pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if not pattern.match(ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name."""
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def sanitize_url(url: str) -> Optional[str]:
    """Sanitize and normalize a URL."""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://", "file://")):
        url = "http://" + url
    return url if is_valid_url(url) else None


def is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    private_ranges = [
        re.compile(r"^10\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^127\."),
        re.compile(r"^169\.254\."),
        re.compile(r"^0\."),
        re.compile(r"^::1$"),
        re.compile(r"^fc[0-9a-f]{2}:", re.IGNORECASE),  # IPv6 ULA
    ]
    return any(p.match(ip) for p in private_ranges)


def validate_thread_count(count: int) -> int:
    """Clamp thread count to a safe range."""
    return max(1, min(count, 500))


def validate_timeout(timeout: int) -> int:
    """Clamp timeout to a sane range (1s - 120s)."""
    return max(1, min(timeout, 120))
