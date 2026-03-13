"""
M7 SSRF Parameter Discovery — Auto-detects SSRF-injectable parameters.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from utils.logger import Logger


# SSRF-sensitive parameter name patterns (ordered by likelihood)
SSRF_PARAM_NAMES = [
    # Direct URL/URI parameters
    "url", "uri", "URL", "URI",
    # Path / file parameters
    "path", "file", "filepath", "filename", "document", "page", "resource",
    # Redirect parameters
    "redirect", "next", "return", "returnurl", "return_url", "returnto",
    "back", "goto", "target", "continue", "redir",
    # Remote resource parameters
    "src", "source", "dest", "destination", "link", "href",
    # Host/IP parameters
    "host", "hostname", "ip", "addr", "address", "server", "domain",
    "site", "endpoint", "service",
    # Media/content parameters
    "image", "img", "avatar", "icon", "thumbnail", "preview", "photo",
    "picture", "media",
    # Data/import parameters
    "data", "feed", "fetch", "load", "import", "export", "content",
    "html", "template", "config",
    # Callback/webhook parameters
    "callback", "webhook", "notify", "ping", "hook",
    # Proxy/API parameters
    "proxy", "api", "remote", "request", "open", "view", "download",
    "upload", "show", "include",
    # Action parameters
    "action", "to", "from", "via",
]

# Pattern for parameter name fuzzy matching
SSRF_PARAM_PATTERNS = [
    re.compile(r"(url|uri|src|source|dest(ination)?|redirect|return|"
               r"back|goto|target|link|href|file|path|host|ip|addr|"
               r"image|img|feed|fetch|data|proxy|endpoint|callback|"
               r"webhook|remote|resource|download|import|open)", re.IGNORECASE),
]


class ParameterDiscovery:
    """
    Discovers SSRF-injectable parameters from:
    1. URL query string
    2. Common parameter name patterns
    3. Fragment identifiers
    """

    def __init__(self, logger: Logger):
        self.logger = logger

    def discover(self, url: str) -> Dict[str, str]:
        """
        Discover all SSRF-injectable parameters in a URL.
        Returns dict of {param_name: original_value}.
        """
        found = {}

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, values in query_params.items():
            if self._is_ssrf_param(param_name):
                found[param_name] = values[0] if values else ""
                self.logger.verbose(
                    f"[+] SSRF param candidate: {param_name}={values[0] if values else ''}"
                )
            else:
                # Check if the VALUE looks like a URL (may be SSRF even with generic param name)
                val = values[0] if values else ""
                if self._value_looks_like_url(val):
                    found[param_name] = val
                    self.logger.verbose(
                        f"[+] URL-value param candidate: {param_name}={val}"
                    )

        # If no params found in query string, try to extract from path
        if not found:
            path_params = self._extract_path_params(parsed.path)
            found.update(path_params)

        return found

    def _is_ssrf_param(self, param_name: str) -> bool:
        """Check if parameter name matches known SSRF patterns."""
        # Exact match (case-insensitive)
        if param_name.lower() in [p.lower() for p in SSRF_PARAM_NAMES]:
            return True

        # Pattern match
        for pattern in SSRF_PARAM_PATTERNS:
            if pattern.search(param_name):
                return True

        return False

    def _value_looks_like_url(self, value: str) -> bool:
        """Check if a value looks like a URL or IP address."""
        if not value:
            return False
        url_patterns = [
            re.compile(r"^https?://", re.IGNORECASE),
            re.compile(r"^ftp://", re.IGNORECASE),
            re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
            re.compile(r"^localhost", re.IGNORECASE),
            re.compile(r"^//"),  # Protocol-relative URL
        ]
        return any(p.search(value) for p in url_patterns)

    def _extract_path_params(self, path: str) -> Dict[str, str]:
        """
        Try to detect parameters embedded in the URL path.
        E.g. /fetch/https%3A%2F%2Fexample.com
        """
        found = {}
        # URL-encoded HTTP(S) in path
        if re.search(r"https?(%3A|:)(%2F|/){2}", path, re.IGNORECASE):
            # Extract last path segment as a parameter
            segments = path.strip("/").split("/")
            for segment in segments:
                if re.search(r"https?(%3A|:)(%2F|/){2}", segment, re.IGNORECASE):
                    found["path_url"] = segment
                    break

        return found

    def get_common_params(self) -> List[str]:
        """Return the full list of common SSRF parameter names."""
        return SSRF_PARAM_NAMES.copy()
