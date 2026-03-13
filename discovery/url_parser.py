"""
M7 SSRF URL Parser — URL manipulation utilities.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import re
from urllib.parse import (
    urlparse, urlunparse, urlencode, parse_qs,
    quote, unquote, urljoin
)
from typing import Dict, List, Optional, Tuple


class URLParser:
    """URL parsing and manipulation utilities for SSRF testing."""

    @staticmethod
    def parse(url: str) -> dict:
        """Parse URL into components."""
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "host": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "params": parse_qs(parsed.query, keep_blank_values=True),
        }

    @staticmethod
    def replace_param(url: str, param: str, value: str) -> str:
        """Replace a query parameter value in a URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_params[param] = [value]
        new_query = "&".join(
            f"{k}={v[0]}" for k, v in query_params.items()
        )
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def add_param(url: str, param: str, value: str) -> str:
        """Add a new query parameter to a URL."""
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{param}={quote(value, safe='')}"

    @staticmethod
    def normalize(url: str) -> str:
        """Normalize URL — ensure it has a scheme."""
        if not url.startswith(("http://", "https://", "ftp://", "file://")):
            url = "https://" + url
        return url

    @staticmethod
    def extract_base(url: str) -> str:
        """Extract base URL (scheme + netloc)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def is_internal(url: str) -> bool:
        """Check if a URL points to an internal/private address."""
        internal_patterns = [
            r"^https?://localhost",
            r"^https?://127\.",
            r"^https?://10\.",
            r"^https?://192\.168\.",
            r"^https?://172\.(1[6-9]|2[0-9]|3[01])\.",
            r"^https?://0\.0\.0\.0",
            r"^https?://\[::1\]",
            r"^https?://\[fc",
            r"^https?://169\.254\.",
        ]
        for pattern in internal_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def encode_url_for_injection(url: str) -> List[str]:
        """
        Generate multiple encodings of a URL for bypass testing.
        Returns list of encoded variants.
        """
        variants = [url]

        # URL-encoded
        variants.append(quote(url, safe=""))

        # Double URL-encoded
        variants.append(quote(quote(url, safe=""), safe=""))

        # HTML entity encoded
        html_encoded = url.replace(":", "&#58;").replace("/", "&#47;")
        variants.append(html_encoded)

        return list(dict.fromkeys(variants))  # dedupe

    @staticmethod
    def extract_urls_from_body(body: str) -> List[str]:
        """Extract all URLs from an HTML/JS response body."""
        url_pattern = re.compile(
            r'https?://[^\s\'"<>(){}[\]\\,;|`]+',
            re.IGNORECASE
        )
        return list(set(url_pattern.findall(body)))

    @staticmethod
    def extract_endpoints_from_js(js_content: str) -> List[str]:
        """Extract API endpoints from JavaScript content."""
        endpoints = []

        patterns = [
            re.compile(r'''["'](/api/[^"'\s]+)["']'''),
            re.compile(r'''["'](/v\d+/[^"'\s]+)["']'''),
            re.compile(r'''fetch\(["']([^"']+)["']'''),
            re.compile(r'''axios\.(get|post|put)\(["']([^"']+)["']'''),
            re.compile(r'''url:\s*["']([^"']+)["']'''),
        ]

        for pattern in patterns:
            for match in pattern.finditer(js_content):
                endpoint = match.group(1) if match.lastindex == 1 else match.group(2)
                endpoints.append(endpoint)

        return list(set(endpoints))
