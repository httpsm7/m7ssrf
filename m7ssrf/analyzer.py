"""
M7 SSRF Analyzer — Response analysis engine.
Detects SSRF signals in HTTP responses.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import re
from typing import Dict, Any, List, Optional

from utils.logger import Logger


# Detection signatures
CRITICAL_SIGNATURES = [
    # AWS metadata
    (r"ami-id", "AWS EC2 metadata (ami-id)"),
    (r"instance-id", "AWS EC2 metadata (instance-id)"),
    (r"security-credentials", "AWS IAM credentials"),
    (r"iam/security-credentials", "AWS IAM credentials endpoint"),
    (r'"AccessKeyId"', "AWS Access Key found"),
    (r'"SecretAccessKey"', "AWS Secret Key found"),
    # GCP metadata
    (r"computeMetadata", "GCP compute metadata"),
    (r'"serviceAccounts"', "GCP service account data"),
    (r"gce-", "GCP metadata prefix"),
    # Azure metadata
    (r'"subscriptionId"', "Azure subscription ID"),
    (r'"resourceGroupName"', "Azure resource group"),
    (r'"vmId"', "Azure VM ID"),
    # Internal service responses
    (r"\+OK", "Redis PING response"),
    (r"redis_version", "Redis INFO response"),
    (r"NOAUTH Authentication required", "Redis auth prompt"),
    (r"memcached", "Memcached response"),
    (r"STAT pid", "Memcached stats"),
    # File read
    (r"root:x:0:0:", "Linux /etc/passwd content"),
    (r"root:.*:0:0:", "Linux /etc/passwd content"),
    (r"\[extensions\]", "Windows win.ini"),
    (r"PROCESSOR_IDENTIFIER", "Windows environment"),
]

HIGH_SIGNATURES = [
    # Internal IP reflected
    (r"127\.0\.0\.1", "Localhost IP reflected in response"),
    (r"169\.254\.169\.254", "Cloud metadata IP reflected"),
    (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "RFC1918 10.x.x.x IP in response"),
    (r"192\.168\.\d{1,3}\.\d{1,3}", "RFC1918 192.168.x.x IP in response"),
    (r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}", "RFC1918 172.16-31 IP in response"),
    # Service banners
    (r"SSH-2\.0", "SSH banner detected"),
    (r"MySQL.*Server", "MySQL banner detected"),
    (r"PostgreSQL", "PostgreSQL banner detected"),
    (r"Microsoft-IIS", "IIS internal server"),
    (r"Apache.*internal", "Internal Apache server"),
    # Admin panels
    (r"phpMyAdmin", "phpMyAdmin detected"),
    (r"Jenkins", "Jenkins CI/CD detected"),
    (r"Kibana", "Kibana detected"),
    (r"Grafana", "Grafana detected"),
    (r"Elasticsearch", "Elasticsearch detected"),
    (r"RabbitMQ", "RabbitMQ management UI"),
    (r"Consul", "HashiCorp Consul API"),
    # Generic internal indicators
    (r"internal server error.*?stack", "Stack trace (internal error)"),
    (r"localhost", "Localhost string in response"),
]

MEDIUM_SIGNATURES = [
    (r"connect(ion)?\s*(refused|reset|timed out)", "Connection refused (internal port probe)"),
    (r"ECONNREFUSED", "ECONNREFUSED — port likely closed"),
    (r"No route to host", "Routing error — internal target"),
    (r"Name or service not known", "DNS resolution of internal host"),
    (r"Invalid URL", "URL validation present"),
    (r"invalid.*protocol", "Protocol filtering detected"),
    (r"blocked.*request", "Request blocked by WAF"),
    (r"Blacklisted", "Blacklist filter response"),
    (r"Forbidden.*ip", "IP-based blocking"),
]

# Timing threshold (seconds) — blind SSRF via response time
TIMING_THRESHOLD = 5.0

# Status codes that may indicate SSRF
INTERESTING_STATUS_CODES = {200, 301, 302, 303, 307, 308, 403, 500, 502, 503}


class ResponseAnalyzer:
    """Analyze HTTP responses for SSRF indicators."""

    def __init__(self, logger: Logger):
        self.logger = logger
        # Pre-compile regexes for performance
        self._critical = [
            (re.compile(pattern, re.IGNORECASE), desc)
            for pattern, desc in CRITICAL_SIGNATURES
        ]
        self._high = [
            (re.compile(pattern, re.IGNORECASE), desc)
            for pattern, desc in HIGH_SIGNATURES
        ]
        self._medium = [
            (re.compile(pattern, re.IGNORECASE), desc)
            for pattern, desc in MEDIUM_SIGNATURES
        ]

    def analyze(
        self,
        response: Dict[str, Any],
        payload: str,
        url: str,
    ) -> Dict[str, Any]:
        """
        Analyze a response for SSRF indicators.
        Returns dict with detected, severity, signal, evidence.
        """
        if not response:
            return {"detected": False}

        body = response.get("body", "")
        headers = response.get("headers", {})
        status_code = response.get("status_code", 0)
        elapsed = response.get("elapsed", 0)
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        full_content = body + " " + header_str

        # Check CRITICAL signatures first
        for regex, desc in self._critical:
            match = regex.search(full_content)
            if match:
                evidence = match.group(0)[:200]
                return {
                    "detected": True,
                    "severity": "CRITICAL",
                    "signal": desc,
                    "evidence": evidence,
                }

        # Check HIGH signatures
        for regex, desc in self._high:
            match = regex.search(full_content)
            if match:
                evidence = match.group(0)[:200]
                return {
                    "detected": True,
                    "severity": "HIGH",
                    "signal": desc,
                    "evidence": evidence,
                }

        # Timing-based detection
        if elapsed >= TIMING_THRESHOLD and status_code in INTERESTING_STATUS_CODES:
            return {
                "detected": True,
                "severity": "MEDIUM",
                "signal": f"Timing anomaly ({elapsed:.2f}s) — possible blind SSRF or internal timeout",
                "evidence": f"Response time: {elapsed:.2f}s, Status: {status_code}",
            }

        # MEDIUM signatures
        for regex, desc in self._medium:
            match = regex.search(full_content)
            if match:
                evidence = match.group(0)[:200]
                return {
                    "detected": True,
                    "severity": "MEDIUM",
                    "signal": desc,
                    "evidence": evidence,
                }

        # Unexpected redirect to internal IP
        for redirect in response.get("redirect_history", []):
            for pattern, desc in [
                (r"127\.0\.0\.1", "Redirect to localhost"),
                (r"10\.\d{1,3}", "Redirect to internal 10.x"),
                (r"192\.168", "Redirect to internal 192.168.x"),
                (r"169\.254\.169\.254", "Redirect to metadata IP"),
            ]:
                if re.search(pattern, redirect):
                    return {
                        "detected": True,
                        "severity": "HIGH",
                        "signal": f"{desc} in redirect chain",
                        "evidence": redirect,
                    }

        return {"detected": False}

    def detect_cloud_provider(self, response: Dict[str, Any]) -> Optional[str]:
        """Attempt to identify the cloud provider from a response."""
        body = response.get("body", "")
        if any(kw in body for kw in ["ami-id", "instance-id", "ec2", "AccessKeyId"]):
            return "AWS"
        if any(kw in body for kw in ["computeMetadata", "gce-", "serviceAccounts"]):
            return "GCP"
        if any(kw in body for kw in ["subscriptionId", "resourceGroupName", "vmId"]):
            return "Azure"
        return None

    def detect_internal_service(self, response: Dict[str, Any]) -> Optional[str]:
        """Identify internal services from response content."""
        body = response.get("body", "")
        services = {
            "Redis": ["+OK", "redis_version", "NOAUTH"],
            "Elasticsearch": ["_cat", "_nodes", "cluster_name"],
            "Jenkins": ["Jenkins", "hudson"],
            "MySQL": ["mysql_native_password", "Access denied for user"],
            "PostgreSQL": ["PostgreSQL", "pg_hba"],
            "MongoDB": ["MongoDB", "mongod"],
            "Kibana": ["kbn-name", "Kibana"],
            "Consul": ["consul", "serf"],
        }
        for service, keywords in services.items():
            if any(kw.lower() in body.lower() for kw in keywords):
                return service
        return None
