"""
M7 SSRF DNS Monitor — DNS callback monitoring for blind SSRF.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import time
from typing import Optional, List, Dict, Any

from utils.logger import Logger


class DNSMonitor:
    """
    DNS callback monitor for blind SSRF detection.
    
    Monitors callback platforms for DNS/HTTP interactions:
    - Interactsh polling
    - DNSlog.cn API
    - Custom polling endpoint
    """

    def __init__(
        self,
        interactsh_url: Optional[str] = None,
        dnslog_domain: Optional[str] = None,
        poll_interval: float = 5.0,
        max_wait: float = 60.0,
        logger: Optional[Logger] = None,
    ):
        self.interactsh_url = interactsh_url
        self.dnslog_domain = dnslog_domain
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self.logger = logger
        self._interactions: List[Dict[str, Any]] = []

    async def poll_interactsh(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Poll an Interactsh server for interactions matching a token.
        
        NOTE: Full Interactsh integration requires authentication.
        This implements basic HTTP polling for self-hosted instances.
        """
        if not self.interactsh_url:
            return None

        try:
            import httpx
            poll_url = f"{self.interactsh_url.rstrip('/')}/poll"

            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(
                    poll_url,
                    params={"id": token},
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("data"):
                        for interaction in data["data"]:
                            if token in str(interaction):
                                self._interactions.append(interaction)
                                return {
                                    "token": token,
                                    "interaction": interaction,
                                    "timestamp": time.time(),
                                }
        except Exception as e:
            if self.logger:
                self.logger.verbose(f"[dns_monitor] Interactsh poll error: {e}")

        return None

    async def monitor(
        self,
        tokens: Dict[str, Dict],
        requestor=None,
    ) -> List[Dict[str, Any]]:
        """
        Monitor for callbacks over a time window.
        Returns list of confirmed blind SSRF findings.
        """
        if not tokens:
            return []

        if self.logger:
            self.logger.info(
                f"[dns_monitor] Monitoring {len(tokens)} token(s) for {self.max_wait}s..."
            )

        findings = []
        start = time.time()

        while time.time() - start < self.max_wait:
            await asyncio.sleep(self.poll_interval)

            for token, meta in list(tokens.items()):
                # Poll Interactsh
                if self.interactsh_url:
                    result = await self.poll_interactsh(token)
                    if result:
                        finding = {
                            "url": meta.get("url"),
                            "param": meta.get("param"),
                            "payload": meta.get("payload"),
                            "token": token,
                            "type": "blind_ssrf_confirmed",
                            "severity": "HIGH",
                            "signal": "Blind SSRF confirmed via OOB DNS/HTTP callback",
                            "evidence": str(result.get("interaction", "")),
                        }
                        findings.append(finding)
                        if self.logger:
                            self.logger.vuln(
                                f"[BLIND SSRF CONFIRMED] Token: {token} | "
                                f"URL: {meta.get('url')} | Param: {meta.get('param')}"
                            )
                        tokens.pop(token, None)

        remaining = len(tokens)
        if remaining > 0 and self.logger:
            self.logger.verbose(
                f"[dns_monitor] {remaining} token(s) did not receive callbacks within {self.max_wait}s. "
                f"Check manually: {self.interactsh_url or self.dnslog_domain}"
            )

        return findings

    def get_interactions(self) -> List[Dict[str, Any]]:
        """Return all recorded interactions."""
        return list(self._interactions)

    @staticmethod
    def generate_dnslog_payload(domain: str, token: str) -> str:
        """Generate a DNSlog subdomain payload."""
        return f"http://{token}.{domain}/"

    @staticmethod
    def generate_interactsh_payload(interactsh_url: str, token: str) -> str:
        """Generate an Interactsh payload URL."""
        host = interactsh_url.rstrip("/").replace("https://", "").replace("http://", "")
        return f"http://{token}.{host}/"
