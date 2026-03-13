"""
M7 SSRF Blind Detection — OOB callback-based blind SSRF detection.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import uuid
import time
from typing import Dict, List, Optional, Any

from utils.logger import Logger


class BlindSSRF:
    """
    Blind SSRF detection via OOB (Out-of-Band) callbacks.

    Supports:
    - Interactsh / OAST platforms
    - DNSlog domains
    - Custom callback hosts
    """

    def __init__(
        self,
        interactsh_url: Optional[str] = None,
        dnslog_domain: Optional[str] = None,
        callback_host: Optional[str] = None,
        logger: Optional[Logger] = None,
    ):
        self.interactsh_url = interactsh_url
        self.dnslog_domain = dnslog_domain
        self.callback_host = callback_host
        self.logger = logger

        # Token registry: token → {url, param, payload, time}
        self._tokens: Dict[str, Dict] = {}

        # Determine active OOB host
        self.oob_host = self._resolve_oob_host()

    def _resolve_oob_host(self) -> Optional[str]:
        """Determine the active OOB host to use."""
        if self.interactsh_url:
            return self.interactsh_url.rstrip("/")
        if self.callback_host:
            return self.callback_host.rstrip("/")
        if self.dnslog_domain:
            return self.dnslog_domain
        return None

    def _generate_token(self) -> str:
        """Generate a unique token for tracking callbacks."""
        return uuid.uuid4().hex[:12]

    def _build_blind_payload(self, token: str) -> Optional[str]:
        """Build a blind SSRF payload with the unique token embedded."""
        if not self.oob_host:
            return None

        if self.dnslog_domain:
            # DNS-based: token becomes a subdomain
            return f"http://{token}.{self.oob_host}/"

        if self.interactsh_url or self.callback_host:
            # HTTP-based: token in path
            return f"{self.oob_host}/{token}"

        return None

    async def scan(
        self,
        url: str,
        params: Dict[str, str],
        requestor,
    ) -> List[Dict[str, Any]]:
        """
        Execute blind SSRF scans using OOB payloads.
        Returns list of findings (may be empty if callbacks not yet received).
        """
        if not self.oob_host:
            self.logger.verbose(
                "[blind] No OOB host configured — using generic blind payloads only"
            )
            return await self._scan_generic(url, params, requestor)

        results = []
        tasks = []

        for param in params:
            token = self._generate_token()
            payload = self._build_blind_payload(token)
            if not payload:
                continue

            self._tokens[token] = {
                "url": url,
                "param": param,
                "payload": payload,
                "timestamp": time.time(),
            }

            tasks.append(
                self._fire_blind_request(url, param, payload, token, requestor)
            )

        fired = await asyncio.gather(*tasks, return_exceptions=True)

        for result in fired:
            if isinstance(result, dict) and result:
                results.append(result)

        if self._tokens:
            oob_count = len([t for t in self._tokens.values()
                             if t["url"] == url])
            self.logger.verbose(
                f"[blind] Fired {oob_count} OOB probe(s) for {url}. "
                f"Monitor your callback: {self.oob_host}"
            )

        return results

    async def _fire_blind_request(
        self,
        url: str,
        param: str,
        payload: str,
        token: str,
        requestor,
    ) -> Dict[str, Any]:
        """Fire a single blind SSRF request and check for immediate callback signs."""
        try:
            from discovery.url_parser import URLParser
            injected_url = URLParser.replace_param(url, param, payload)
            response = await requestor.get(injected_url)

            if response:
                # Some blind SSRF shows immediate timing signals
                elapsed = response.get("elapsed", 0)
                status = response.get("status_code", 0)

                if elapsed > 3.0:
                    return {
                        "url": url,
                        "injected_url": injected_url,
                        "param": param,
                        "payload": payload,
                        "token": token,
                        "type": "blind_ssrf_timing",
                        "severity": "MEDIUM",
                        "signal": f"Blind SSRF — timing anomaly ({elapsed:.2f}s)",
                        "evidence": f"OOB payload sent. Token: {token}. Monitor: {self.oob_host}",
                    }

        except Exception as e:
            self.logger.verbose(f"[blind] Error: {e}")

        return {}

    async def _scan_generic(
        self,
        url: str,
        params: Dict[str, str],
        requestor,
    ) -> List[Dict[str, Any]]:
        """
        Generic blind SSRF probes without OOB host.
        Uses well-known public OOB domains as reference.
        """
        # Generic payloads pointing to safe public OOB services
        generic_payloads = [
            "http://burpcollaborator.net/",
            "http://canarytokens.org/",
            "http://requestbin.net/",
            "http://webhook.site/",
        ]

        results = []
        for param in params:
            for payload in generic_payloads[:2]:  # Limit to avoid noise
                try:
                    from discovery.url_parser import URLParser
                    injected_url = URLParser.replace_param(url, param, payload)
                    response = await requestor.get(injected_url)

                    if response and response.get("elapsed", 0) > 4.0:
                        results.append({
                            "url": url,
                            "injected_url": injected_url,
                            "param": param,
                            "payload": payload,
                            "type": "blind_ssrf_generic",
                            "severity": "LOW",
                            "signal": "Possible blind SSRF — delayed response to external callback",
                            "evidence": f"Response time: {response.get('elapsed', 0):.2f}s",
                        })

                except Exception:
                    pass

        return results

    def get_pending_tokens(self) -> Dict[str, Dict]:
        """Return all pending OOB tokens that haven't received callbacks."""
        return dict(self._tokens)

    def mark_callback_received(self, token: str) -> Optional[Dict]:
        """Mark a token as received and return its metadata."""
        return self._tokens.pop(token, None)
