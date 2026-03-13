"""
M7 SSRF DNSlog Integration — DNS-based OOB callback via dnslog.cn.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import uuid
from typing import Optional, List, Dict, Any

from utils.logger import Logger


class DNSlogClient:
    """
    DNSlog.cn client for DNS-based blind SSRF detection.
    
    Flow:
    1. Get a unique subdomain from dnslog.cn
    2. Use it in SSRF payloads
    3. Poll for DNS resolutions
    """

    DNSLOG_API = "http://www.dnslog.cn/api.php"

    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger
        self._domain: Optional[str] = None

    async def get_domain(self) -> Optional[str]:
        """Get a unique subdomain from dnslog.cn."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    self.DNSLOG_API,
                    params={"action": "getdomain"},
                )
                if response.status_code == 200:
                    domain = response.text.strip()
                    if domain and "." in domain:
                        self._domain = domain
                        if self.logger:
                            self.logger.success(
                                f"[dnslog] Got domain: {domain}"
                            )
                        return domain
        except Exception as e:
            if self.logger:
                self.logger.verbose(f"[dnslog] Failed to get domain: {e}")
        return None

    async def get_records(self) -> List[Dict[str, Any]]:
        """Poll dnslog.cn for DNS resolution records."""
        if not self._domain:
            return []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    self.DNSLOG_API,
                    params={"action": "getrecords"},
                )
                if response.status_code == 200:
                    records = response.json()
                    return records if isinstance(records, list) else []
        except Exception as e:
            if self.logger:
                self.logger.verbose(f"[dnslog] Poll error: {e}")

        return []

    def build_payload(self, token: str) -> Optional[str]:
        """Build a DNS payload with the token as subdomain."""
        if not self._domain:
            return None
        return f"http://{token}.{self._domain}/"

    def generate_token(self) -> str:
        """Generate a unique token for subdomain injection."""
        return uuid.uuid4().hex[:8]

    @property
    def domain(self) -> Optional[str]:
        return self._domain
