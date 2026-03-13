"""
M7 SSRF Interactsh Integration — OOB callback via Interactsh.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import time
import uuid
from typing import Optional, List, Dict, Any

from utils.logger import Logger


class InteractshClient:
    """
    Lightweight Interactsh client for blind SSRF detection.
    
    Compatible with:
    - interact.sh (public)
    - Self-hosted interactsh-server
    - OAST services
    """

    def __init__(
        self,
        server_url: str = "https://interact.sh",
        logger: Optional[Logger] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.logger = logger
        self._correlation_id: Optional[str] = None
        self._secret: Optional[str] = None
        self._interactions: List[Dict[str, Any]] = []

    async def register(self) -> Optional[str]:
        """
        Register with Interactsh server to get a correlation ID.
        Returns the OOB domain to use in payloads.
        """
        try:
            import httpx
            reg_url = f"{self.server_url}/register"
            payload = {
                "public-key": self._generate_public_key(),
                "secret-key": uuid.uuid4().hex,
                "correlation-id": uuid.uuid4().hex[:20],
            }
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                response = await client.post(reg_url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    self._correlation_id = data.get("correlation-id")
                    domain = data.get("domain")
                    if self.logger:
                        self.logger.success(
                            f"[interactsh] Registered. OOB domain: {domain}"
                        )
                    return domain
        except Exception as e:
            if self.logger:
                self.logger.verbose(f"[interactsh] Registration failed: {e}")
        return None

    async def poll(self) -> List[Dict[str, Any]]:
        """Poll for new interactions."""
        if not self._correlation_id:
            return []

        try:
            import httpx
            poll_url = f"{self.server_url}/poll"
            params = {"id": self._correlation_id, "secret": self._secret}

            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(poll_url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    interactions = data.get("data", [])
                    self._interactions.extend(interactions)
                    return interactions
        except Exception as e:
            if self.logger:
                self.logger.verbose(f"[interactsh] Poll error: {e}")

        return []

    def build_payload(self, token: str, domain: str) -> str:
        """Build an OOB payload URL with embedded token."""
        return f"http://{token}.{domain}/"

    def _generate_public_key(self) -> str:
        """Generate a dummy public key for registration (simplified)."""
        return uuid.uuid4().hex + uuid.uuid4().hex

    def get_all_interactions(self) -> List[Dict[str, Any]]:
        """Return all collected interactions."""
        return list(self._interactions)
