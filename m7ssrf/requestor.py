"""
M7 SSRF Requestor — Async HTTP request engine.
Primary: httpx (async)  |  Fallback: urllib (sync wrapped in executor)
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
import time
import ssl
from typing import Dict, Any, Optional

# Try to import httpx; fall back to urllib
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    import urllib.request
    import urllib.error


class Requestor:
    """
    Async HTTP request engine.
    Uses httpx when available, falls back to urllib wrapped in asyncio executor.
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 10,
        retries: int = 2,
        follow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.follow_redirects = follow_redirects
        self.headers = headers or {}
        self._client = None
        self._client_lock = asyncio.Lock()

        self._base_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        self._base_headers.update(self.headers)

    async def _get_client(self):
        """Lazy-initialize async httpx client."""
        if not _HTTPX_AVAILABLE:
            return None
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    proxy_conf = {}
                    if self.proxy:
                        proxy_conf = {"proxy": self.proxy}
                    self._client = httpx.AsyncClient(
                        headers=self._base_headers,
                        timeout=httpx.Timeout(
                            connect=self.timeout,
                            read=self.timeout,
                            write=self.timeout,
                            pool=self.timeout,
                        ),
                        follow_redirects=self.follow_redirects,
                        verify=False,
                        **proxy_conf,
                    )
        return self._client

    async def get(
        self,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        return await self._request("GET", url, extra_headers=extra_headers)

    async def post(
        self,
        url: str,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        return await self._request(
            "POST", url, data=data, json_data=json_data,
            extra_headers=extra_headers,
        )

    async def _request(
        self,
        method: str,
        url: str,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Core request dispatcher with retry logic."""
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                if _HTTPX_AVAILABLE:
                    result = await self._request_httpx(
                        method, url, data, json_data, extra_headers
                    )
                else:
                    result = await self._request_urllib(
                        method, url, data, extra_headers
                    )
                if result is not None:
                    return result
            except Exception as e:
                last_error = e
                if attempt < self.retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
        return None

    async def _request_httpx(
        self, method, url, data, json_data, extra_headers
    ) -> Optional[Dict[str, Any]]:
        client = await self._get_client()
        req_kwargs = {}
        if extra_headers:
            req_kwargs["headers"] = extra_headers
        if data:
            req_kwargs["content"] = data
        if json_data:
            req_kwargs["json"] = json_data

        start = time.monotonic()
        response = await client.request(method, url, **req_kwargs)
        elapsed = time.monotonic() - start

        try:
            body = response.content[:51200].decode("utf-8", errors="replace")
        except Exception:
            body = ""

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "elapsed": elapsed,
            "url": str(response.url),
            "redirect_history": [str(r.url) for r in response.history],
        }

    async def _request_urllib(
        self, method, url, data, extra_headers
    ) -> Optional[Dict[str, Any]]:
        """Fallback sync urllib wrapped in asyncio executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._sync_urllib_request,
            method, url, data, extra_headers,
        )

    def _sync_urllib_request(self, method, url, data, extra_headers):
        """Synchronous urllib request (run in executor)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        all_headers = dict(self._base_headers)
        if extra_headers:
            all_headers.update(extra_headers)

        req_data = data.encode() if data else None
        req = urllib.request.Request(url, data=req_data, headers=all_headers, method=method)

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                elapsed = time.monotonic() - start
                body = resp.read(51200).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return {
                    "status_code": resp.status,
                    "headers": headers,
                    "body": body,
                    "elapsed": elapsed,
                    "url": resp.url if hasattr(resp, "url") else url,
                    "redirect_history": [],
                }
        except urllib.error.HTTPError as e:
            elapsed = time.monotonic() - start
            try:
                body = e.read(51200).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return {
                "status_code": e.code,
                "headers": dict(e.headers) if hasattr(e, "headers") else {},
                "body": body,
                "elapsed": elapsed,
                "url": url,
                "redirect_history": [],
            }
        except Exception:
            return None

    async def close(self):
        if self._client and _HTTPX_AVAILABLE:
            await self._client.aclose()
            self._client = None
