"""
M7 SSRF Engine — Core orchestration engine.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import asyncio
from typing import List, Dict, Any, Optional

from m7ssrf.requestor import Requestor
from m7ssrf.analyzer import ResponseAnalyzer
from discovery.parameter_discovery import ParameterDiscovery
from discovery.url_parser import URLParser
from modules.blind_ssrf import BlindSSRF
from modules.ssrf_chain import SSRFChain
from utils.logger import Logger
from utils.output import OutputManager


def _mutate_payloads_stub():
    return []


class SSRFEngine:
    def __init__(self, args, logger: Logger, output: OutputManager):
        self.args = args
        self.logger = logger
        self.output = output

        self.requestor = Requestor(
            proxy=args.proxy,
            timeout=args.timeout,
            retries=args.retries,
            follow_redirects=not getattr(args, 'no_redirects', False),
            headers=self._parse_headers(args.header),
        )

        self.analyzer = ResponseAnalyzer(logger=logger)
        self.param_discovery = ParameterDiscovery(logger=logger)
        self.url_parser = URLParser()

        from m7ssrf.scanner import SSRFScanner
        self.scanner = SSRFScanner(
            requestor=self.requestor,
            analyzer=self.analyzer,
            logger=logger,
            args=args,
        )

        self.blind_ssrf = None
        self.ssrf_chain = None

        if args.blind:
            self.blind_ssrf = BlindSSRF(
                interactsh_url=getattr(args, 'interactsh_url', None),
                dnslog_domain=getattr(args, 'dnslog_domain', None),
                callback_host=getattr(args, 'callback_host', None),
                logger=logger,
            )

        if args.chain:
            self.ssrf_chain = SSRFChain(
                requestor=self.requestor,
                analyzer=self.analyzer,
                logger=logger,
            )

        self.stats = {
            "total": 0, "scanned": 0,
            "vulnerable": 0, "possible": 0, "errors": 0,
        }

    def _parse_headers(self, header_list):
        headers = {}
        if not header_list:
            return headers
        for h in header_list:
            if ":" in h:
                key, _, val = h.partition(":")
                headers[key.strip()] = val.strip()
        return headers

    async def run(self, targets: List[str]):
        self.stats["total"] = len(targets)
        self.logger.info(f"Engine started. Processing {len(targets)} target(s)...")
        semaphore = asyncio.Semaphore(self.args.threads)
        tasks = [self._process_target(url, semaphore) for url in targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.banner(
            f"SCAN COMPLETE | Total: {self.stats['total']} | "
            f"Scanned: {self.stats['scanned']} | "
            f"Vulnerable: {self.stats['vulnerable']} | "
            f"Possible: {self.stats['possible']} | "
            f"Errors: {self.stats['errors']}"
        )

    async def _process_target(self, url: str, semaphore: asyncio.Semaphore):
        async with semaphore:
            try:
                if self.args.delay > 0:
                    await asyncio.sleep(self.args.delay)
                self.logger.verbose(f"Processing: {url}")
                self.stats["scanned"] += 1

                params = self._discover_parameters(url)
                if not params:
                    self.logger.verbose(f"No injectable parameters found in: {url}")
                    return

                self.logger.info(
                    f"Found {len(params)} parameter(s) in {url}: {', '.join(params.keys())}"
                )

                results = await self.scanner.scan(url, params)

                if self.blind_ssrf:
                    blind_results = await self.blind_ssrf.scan(url, params, self.requestor)
                    results.extend(blind_results)

                if self.ssrf_chain:
                    chain_results = await self.ssrf_chain.scan(url, params)
                    results.extend(chain_results)

                for result in results:
                    if not result:
                        continue
                    severity = result.get("severity", "")
                    if severity in ("CRITICAL", "HIGH"):
                        self.stats["vulnerable"] += 1
                        self.logger.vuln(
                            f"[{severity}] {result['url']} | "
                            f"Param: {result.get('param', '?')} | "
                            f"Payload: {result.get('payload', '?')} | "
                            f"Signal: {result.get('signal', 'N/A')}"
                        )
                        self.output.add_vulnerable(result)
                    elif severity in ("MEDIUM", "LOW"):
                        self.stats["possible"] += 1
                        self.logger.possible(
                            f"[{severity}] {result['url']} | "
                            f"Param: {result.get('param', '?')} | "
                            f"Signal: {result.get('signal', 'N/A')}"
                        )
                        self.output.add_possible(result)
                    self.output.add_log(result)

            except asyncio.TimeoutError:
                self.stats["errors"] += 1
                self.logger.verbose(f"Timeout: {url}")
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.verbose(f"Error processing {url}: {e}")

    def _discover_parameters(self, url: str) -> Dict[str, str]:
        if self.args.params:
            return {p.strip(): "" for p in self.args.params.split(",") if p.strip()}
        return self.param_discovery.discover(url)
