#!/usr/bin/env python3
"""
╔╦╗ ███████╗ ███████╗ ██████╗  ███████╗
║║║ ╚════██║ ██╔════╝ ██╔══██╗ ██╔════╝
║║║     ██╔╝ ███████╗ ██████╔╝ █████╗
╚═╝    ██╔╝  ╚════██║ ██╔══██╗ ██╔══╝
       ██║   ███████║ ██║  ██║ ██║
       ╚═╝   ╚══════╝ ╚═╝  ╚═╝ ╚═╝

M7 SSRF — Advanced SSRF Research Tool
Made by Milkyway Intelligence
Author: Sharlix Martin
"""

import argparse
import sys
import os
import asyncio
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from m7ssrf.engine import SSRFEngine
from utils.logger import Logger
from utils.output import OutputManager
from utils.dependency_checker import check_dependencies

BANNER = """
\033[38;5;39m
  ███╗   ███╗ ███████╗     ███████╗███████╗██████╗ ███████╗
  ████╗ ████║ ╚════██║     ██╔════╝██╔════╝██╔══██╗██╔════╝
  ██╔████╔██║     ██╔╝     ███████╗███████╗██████╔╝█████╗  
  ██║╚██╔╝██║    ██╔╝      ╚════██║╚════██║██╔══██╗██╔══╝  
  ██║ ╚═╝ ██║   ██║███████╗███████║███████║██║  ██║██║     
  ╚═╝     ╚═╝   ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
\033[0m
\033[38;5;208m  ╔══════════════════════════════════════════════════════╗
  ║   Advanced SSRF Research & Detection Framework       ║
  ║   Made by \033[38;5;226mMilkyway Intelligence\033[38;5;208m  |  Author: \033[38;5;226mSharlix Martin\033[38;5;208m ║
  ╚══════════════════════════════════════════════════════╝\033[0m
\033[38;5;245m  [~] Version: 1.0.0  |  Target: Bug Bounty & Security Research\033[0m
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="m7ssrf",
        description="M7 SSRF — Advanced SSRF Research Tool by Milkyway Intelligence",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  m7ssrf -u https://target.com
  m7ssrf -u https://target.com --blind --interactsh-url https://your.interact.sh
  m7ssrf -f targets.txt --threads 20 --output results/
  m7ssrf -u https://target.com/api?url=test --params url,path,file
  m7ssrf -u https://target.com --safe --json
  m7ssrf -u https://target.com --mutate --cloud-detect
        """
    )

    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "--url", help="Single target URL")
    target_group.add_argument("-f", "--file", help="File containing target URLs (one per line)")
    target_group.add_argument("-p", "--params", help="Comma-separated parameter names to test (e.g. url,path,file)")

    # Scan modes
    mode_group = parser.add_argument_group("Scan Modes")
    mode_group.add_argument("--blind", action="store_true", help="Enable blind SSRF detection (requires OOB callback)")
    mode_group.add_argument("--chain", action="store_true", help="Enable SSRF chaining engine (internal network)")
    mode_group.add_argument("--safe", action="store_true", help="Safe mode — only localhost/metadata checks")
    mode_group.add_argument("--cloud-detect", action="store_true", help="Detect cloud metadata endpoints (AWS/GCP/Azure)")
    mode_group.add_argument("--mutate", action="store_true", help="Enable payload mutation engine")
    mode_group.add_argument("--full", action="store_true", help="Run all detection modules")

    # OOB / Callback
    oob_group = parser.add_argument_group("OOB / Blind SSRF Options")
    oob_group.add_argument("--interactsh-url", metavar="URL", help="Interactsh/OAST callback URL for blind SSRF")
    oob_group.add_argument("--dnslog-domain", metavar="DOMAIN", help="DNSlog domain for OOB detection")
    oob_group.add_argument("--callback-host", metavar="HOST", help="Custom callback host for blind SSRF")

    # Performance
    perf_group = parser.add_argument_group("Performance Options")
    perf_group.add_argument("--threads", type=int, default=10, metavar="N", help="Number of concurrent threads (default: 10)")
    perf_group.add_argument("--timeout", type=int, default=10, metavar="SEC", help="Request timeout in seconds (default: 10)")
    perf_group.add_argument("--delay", type=float, default=0, metavar="SEC", help="Delay between requests (default: 0)")
    perf_group.add_argument("--retries", type=int, default=2, metavar="N", help="Retry failed requests N times (default: 2)")

    # Request options
    req_group = parser.add_argument_group("Request Options")
    req_group.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    req_group.add_argument("-H", "--header", action="append", metavar="HEADER", help="Custom header (repeatable, e.g. -H 'X-Token: abc')")
    req_group.add_argument("--method", default="GET", choices=["GET", "POST", "PUT"], help="HTTP method (default: GET)")
    req_group.add_argument("--data", metavar="DATA", help="POST body data")
    req_group.add_argument("--follow-redirects", action="store_true", default=True, help="Follow redirects (default: True)")
    req_group.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")

    # Output options
    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("-o", "--output", metavar="DIR", default="results", help="Output directory (default: results/)")
    out_group.add_argument("--json", action="store_true", help="Output results in JSON format")
    out_group.add_argument("-q", "--quiet", action="store_true", help="Quiet mode — only show findings")
    out_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out_group.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser.parse_args()


def validate_args(args, logger):
    """Validate argument combinations."""
    if not args.url and not args.file:
        logger.error("No target specified. Use -u <url> or -f <file>")
        sys.exit(1)

    if args.blind and not any([args.interactsh_url, args.dnslog_domain, args.callback_host]):
        logger.warn("Blind SSRF mode enabled but no callback URL set. Using generic payloads only.")
        logger.warn("For full blind detection, use: --interactsh-url or --dnslog-domain")

    if args.threads > 100:
        logger.warn(f"High thread count ({args.threads}) may trigger rate limiting. Consider --delay 0.5")

    if args.full:
        args.blind = True
        args.chain = True
        args.cloud_detect = True
        args.mutate = True

    return args


def main():
    args = parse_args()

    # Init logger
    logger = Logger(
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color
    )

    # Print banner
    if not args.quiet:
        print(BANNER)

    # Check dependencies
    logger.info("Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    logger.success("All dependencies satisfied.")

    # Validate args
    args = validate_args(args, logger)

    # Build target list
    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.file:
        try:
            with open(args.file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
            logger.info(f"Loaded {len(targets)} targets from {args.file}")
        except FileNotFoundError:
            logger.error(f"Target file not found: {args.file}")
            sys.exit(1)

    if not targets:
        logger.error("No valid targets found.")
        sys.exit(1)

    # Init output manager
    output = OutputManager(
        output_dir=args.output,
        json_mode=args.json,
        logger=logger
    )

    # Init and run engine
    engine = SSRFEngine(args=args, logger=logger, output=output)

    logger.info(f"Starting M7 SSRF scan on {len(targets)} target(s)")
    logger.info(f"Threads: {args.threads} | Timeout: {args.timeout}s | Mode: {'FULL' if args.full else 'STANDARD'}")

    try:
        asyncio.run(engine.run(targets))
    except KeyboardInterrupt:
        logger.warn("\n[!] Scan interrupted by user.")
        output.finalize()
        sys.exit(0)

    output.finalize()
    logger.success(f"Scan complete. Results saved to: {args.output}/")


if __name__ == "__main__":
    main()
