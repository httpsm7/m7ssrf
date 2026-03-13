"""
M7 SSRF Output Manager — Results storage and formatting.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import os
import json
import datetime
from typing import List, Dict, Any

from utils.logger import Logger


class OutputManager:
    """
    Manages scan results output:
    - vulnerable.txt
    - possible.txt
    - logs.txt
    - results.json
    """

    def __init__(
        self,
        output_dir: str = "results",
        json_mode: bool = False,
        logger: Logger = None,
    ):
        self.output_dir = output_dir
        self.json_mode = json_mode
        self.logger = logger
        self._vulnerable: List[Dict[str, Any]] = []
        self._possible: List[Dict[str, Any]] = []
        self._all_logs: List[Dict[str, Any]] = []

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def add_vulnerable(self, result: Dict[str, Any]):
        """Add a confirmed vulnerability finding."""
        result["_timestamp"] = datetime.datetime.now().isoformat()
        self._vulnerable.append(result)

    def add_possible(self, result: Dict[str, Any]):
        """Add a possible vulnerability finding."""
        result["_timestamp"] = datetime.datetime.now().isoformat()
        self._possible.append(result)

    def add_log(self, result: Dict[str, Any]):
        """Add a general log entry."""
        self._all_logs.append(result)

    def finalize(self):
        """Write all results to disk."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Vulnerable findings
        vuln_path = os.path.join(self.output_dir, "vulnerable.txt")
        with open(vuln_path, "w") as f:
            f.write(f"# M7 SSRF — Vulnerable Findings\n")
            f.write(f"# Scan time: {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Made by Milkyway Intelligence | Author: Sharlix Martin\n\n")
            for r in self._vulnerable:
                f.write(self._format_finding(r))
                f.write("\n")
        if self.logger:
            self.logger.info(f"Vulnerable findings: {vuln_path} ({len(self._vulnerable)} entries)")

        # Possible findings
        possible_path = os.path.join(self.output_dir, "possible.txt")
        with open(possible_path, "w") as f:
            f.write(f"# M7 SSRF — Possible Findings\n")
            f.write(f"# Scan time: {datetime.datetime.now().isoformat()}\n\n")
            for r in self._possible:
                f.write(self._format_finding(r))
                f.write("\n")
        if self.logger:
            self.logger.info(f"Possible findings: {possible_path} ({len(self._possible)} entries)")

        # All logs
        logs_path = os.path.join(self.output_dir, "logs.txt")
        with open(logs_path, "w") as f:
            f.write(f"# M7 SSRF — Full Scan Log\n")
            f.write(f"# Scan time: {datetime.datetime.now().isoformat()}\n\n")
            for r in self._all_logs:
                f.write(self._format_log(r))
                f.write("\n")

        # JSON output
        if self.json_mode:
            json_path = os.path.join(self.output_dir, f"results_{timestamp}.json")
            report = {
                "meta": {
                    "tool": "M7 SSRF",
                    "version": "1.0.0",
                    "author": "Sharlix Martin",
                    "brand": "Milkyway Intelligence",
                    "scan_time": datetime.datetime.now().isoformat(),
                },
                "summary": {
                    "vulnerable": len(self._vulnerable),
                    "possible": len(self._possible),
                    "total_findings": len(self._all_logs),
                },
                "vulnerable": self._vulnerable,
                "possible": self._possible,
                "logs": self._all_logs,
            }
            with open(json_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            if self.logger:
                self.logger.info(f"JSON report: {json_path}")

    def _format_finding(self, result: Dict[str, Any]) -> str:
        """Format a finding for text output."""
        lines = [
            f"[{result.get('severity', 'UNKNOWN')}] {result.get('url', '')}",
            f"  Parameter : {result.get('param', 'N/A')}",
            f"  Payload   : {result.get('payload', 'N/A')}",
            f"  Signal    : {result.get('signal', 'N/A')}",
            f"  Type      : {result.get('type', 'N/A')}",
            f"  Evidence  : {result.get('evidence', 'N/A')}",
            f"  Injected  : {result.get('injected_url', 'N/A')}",
            f"  Timestamp : {result.get('_timestamp', 'N/A')}",
            "-" * 70,
        ]
        return "\n".join(lines)

    def _format_log(self, result: Dict[str, Any]) -> str:
        """Format a log entry for text output."""
        return (
            f"[{result.get('severity', '?')}] "
            f"{result.get('url', '')} | "
            f"param={result.get('param', '?')} | "
            f"signal={result.get('signal', '?')}"
        )

    def get_stats(self) -> Dict[str, int]:
        """Return summary statistics."""
        return {
            "vulnerable": len(self._vulnerable),
            "possible": len(self._possible),
            "total": len(self._all_logs),
        }
