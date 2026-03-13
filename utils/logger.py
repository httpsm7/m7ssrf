"""
M7 SSRF Logger — Colored terminal output.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import sys
import datetime


class Colors:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Standard colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # 256-color
    ORANGE = "\033[38;5;208m"
    GOLD = "\033[38;5;226m"
    SKY = "\033[38;5;39m"
    PINK = "\033[38;5;213m"
    GRAY = "\033[38;5;245m"


class Logger:
    """
    Colored terminal logger for M7 SSRF.
    Supports verbose, quiet, and no-color modes.
    """

    def __init__(
        self,
        verbose: bool = False,
        quiet: bool = False,
        no_color: bool = False,
    ):
        self.verbose_mode = verbose
        self.quiet_mode = quiet
        self.no_color = no_color

    def _colorize(self, text: str, *color_codes: str) -> str:
        """Apply ANSI color codes to text."""
        if self.no_color:
            return text
        codes = "".join(color_codes)
        return f"{codes}{text}{Colors.RESET}"

    def _timestamp(self) -> str:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        return self._colorize(f"[{now}]", Colors.GRAY)

    def _print(self, message: str):
        print(message, file=sys.stdout, flush=True)

    # ─── Log levels ────────────────────────────────────────────────────────────

    def info(self, message: str):
        """General info message."""
        if self.quiet_mode:
            return
        prefix = self._colorize("[*]", Colors.BRIGHT_BLUE, Colors.BOLD)
        self._print(f"{self._timestamp()} {prefix} {message}")

    def success(self, message: str):
        """Success message."""
        if self.quiet_mode:
            return
        prefix = self._colorize("[+]", Colors.BRIGHT_GREEN, Colors.BOLD)
        self._print(f"{self._timestamp()} {prefix} {message}")

    def warn(self, message: str):
        """Warning message."""
        if self.quiet_mode:
            return
        prefix = self._colorize("[!]", Colors.BRIGHT_YELLOW, Colors.BOLD)
        self._print(f"{self._timestamp()} {prefix} {message}")

    def error(self, message: str):
        """Error message."""
        prefix = self._colorize("[ERROR]", Colors.BRIGHT_RED, Colors.BOLD)
        self._print(f"{self._timestamp()} {prefix} {message}")

    def verbose(self, message: str):
        """Verbose/debug message (only shown with -v)."""
        if not self.verbose_mode:
            return
        prefix = self._colorize("[~]", Colors.GRAY)
        self._print(f"{self._timestamp()} {prefix} {self._colorize(message, Colors.DIM)}")

    def vuln(self, message: str):
        """Vulnerability finding — always shown, high visibility."""
        prefix = self._colorize("[VULN]", Colors.BRIGHT_RED, Colors.BOLD)
        full_msg = f"\n{self._timestamp()} {prefix} {self._colorize(message, Colors.BRIGHT_RED)}\n"
        self._print(full_msg)

    def possible(self, message: str):
        """Possible finding — shown in orange."""
        prefix = self._colorize("[POSSIBLE]", Colors.ORANGE, Colors.BOLD)
        self._print(f"{self._timestamp()} {prefix} {self._colorize(message, Colors.ORANGE)}")

    def banner(self, message: str):
        """Banner/summary message."""
        if self.quiet_mode:
            return
        line = self._colorize("─" * 60, Colors.GRAY)
        self._print(f"\n{line}")
        self._print(self._colorize(message, Colors.GOLD, Colors.BOLD))
        self._print(f"{line}\n")

    def section(self, title: str):
        """Section header."""
        if self.quiet_mode:
            return
        prefix = self._colorize("[>>]", Colors.BRIGHT_CYAN, Colors.BOLD)
        self._print(f"\n{self._timestamp()} {prefix} {self._colorize(title, Colors.BRIGHT_CYAN, Colors.BOLD)}")

    def finding(self, severity: str, message: str):
        """Route finding to appropriate log level."""
        if severity in ("CRITICAL", "HIGH"):
            self.vuln(message)
        elif severity == "MEDIUM":
            self.possible(message)
        else:
            self.info(message)
