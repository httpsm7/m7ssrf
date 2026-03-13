"""
M7 SSRF Dependency Checker — Verifies required dependencies.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

import sys
import subprocess
import importlib
from typing import List, Tuple


# httpx is strongly recommended but falls back to urllib if missing
RECOMMENDED_PYTHON_PACKAGES = [
    ("httpx", "httpx", "pip install httpx  [async HTTP, strongly recommended]"),
]

OPTIONAL_PYTHON_PACKAGES = [
    ("dnspython", "dns.resolver", "pip install dnspython"),
    ("rich", "rich", "pip install rich"),
]


def _check_python_version() -> bool:
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 7):
        print(f"\033[91m[ERROR] Python 3.7+ required. Found: {major}.{minor}\033[0m")
        return False
    return True


def _check_python_package(display_name, import_name, install_hint):
    try:
        importlib.import_module(import_name)
        return True, ""
    except ImportError:
        return False, f"{display_name} — {install_hint}"


def check_dependencies() -> bool:
    """
    Verify dependencies.
    Returns True always (fallbacks exist); warns if recommended packages missing.
    """
    if not _check_python_version():
        return False

    # Recommended (warn, don't fail)
    for display, import_name, hint in RECOMMENDED_PYTHON_PACKAGES:
        ok, msg = _check_python_package(display, import_name, hint)
        if not ok:
            print(f"\033[93m[~] Recommended: {msg}\033[0m")
            print(f"\033[93m[~] Falling back to urllib (slower, no async). For best results: pip install httpx\033[0m")

    # Optional (info only)
    for display, import_name, hint in OPTIONAL_PYTHON_PACKAGES:
        ok, _ = _check_python_package(display, import_name, hint)
        # Silently skip optional

    return True  # Always pass — urllib fallback handles missing httpx


def auto_install_requirements() -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"],
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"\033[91m[!] Auto-install failed: {e}\033[0m")
        return False
