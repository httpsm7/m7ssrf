#!/usr/bin/env bash
# ============================================================
#  M7 SSRF — Single Command Installer
#  Made by Milkyway Intelligence | Author: Sharlix Martin
# ============================================================

set -e

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN="/usr/local/bin/m7ssrf"

# ── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ███╗   ███╗ ███████╗     ███████╗███████╗██████╗ ███████╗"
  echo "  ████╗ ████║ ╚════██║     ██╔════╝██╔════╝██╔══██╗██╔════╝"
  echo "  ██╔████╔██║     ██╔╝     ███████╗███████╗██████╔╝█████╗  "
  echo "  ██║╚██╔╝██║    ██╔╝      ╚════██║╚════██║██╔══██╗██╔══╝  "
  echo "  ██║ ╚═╝ ██║   ██║███████╗███████║███████║██║  ██║██║     "
  echo "  ╚═╝     ╚═╝   ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝   "
  echo -e "${RESET}"
  echo -e "${YELLOW}  Made by Milkyway Intelligence  |  Author: Sharlix Martin${RESET}"
  echo -e "${CYAN}  ─────────────────────────────────────────────────────${RESET}"
  echo ""
}

ok()   { echo -e "${GREEN}  [✓] $1${RESET}"; }
info() { echo -e "${CYAN}  [*] $1${RESET}"; }
warn() { echo -e "${YELLOW}  [!] $1${RESET}"; }
fail() { echo -e "${RED}  [✗] $1${RESET}"; }
die()  { fail "$1"; exit 1; }

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

print_banner

# ── Step 1: Check OS ──────────────────────────────────────
info "Detecting operating system..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  OS="linux"
  ok "Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
  ok "macOS detected"
else
  warn "Unsupported OS: $OSTYPE — proceeding anyway"
  OS="unknown"
fi

# ── Step 2: Check Python ──────────────────────────────────
info "Checking Python 3..."
if command_exists python3; then
  PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
  PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
  if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 7 ]]; }; then
    die "Python 3.7+ required. Found: $PY_VER"
  fi
  ok "Python $PY_VER"
else
  warn "Python3 not found. Attempting install..."
  if [[ "$OS" == "linux" ]]; then
    if command_exists apt; then
      sudo apt-get install python3 python3-pip -y || die "Failed to install Python3"
    elif command_exists yum; then
      sudo yum install python3 -y || die "Failed to install Python3"
    elif command_exists pacman; then
      sudo pacman -S python python-pip --noconfirm || die "Failed to install Python3"
    else
      die "Cannot auto-install Python3. Please install manually."
    fi
  elif [[ "$OS" == "macos" ]]; then
    if command_exists brew; then
      brew install python3 || die "Failed to install Python3"
    else
      die "Please install Python3 from https://python.org or install Homebrew first."
    fi
  else
    die "Please install Python 3.7+ manually."
  fi
  ok "Python3 installed"
fi

# ── Step 3: Check pip ─────────────────────────────────────
info "Checking pip..."
if command_exists pip3; then
  ok "pip3 found"
  PIP="pip3"
elif python3 -m pip --version >/dev/null 2>&1; then
  ok "pip (via python3 -m pip) found"
  PIP="python3 -m pip"
else
  warn "pip not found. Attempting install..."
  if [[ "$OS" == "linux" ]]; then
    sudo apt-get install python3-pip -y 2>/dev/null || \
    python3 -c "import urllib.request; exec(urllib.request.urlopen('https://bootstrap.pypa.io/get-pip.py').read())"
    PIP="pip3"
  else
    die "Please install pip manually: https://pip.pypa.io/en/stable/installation/"
  fi
  ok "pip installed"
fi

# ── Step 4: Check git ─────────────────────────────────────
info "Checking git..."
if command_exists git; then
  ok "git found"
else
  warn "git not found. Installing..."
  if [[ "$OS" == "linux" ]]; then
    sudo apt-get install git -y 2>/dev/null || \
    sudo yum install git -y 2>/dev/null || \
    warn "Could not install git automatically — install manually if needed"
  fi
fi

# ── Step 5: Check curl ────────────────────────────────────
info "Checking curl..."
if command_exists curl; then
  ok "curl found"
else
  warn "curl not found — some features may be limited"
fi

# ── Step 6: Install Python dependencies ───────────────────
info "Installing Python dependencies..."
cd "$TOOL_DIR"
if [[ -f requirements.txt ]]; then
  $PIP install -r requirements.txt -q --break-system-packages 2>/dev/null || \
  $PIP install -r requirements.txt -q
  ok "Dependencies installed"
else
  die "requirements.txt not found in $TOOL_DIR"
fi

# ── Step 7: Install tool (pip editable) ───────────────────
info "Installing m7ssrf..."
$PIP install -e . -q --break-system-packages 2>/dev/null || \
$PIP install -e . -q

# ── Step 8: Create wrapper script ─────────────────────────
info "Creating system command: m7ssrf..."
PY_EXEC=$(which python3)
WRAPPER_CONTENT="#!/usr/bin/env bash
# M7 SSRF wrapper — auto-generated by install.sh
export PYTHONPATH=\"${TOOL_DIR}:\$PYTHONPATH\"
exec \"${PY_EXEC}\" \"${TOOL_DIR}/m7ssrf/cli.py\" \"\$@\"
"

if [[ -w "/usr/local/bin" ]]; then
  echo "$WRAPPER_CONTENT" > "$INSTALL_BIN"
  chmod +x "$INSTALL_BIN"
  ok "Installed to $INSTALL_BIN"
else
  # Try with sudo
  echo "$WRAPPER_CONTENT" | sudo tee "$INSTALL_BIN" > /dev/null
  sudo chmod +x "$INSTALL_BIN"
  ok "Installed to $INSTALL_BIN (via sudo)"
fi

# ── Step 9: Create results directory ──────────────────────
mkdir -p "$TOOL_DIR/results"
ok "Results directory created: $TOOL_DIR/results"

# ── Done ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}   ✓  M7 SSRF installed successfully!${RESET}"
echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${CYAN}  Usage:${RESET}"
echo -e "    ${YELLOW}m7ssrf -u https://target.com${RESET}"
echo -e "    ${YELLOW}m7ssrf -u https://target.com --blind --interactsh-url https://your.oast.fun${RESET}"
echo -e "    ${YELLOW}m7ssrf -f targets.txt --threads 20 --json${RESET}"
echo -e "    ${YELLOW}m7ssrf -u https://target.com --full${RESET}"
echo ""
echo -e "${CYAN}  Help:${RESET}  m7ssrf --help"
echo ""
