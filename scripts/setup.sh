#!/usr/bin/env bash
#
# malphas setup script
#
# Installs Tor, configures ControlPort, sets permissions,
# installs malphas, and verifies everything works.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/CristianDArrigo/malphas/main/scripts/setup.sh | sudo bash
#   or:
#   sudo bash scripts/setup.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[0;90m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${NC} $1"; }
err()  { echo -e "  ${RED}[err]${NC} $1"; }
info() { echo -e "  ${DIM}[...]${NC} $1"; }

echo ""
echo "  malphas setup"
echo "  ─────────────"
echo ""

# ── Check root ──────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    err "this script must be run as root (sudo bash scripts/setup.sh)"
    exit 1
fi

# ── Detect OS ───────────────────────────────────────────────────────────────

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    err "cannot detect OS"
    exit 1
fi

info "detected $OS $VER"

# ── Install Tor ─────────────────────────────────────────────────────────────

if command -v tor &>/dev/null; then
    ok "tor already installed ($(tor --version | head -1 | awk '{print $3}'))"
else
    info "installing tor..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
        apt-get update -qq
        apt-get install -y -qq tor
    elif [ "$OS" = "fedora" ] || [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
        dnf install -y -q tor
    elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
        pacman -S --noconfirm tor
    else
        err "unsupported OS: $OS. install tor manually and re-run."
        exit 1
    fi
    ok "tor installed"
fi

# ── Configure Tor ControlPort ───────────────────────────────────────────────

TORRC="/etc/tor/torrc"

if grep -q "^ControlPort 9051" "$TORRC" 2>/dev/null; then
    ok "ControlPort 9051 already enabled"
else
    info "enabling ControlPort 9051..."
    # Try to uncomment first, then append if not found
    if grep -q "#ControlPort 9051" "$TORRC" 2>/dev/null; then
        sed -i 's/#ControlPort 9051/ControlPort 9051/' "$TORRC"
    else
        echo "ControlPort 9051" >> "$TORRC"
    fi
    ok "ControlPort 9051 enabled"
fi

if grep -q "^CookieAuthentication 1" "$TORRC" 2>/dev/null; then
    ok "CookieAuthentication already enabled"
else
    info "enabling CookieAuthentication..."
    if grep -q "#CookieAuthentication 1" "$TORRC" 2>/dev/null; then
        sed -i 's/#CookieAuthentication 1/CookieAuthentication 1/' "$TORRC"
    else
        echo "CookieAuthentication 1" >> "$TORRC"
    fi
    ok "CookieAuthentication enabled"
fi

# ── Start/restart Tor ───────────────────────────────────────────────────────

info "restarting tor..."
if systemctl is-active --quiet tor@default 2>/dev/null; then
    systemctl restart tor@default
elif systemctl is-active --quiet tor 2>/dev/null; then
    systemctl restart tor
else
    systemctl start tor@default 2>/dev/null || systemctl start tor 2>/dev/null
fi
sleep 3
ok "tor running"

# ── Fix cookie permissions ──────────────────────────────────────────────────

COOKIE="/run/tor/control.authcookie"
if [ -f "$COOKIE" ]; then
    chmod o+r "$COOKIE"
    ok "cookie permissions set"
else
    # Try alternative location
    COOKIE="/var/run/tor/control.authcookie"
    if [ -f "$COOKIE" ]; then
        chmod o+r "$COOKIE"
        ok "cookie permissions set"
    else
        err "cookie file not found — tor may not have started correctly"
    fi
fi

# ── Add user to debian-tor group (persistent fix) ───────────────────────────

SUDO_USER_NAME="${SUDO_USER:-$USER}"
if [ "$SUDO_USER_NAME" != "root" ]; then
    if getent group debian-tor &>/dev/null; then
        usermod -aG debian-tor "$SUDO_USER_NAME"
        ok "added $SUDO_USER_NAME to debian-tor group"
    elif getent group tor &>/dev/null; then
        usermod -aG tor "$SUDO_USER_NAME"
        ok "added $SUDO_USER_NAME to tor group"
    fi
fi

# ── Verify Tor is working ──────────────────────────────────────────────────

info "verifying tor..."
if ss -tlnp | grep -q ":9050 "; then
    ok "SOCKS5 proxy on port 9050"
else
    err "SOCKS5 proxy not listening on 9050"
fi

if ss -tlnp | grep -q ":9051 "; then
    ok "ControlPort on port 9051"
else
    err "ControlPort not listening on 9051"
fi

# ── Install Python 3.11+ if needed ─────────────────────────────────────────

PYTHON=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v $py &>/dev/null; then
        PY_VER=$($py -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
        PY_MAJOR=$($py -c "import sys; print(sys.version_info[0])" 2>/dev/null)
        PY_MINOR=$($py -c "import sys; print(sys.version_info[1])" 2>/dev/null)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
            PYTHON=$py
            break
        fi
    fi
done

if [ -n "$PYTHON" ]; then
    ok "python: $($PYTHON --version)"
else
    info "installing python 3.12..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
        apt-get update -qq
        apt-get install -y -qq python3.12 python3.12-venv 2>/dev/null || apt-get install -y -qq python3.11 python3.11-venv 2>/dev/null
    fi
    for py in python3.12 python3.11; do
        if command -v $py &>/dev/null; then
            PYTHON=$py
            break
        fi
    done
    if [ -n "$PYTHON" ]; then
        ok "python: $($PYTHON --version)"
    else
        err "could not install python 3.11+. install manually and re-run."
        exit 1
    fi
fi

# ── Install malphas ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "$PROJECT_DIR/pyproject.toml" ]; then
    info "installing malphas from local directory..."
    cd "$PROJECT_DIR"
    if [ ! -d ".venv" ]; then
        $PYTHON -m venv .venv
    fi
    . .venv/bin/activate
    pip install -e . -q
    ok "malphas installed"
else
    info "installing malphas from github..."
    pip install git+https://github.com/CristianDArrigo/malphas.git -q 2>/dev/null || {
        err "could not install from github. clone the repo first:"
        echo "    git clone https://github.com/CristianDArrigo/malphas.git"
        echo "    cd malphas && sudo bash scripts/setup.sh"
        exit 1
    }
    ok "malphas installed from github"
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "  ─────────────────────────────────────────"
echo "  setup complete. launch malphas with:"
echo ""
echo "    malphas --tor --port 7777"
echo ""
echo "  note: malphas needs sudo for hidden service"
echo "  registration (writes to /var/lib/tor/)."
echo "  run with: sudo malphas --tor --port 7777"
echo "  ─────────────────────────────────────────"
echo ""
