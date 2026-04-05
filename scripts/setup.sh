#!/usr/bin/env bash
#
# malphas Tor setup script
#
# Installs and configures Tor for use with malphas hidden services.
# Does NOT install malphas itself — do that with: pip install -e .
#
# Usage:
#   git clone https://github.com/CristianDArrigo/malphas.git
#   cd malphas
#   sudo bash scripts/setup.sh
#   pip install -e .
#   sudo malphas --tor --port 7777
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
echo "  malphas tor setup"
echo "  ─────────────────"
echo ""

# ── Check root ──────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    err "run as root: sudo bash scripts/setup.sh"
    exit 1
fi

# ── Detect OS ───────────────────────────────────────────────────────────────

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    err "cannot detect OS"
    exit 1
fi

info "detected $OS"

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
        err "unsupported OS: $OS — install tor manually and re-run"
        exit 1
    fi
    ok "tor installed"
fi

# ── Configure ControlPort ───────────────────────────────────────────────────

TORRC="/etc/tor/torrc"

if grep -q "^ControlPort 9051" "$TORRC" 2>/dev/null; then
    ok "ControlPort 9051 already enabled"
else
    info "enabling ControlPort 9051..."
    if grep -q "#ControlPort 9051" "$TORRC" 2>/dev/null; then
        sed -i 's/#ControlPort 9051/ControlPort 9051/' "$TORRC"
    else
        echo "ControlPort 9051" >> "$TORRC"
    fi
    ok "ControlPort enabled"
fi

if grep -q "^CookieAuthentication 1" "$TORRC" 2>/dev/null; then
    ok "CookieAuthentication already enabled"
else
    if grep -q "#CookieAuthentication 1" "$TORRC" 2>/dev/null; then
        sed -i 's/#CookieAuthentication 1/CookieAuthentication 1/' "$TORRC"
    else
        echo "CookieAuthentication 1" >> "$TORRC"
    fi
    ok "CookieAuthentication enabled"
fi

# ── Start Tor ───────────────────────────────────────────────────────────────

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

for COOKIE in /run/tor/control.authcookie /var/run/tor/control.authcookie; do
    if [ -f "$COOKIE" ]; then
        chmod o+r "$COOKIE"
        ok "cookie permissions set ($COOKIE)"
        break
    fi
done

# ── Add user to tor group ───────────────────────────────────────────────────

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

# ── Verify ──────────────────────────────────────────────────────────────────

info "verifying..."
PASS=true

if ss -tlnp | grep -q ":9050 "; then
    ok "SOCKS5 proxy on port 9050"
else
    err "SOCKS5 proxy not listening on 9050"
    PASS=false
fi

if ss -tlnp | grep -q ":9051 "; then
    ok "ControlPort on port 9051"
else
    err "ControlPort not listening on 9051"
    PASS=false
fi

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
if [ "$PASS" = true ]; then
    echo "  ─────────────────────────────────────────"
    echo "  tor setup complete. now install malphas:"
    echo ""
    echo "    pip install -e ."
    echo "    sudo malphas --tor --port 7777"
    echo "  ─────────────────────────────────────────"
else
    echo "  setup finished with errors — check above"
fi
echo ""
