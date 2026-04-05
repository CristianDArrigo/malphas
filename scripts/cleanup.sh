#!/usr/bin/env bash
#
# malphas cleanup script
#
# Removes all traces of malphas Tor configuration from the system.
# Reverts everything done by setup.sh.
#
# Usage:
#   sudo bash scripts/cleanup.sh
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
echo "  malphas cleanup"
echo "  ───────────────"
echo ""

if [ "$EUID" -ne 0 ]; then
    err "run as root: sudo bash scripts/cleanup.sh"
    exit 1
fi

# ── Remove hidden service directory ─────────────────────────────────────────

HS_DIR="/var/lib/tor/malphas_hs"
if [ -d "$HS_DIR" ]; then
    rm -rf "$HS_DIR"
    ok "removed $HS_DIR"
else
    info "hidden service directory not found, skipping"
fi

# ── Remove malphas lines from torrc ─────────────────────────────────────────

TORRC="/etc/tor/torrc"
if [ -f "$TORRC" ] && grep -q "malphas_hs" "$TORRC" 2>/dev/null; then
    sed -i '/malphas_hs/d' "$TORRC"
    # Also remove orphaned HiddenServicePort lines that follow
    sed -i '/^HiddenServicePort 80 127\.0\.0\.1/d' "$TORRC"
    # Clean up empty lines at end of file
    sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$TORRC"
    ok "removed malphas config from torrc"

    # Restore torrc permissions to default
    chmod 644 "$TORRC"
    chown root:root "$TORRC"
    ok "restored torrc permissions"
else
    info "no malphas config in torrc, skipping"
fi

# ── Remove user from debian-tor group ───────────────────────────────────────

SUDO_USER_NAME="${SUDO_USER:-}"
if [ -n "$SUDO_USER_NAME" ] && [ "$SUDO_USER_NAME" != "root" ]; then
    if getent group debian-tor &>/dev/null && id -nG "$SUDO_USER_NAME" | grep -qw debian-tor; then
        gpasswd -d "$SUDO_USER_NAME" debian-tor >/dev/null 2>&1
        ok "removed $SUDO_USER_NAME from debian-tor group"
    elif getent group tor &>/dev/null && id -nG "$SUDO_USER_NAME" | grep -qw tor; then
        gpasswd -d "$SUDO_USER_NAME" tor >/dev/null 2>&1
        ok "removed $SUDO_USER_NAME from tor group"
    else
        info "user not in tor group, skipping"
    fi
fi

# ── Remove malphas user data ───────────────────────────────────────────────

if [ -n "$SUDO_USER_NAME" ] && [ "$SUDO_USER_NAME" != "root" ]; then
    USER_HOME=$(eval echo "~$SUDO_USER_NAME")
    MALPHAS_DIR="$USER_HOME/.malphas"
    if [ -d "$MALPHAS_DIR" ]; then
        rm -rf "$MALPHAS_DIR"
        ok "removed $MALPHAS_DIR (address book + pins)"
    else
        info "no user data directory found, skipping"
    fi
fi

# ── Remove sudoers rules ────────────────────────────────────────────────────

if [ -f /etc/sudoers.d/malphas ]; then
    rm -f /etc/sudoers.d/malphas
    ok "removed sudoers rules"
else
    info "no sudoers rules found, skipping"
fi

# ── Reload Tor ──────────────────────────────────────────────────────────────

if systemctl is-active --quiet tor@default 2>/dev/null; then
    systemctl reload tor@default 2>/dev/null || true
    ok "tor reloaded"
elif systemctl is-active --quiet tor 2>/dev/null; then
    systemctl reload tor 2>/dev/null || true
    ok "tor reloaded"
fi

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
echo "  ─────────────────────────────────────────"
echo "  cleanup complete. all malphas traces removed."
echo "  tor is still installed — remove with:"
echo "    sudo apt remove tor"
echo "  ─────────────────────────────────────────"
echo ""
