"""
Shared design tokens (palette + spacing) for the malphas GUI.

Originally extracted to back the tkinter GUI; will also feed the
upcoming PySide6 port so the dark theme stays identical between
the two implementations during the transition.
"""

from __future__ import annotations

# ── Palette ──────────────────────────────────────────────────────────────────

BG_BASE     = "#1f2129"
BG_SURFACE  = "#262932"
BG_RAISED   = "#30333d"
BG_HOVER    = "#3d4150"
BG_ACTIVE   = "#4a2630"
BG_DIVIDER  = "#3a3d47"

BUBBLE_THEM = "#363944"
BUBBLE_YOU  = "#7a2828"
BUBBLE_SYS  = "#2a2c35"

FG_PRIMARY  = "#f0f0f2"
FG_MUTED    = "#b0b2bb"
FG_FAINT    = "#7a7d88"

ACCENT      = "#d23a3a"
ACCENT_DIM  = "#7a2222"
ACCENT_GLOW = "#ff5555"
OK_GREEN    = "#5cb85c"
WARN_AMBER  = "#e0a830"
INFO_CYAN   = "#5b9fd8"

# ── Spacing ─────────────────────────────────────────────────────────────────

PAD_XS = 4
PAD_SM = 8
PAD_MD = 12
PAD_LG = 16
PAD_XL = 24
