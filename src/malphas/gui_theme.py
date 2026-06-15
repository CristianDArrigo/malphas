"""
Shared design tokens (palette + spacing) for the malphas GUI.

Originally extracted to back the tkinter GUI; will also feed the
upcoming PySide6 port so the dark theme stays identical between
the two implementations during the transition.
"""

from __future__ import annotations

# ── Palette ──────────────────────────────────────────────────────────────────

# Elevation ladder — each surface sits one perceptible step above the one
# below it, so depth reads from tone rather than from hard 1px borders.
#   BG_BASE   chat canvas (deepest)
#   BG_SURFACE chrome: sidebar / header / input bar
#   BG_RAISED  inputs, cards, "them" bubbles
#   BG_HOVER / BG_ACTIVE  interactive states
BG_BASE     = "#15171d"
BG_SURFACE  = "#1d2027"
BG_RAISED   = "#272b34"
BG_HOVER    = "#333845"
BG_ACTIVE   = "#3a2026"
BG_DIVIDER  = "#23262e"

BUBBLE_THEM = "#272b34"
BUBBLE_YOU  = "#8f2f30"
BUBBLE_SYS  = "#242833"

FG_PRIMARY  = "#f1f1f4"
FG_MUTED    = "#aab0bd"
FG_FAINT    = "#737783"

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
