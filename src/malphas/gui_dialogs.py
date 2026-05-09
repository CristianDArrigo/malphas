"""
Custom in-app dialogs and toasts that replace `tkinter.messagebox` /
`tkinter.simpledialog`. The native widgets carry their OS theme,
which clashes with the dark malphas surface. These reimplementations
use the shared palette (`gui_theme`) so every popup stays on-brand.

Public API mirrors the messagebox / simpledialog one we used:

    info(parent, title, message)
    warning(parent, title, message)
    error(parent, title, message)
    confirm(parent, title, message) -> bool
    prompt(parent, title, label, initial="") -> str | None
    toast(parent, message, kind="info", ms=2200)

`filedialog.*` is intentionally kept native — file pickers should
match the OS for muscle memory.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from typing import Literal

from .gui_theme import (
    ACCENT,
    ACCENT_GLOW,
    BG_BASE,
    BG_HOVER,
    BG_RAISED,
    BG_SURFACE,
    FG_MUTED,
    FG_PRIMARY,
    INFO_CYAN,
    OK_GREEN,
    PAD_LG,
    PAD_MD,
    PAD_SM,
    PAD_XL,
    WARN_AMBER,
)

Kind = Literal["info", "warning", "error", "question"]


def _kind_color(kind: Kind) -> str:
    return {
        "info":     INFO_CYAN,
        "warning":  WARN_AMBER,
        "error":    ACCENT,
        "question": ACCENT,
    }[kind]


def _font(parent: tk.Misc, size: int = 10, bold: bool = False) -> tkfont.Font:
    return tkfont.Font(parent, size=size, weight="bold" if bold else "normal")


def _center(win: tk.Toplevel, parent: tk.Misc) -> None:
    win.update_idletasks()
    pw = parent.winfo_rootx()
    ph = parent.winfo_rooty()
    pW = parent.winfo_width()
    pH = parent.winfo_height()
    w = win.winfo_reqwidth()
    h = win.winfo_reqheight()
    x = pw + (pW - w) // 2
    y = ph + (pH - h) // 3   # slightly above center reads as "modal"
    win.geometry(f"+{max(0, x)}+{max(0, y)}")


# ── Stylized Button ──────────────────────────────────────────────────────────


class _Button(tk.Frame):
    """Flat colored button with hover. We use a Frame + Label so we
    can paint backgrounds freely without ttk theming interference."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        on_click,
        *,
        variant: Literal["accent", "ghost", "ok"] = "ghost",
        width: int = 110,
    ) -> None:
        bg, hover_bg, fg = self._colors(variant)
        super().__init__(parent, bg=bg, bd=0, highlightthickness=0)
        self._bg = bg
        self._hover_bg = hover_bg
        self._on_click = on_click
        self._label = tk.Label(self, text=text, bg=bg, fg=fg,
                                font=_font(parent, 10, bold=True),
                                padx=PAD_LG, pady=PAD_SM, cursor="hand2")
        self._label.pack(fill=tk.BOTH, expand=True)
        self.configure(width=width)
        for w in (self, self._label):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", lambda _e: self._set_bg(self._hover_bg))
            w.bind("<Leave>", lambda _e: self._set_bg(self._bg))

    @staticmethod
    def _colors(variant: str) -> tuple[str, str, str]:
        if variant == "accent":
            return ACCENT, ACCENT_GLOW, FG_PRIMARY
        if variant == "ok":
            return OK_GREEN, "#7ad07a", FG_PRIMARY
        return BG_RAISED, BG_HOVER, FG_PRIMARY

    def _set_bg(self, c: str) -> None:
        self.configure(bg=c)
        self._label.configure(bg=c)

    def _click(self, _e: object) -> None:
        try:
            self._on_click()
        except Exception:
            pass


# ── Modal base ──────────────────────────────────────────────────────────────


class _Modal(tk.Toplevel):
    """Frameless dark Toplevel with a colored top accent line."""

    def __init__(self, parent: tk.Misc, title: str, kind: Kind = "info") -> None:
        super().__init__(parent)
        self.withdraw()
        self.transient(parent)
        # Keep window decorations: removing them on Linux/Tk loses the
        # close button on some WMs and traps the user. Instead we just
        # pick a clean title and a dark inside.
        self.title(title)
        self.configure(bg=BG_BASE)
        self.resizable(False, False)
        # 4px accent strip at the top
        tk.Frame(self, bg=_kind_color(kind), height=3).pack(fill=tk.X)
        self.body = tk.Frame(self, bg=BG_BASE)
        self.body.pack(fill=tk.BOTH, expand=True, padx=PAD_XL, pady=PAD_LG)

    def show(self) -> None:
        _center(self, self.master)
        self.deiconify()
        self.grab_set()
        self.focus_set()
        self.wait_window(self)


# ── Public API ──────────────────────────────────────────────────────────────


def _show_message(parent: tk.Misc, title: str, message: str, kind: Kind) -> None:
    m = _Modal(parent, title, kind=kind)

    tk.Label(m.body, text=title, bg=BG_BASE, fg=FG_PRIMARY,
              font=_font(parent, 14, bold=True), anchor="w",
              justify="left").pack(fill=tk.X, pady=(0, PAD_SM))
    tk.Label(m.body, text=message, bg=BG_BASE, fg=FG_MUTED,
              font=_font(parent, 10), anchor="w", justify="left",
              wraplength=420).pack(fill=tk.X, pady=(0, PAD_LG))
    btn = _Button(m.body, "OK", on_click=m.destroy, variant="accent")
    btn.pack(side=tk.RIGHT)
    m.bind("<Return>", lambda _e: m.destroy())
    m.bind("<Escape>", lambda _e: m.destroy())
    m.show()


def info(parent: tk.Misc, title: str, message: str) -> None:
    _show_message(parent, title, message, "info")


def warning(parent: tk.Misc, title: str, message: str) -> None:
    _show_message(parent, title, message, "warning")


def error(parent: tk.Misc, title: str, message: str) -> None:
    _show_message(parent, title, message, "error")


def confirm(parent: tk.Misc, title: str, message: str,
            yes: str = "Yes", no: str = "Cancel",
            kind: Kind = "question") -> bool:
    m = _Modal(parent, title, kind=kind)
    answer = {"v": False}

    tk.Label(m.body, text=title, bg=BG_BASE, fg=FG_PRIMARY,
              font=_font(parent, 14, bold=True), anchor="w",
              justify="left").pack(fill=tk.X, pady=(0, PAD_SM))
    tk.Label(m.body, text=message, bg=BG_BASE, fg=FG_MUTED,
              font=_font(parent, 10), anchor="w", justify="left",
              wraplength=460).pack(fill=tk.X, pady=(0, PAD_LG))

    btn_row = tk.Frame(m.body, bg=BG_BASE)
    btn_row.pack(fill=tk.X)

    def _accept() -> None:
        answer["v"] = True
        m.destroy()

    _Button(btn_row, no, on_click=m.destroy,
             variant="ghost").pack(side=tk.RIGHT, padx=(PAD_SM, 0))
    _Button(btn_row, yes, on_click=_accept,
             variant="accent").pack(side=tk.RIGHT)

    m.bind("<Return>", lambda _e: _accept())
    m.bind("<Escape>", lambda _e: m.destroy())
    m.show()
    return answer["v"]


def prompt(parent: tk.Misc, title: str, label: str,
           initial: str = "") -> str | None:
    m = _Modal(parent, title, kind="info")
    answer: dict[str, str | None] = {"v": None}

    tk.Label(m.body, text=title, bg=BG_BASE, fg=FG_PRIMARY,
              font=_font(parent, 14, bold=True), anchor="w",
              justify="left").pack(fill=tk.X, pady=(0, PAD_SM))
    tk.Label(m.body, text=label, bg=BG_BASE, fg=FG_MUTED,
              font=_font(parent, 10), anchor="w", justify="left",
              wraplength=460).pack(fill=tk.X, pady=(0, PAD_SM))

    var = tk.StringVar(value=initial)
    entry_wrap = tk.Frame(m.body, bg=BG_RAISED)
    entry_wrap.pack(fill=tk.X, pady=(0, PAD_LG))
    entry = tk.Entry(entry_wrap, textvariable=var,
                      bg=BG_RAISED, fg=FG_PRIMARY,
                      insertbackground=ACCENT,
                      relief=tk.FLAT, bd=0, highlightthickness=0,
                      font=_font(parent, 11))
    entry.pack(fill=tk.X, padx=PAD_MD, pady=PAD_SM, ipady=4)
    entry.focus_set()
    entry.icursor(tk.END)

    btn_row = tk.Frame(m.body, bg=BG_BASE)
    btn_row.pack(fill=tk.X)

    def _accept() -> None:
        answer["v"] = var.get()
        m.destroy()

    _Button(btn_row, "Cancel", on_click=m.destroy,
             variant="ghost").pack(side=tk.RIGHT, padx=(PAD_SM, 0))
    _Button(btn_row, "OK", on_click=_accept,
             variant="accent").pack(side=tk.RIGHT)

    m.bind("<Return>", lambda _e: _accept())
    m.bind("<Escape>", lambda _e: m.destroy())
    m.show()
    return answer["v"]


# ── Toast (bottom-anchored, auto-dismiss) ───────────────────────────────────


def toast(parent: tk.Misc, message: str, *,
          kind: Kind = "info", ms: int = 2200) -> None:
    """Lightweight transient banner anchored to the bottom-right of
    `parent`. Used for ack-style notifications where a modal would be
    overkill."""
    root = parent.winfo_toplevel()
    t = tk.Toplevel(root)
    t.overrideredirect(True)
    t.transient(root)
    t.attributes("-topmost", True)
    t.configure(bg=_kind_color(kind))

    inner = tk.Frame(t, bg=BG_SURFACE)
    inner.pack(fill=tk.BOTH, expand=True, padx=(3, 0))
    tk.Label(inner, text=message, bg=BG_SURFACE, fg=FG_PRIMARY,
              font=_font(parent, 10), padx=PAD_LG, pady=PAD_SM,
              wraplength=360, justify="left").pack()

    t.update_idletasks()
    rx = root.winfo_rootx()
    ry = root.winfo_rooty()
    rW = root.winfo_width()
    rH = root.winfo_height()
    w = t.winfo_reqwidth()
    h = t.winfo_reqheight()
    x = rx + rW - w - PAD_LG
    y = ry + rH - h - PAD_XL
    t.geometry(f"+{max(0, x)}+{max(0, y)}")

    t.after(ms, t.destroy)
