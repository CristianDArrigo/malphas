"""
Vector-style icons drawn directly on a tkinter.Canvas — no asset files,
no Pillow, no SVG dependency. The shape vocabulary is intentionally
flat-stroked to read like Font Awesome line icons at typical Tk
button sizes (16-24 px).

Each draw_* function takes:
    c     : the Canvas to paint on
    x, y  : top-left corner of the icon's bounding box
    size  : box edge in pixels (icon is square)
    color : stroke color (also fill where applicable)
"""

from __future__ import annotations

import math
import tkinter as tk


def _line(c: tk.Canvas, x1: float, y1: float, x2: float, y2: float,
          color: str, width: float = 1.6) -> None:
    c.create_line(x1, y1, x2, y2, fill=color, width=width,
                  capstyle=tk.ROUND, joinstyle=tk.ROUND, smooth=False)


def _arc(c: tk.Canvas, x1: float, y1: float, x2: float, y2: float,
         start: float, extent: float, color: str, width: float = 1.6) -> None:
    c.create_arc(x1, y1, x2, y2, start=start, extent=extent,
                 outline=color, style=tk.ARC, width=width)


def _circle(c: tk.Canvas, cx: float, cy: float, r: float, color: str,
            width: float = 1.6, fill: str = "") -> None:
    c.create_oval(cx - r, cy - r, cx + r, cy + r,
                  outline=color, width=width, fill=fill)


def _polyline(c: tk.Canvas, points: list[tuple[float, float]],
              color: str, width: float = 1.6) -> None:
    flat: list[float] = []
    for px, py in points:
        flat.extend([px, py])
    c.create_line(*flat, fill=color, width=width,
                  capstyle=tk.ROUND, joinstyle=tk.ROUND)


# ── Icons ────────────────────────────────────────────────────────────────────


def draw_paperclip(c: tk.Canvas, x: float, y: float, size: float,
                   color: str) -> None:
    """Diagonal paperclip — file attachment."""
    pad = size * 0.18
    # Two vertical-ish parallel curves, joined at the top (J-shape)
    # Outer curve
    cx1 = x + pad
    cy1 = y + pad
    cx2 = x + size - pad
    cy2 = y + size - pad
    # Outer J
    _arc(c, cx1, cy1, cx2, cy1 + (cy2 - cy1) * 0.55,
         start=0, extent=180, color=color, width=1.8)
    _line(c, cx2, cy1 + (cy2 - cy1) * 0.275,
          cx2, cy1 + (cy2 - cy1) * 0.85, color, 1.8)
    _arc(c, cx1 + (cx2 - cx1) * 0.18, cy1 + (cy2 - cy1) * 0.55,
         cx2, cy2,
         start=0, extent=-180, color=color, width=1.8)
    # Inner segment (the part that "clips")
    _line(c, cx1 + (cx2 - cx1) * 0.18, cy1 + (cy2 - cy1) * 0.55,
          cx1 + (cx2 - cx1) * 0.18, cy1 + (cy2 - cy1) * 0.30, color, 1.8)


def draw_send(c: tk.Canvas, x: float, y: float, size: float,
              color: str) -> None:
    """Paper-plane — send action."""
    pad = size * 0.10
    pts = [
        (x + pad,           y + size * 0.50),
        (x + size - pad,    y + pad),
        (x + size * 0.62,   y + size - pad),
        (x + size * 0.50,   y + size * 0.62),
        (x + pad,           y + size * 0.50),
    ]
    c.create_polygon(*[v for p in pts for v in p],
                     outline=color, fill="", width=1.8,
                     joinstyle=tk.ROUND)
    # Inner fold line
    _line(c, x + size * 0.50, y + size * 0.62,
          x + size - pad, y + pad, color, 1.4)


def draw_plus(c: tk.Canvas, x: float, y: float, size: float,
              color: str) -> None:
    pad = size * 0.22
    cx, cy = x + size / 2, y + size / 2
    _line(c, cx, y + pad, cx, y + size - pad, color, 1.8)
    _line(c, x + pad, cy, x + size - pad, cy, color, 1.8)


def draw_share(c: tk.Canvas, x: float, y: float, size: float,
               color: str) -> None:
    """Three connected nodes — share / generate invite."""
    r = size * 0.13
    # Top-left, bottom-left, top-right circles
    a = (x + size * 0.25, y + size * 0.30)
    b = (x + size * 0.25, y + size * 0.72)
    d = (x + size * 0.78, y + size * 0.50)
    # Connecting lines
    _line(c, a[0] + r, a[1], d[0] - r, d[1] - r * 0.5, color, 1.6)
    _line(c, b[0] + r, b[1], d[0] - r, d[1] + r * 0.5, color, 1.6)
    for cx, cy in (a, b, d):
        _circle(c, cx, cy, r, color, width=1.6, fill="")


def draw_users(c: tk.Canvas, x: float, y: float, size: float,
               color: str) -> None:
    """Two-people glyph — group / users."""
    # Left person (smaller, behind)
    head1_r = size * 0.13
    head1_cx, head1_cy = x + size * 0.36, y + size * 0.32
    _circle(c, head1_cx, head1_cy, head1_r, color, 1.6)
    body1_x1 = x + size * 0.18
    body1_x2 = x + size * 0.54
    body1_y1 = y + size * 0.50
    body1_y2 = y + size * 0.85
    _arc(c, body1_x1, body1_y1, body1_x2, body1_y2 + size * 0.3,
         start=0, extent=180, color=color, width=1.6)
    # Right person (offset)
    head2_r = size * 0.13
    head2_cx, head2_cy = x + size * 0.66, y + size * 0.36
    _circle(c, head2_cx, head2_cy, head2_r, color, 1.6)
    body2_x1 = x + size * 0.46
    body2_x2 = x + size * 0.86
    body2_y1 = y + size * 0.55
    body2_y2 = y + size * 0.90
    _arc(c, body2_x1, body2_y1, body2_x2, body2_y2 + size * 0.3,
         start=0, extent=180, color=color, width=1.6)


def draw_user_plus(c: tk.Canvas, x: float, y: float, size: float,
                   color: str) -> None:
    """Person + plus sign — add member."""
    head_r = size * 0.14
    head_cx, head_cy = x + size * 0.36, y + size * 0.32
    _circle(c, head_cx, head_cy, head_r, color, 1.6)
    body_x1 = x + size * 0.16
    body_x2 = x + size * 0.56
    body_y1 = y + size * 0.50
    body_y2 = y + size * 0.85
    _arc(c, body_x1, body_y1, body_x2, body_y2 + size * 0.3,
         start=0, extent=180, color=color, width=1.6)
    # Plus on the right
    plus_cx = x + size * 0.78
    plus_cy = y + size * 0.36
    plus_r = size * 0.12
    _line(c, plus_cx - plus_r, plus_cy, plus_cx + plus_r, plus_cy, color, 1.8)
    _line(c, plus_cx, plus_cy - plus_r, plus_cx, plus_cy + plus_r, color, 1.8)


def draw_door_out(c: tk.Canvas, x: float, y: float, size: float,
                  color: str) -> None:
    """Box + arrow out — leave."""
    pad = size * 0.18
    # Box (open right side)
    box_x1 = x + pad
    box_y1 = y + pad
    box_x2 = x + size * 0.55
    box_y2 = y + size - pad
    _line(c, box_x1, box_y1, box_x2, box_y1, color, 1.6)
    _line(c, box_x1, box_y1, box_x1, box_y2, color, 1.6)
    _line(c, box_x1, box_y2, box_x2, box_y2, color, 1.6)
    # Arrow shaft
    arrow_y = y + size / 2
    arrow_x1 = x + size * 0.40
    arrow_x2 = x + size - pad
    _line(c, arrow_x1, arrow_y, arrow_x2, arrow_y, color, 1.8)
    # Arrow head
    head_size = size * 0.16
    _line(c, arrow_x2, arrow_y, arrow_x2 - head_size, arrow_y - head_size, color, 1.8)
    _line(c, arrow_x2, arrow_y, arrow_x2 - head_size, arrow_y + head_size, color, 1.8)


def draw_lock(c: tk.Canvas, x: float, y: float, size: float,
              color: str) -> None:
    """Padlock — security indicator."""
    pad = size * 0.18
    body_x1 = x + pad
    body_x2 = x + size - pad
    body_y1 = y + size * 0.45
    body_y2 = y + size - pad
    c.create_rectangle(body_x1, body_y1, body_x2, body_y2,
                       outline=color, width=1.6, fill="")
    # Shackle
    shackle_x1 = x + size * 0.30
    shackle_x2 = x + size * 0.70
    shackle_y1 = y + pad
    shackle_y2 = body_y1 + size * 0.15
    _arc(c, shackle_x1, shackle_y1, shackle_x2, shackle_y2,
         start=0, extent=180, color=color, width=1.8)
    # Keyhole
    cx, cy = x + size / 2, y + size * 0.65
    _circle(c, cx, cy, size * 0.05, color, 1.4, fill=color)


def draw_copy(c: tk.Canvas, x: float, y: float, size: float,
              color: str) -> None:
    """Two stacked rectangles — copy / clipboard."""
    pad = size * 0.16
    # Back
    b1 = (x + pad,            y + pad,
          x + size * 0.72,    y + size * 0.78)
    c.create_rectangle(*b1, outline=color, width=1.6, fill="")
    # Front (offset down-right)
    f1 = (x + size * 0.28,    y + size * 0.32,
          x + size - pad,     y + size - pad)
    c.create_rectangle(*f1, outline=color, width=1.6, fill="")


def draw_search(c: tk.Canvas, x: float, y: float, size: float,
                color: str) -> None:
    """Magnifying glass."""
    glass_r = size * 0.30
    glass_cx = x + size * 0.40
    glass_cy = y + size * 0.40
    _circle(c, glass_cx, glass_cy, glass_r, color, 1.6)
    # Handle
    h1x = glass_cx + glass_r * math.cos(math.pi / 4)
    h1y = glass_cy + glass_r * math.sin(math.pi / 4)
    h2x = x + size - size * 0.16
    h2y = y + size - size * 0.16
    _line(c, h1x, h1y, h2x, h2y, color, 2.0)


def draw_alert(c: tk.Canvas, x: float, y: float, size: float,
               color: str) -> None:
    """Triangle with !"""
    pad = size * 0.10
    pts = [
        (x + size / 2,   y + pad),
        (x + size - pad, y + size - pad),
        (x + pad,        y + size - pad),
    ]
    c.create_polygon(*[v for p in pts for v in p],
                     outline=color, fill="", width=1.8,
                     joinstyle=tk.ROUND)
    # !
    cx = x + size / 2
    _line(c, cx, y + size * 0.36, cx, y + size * 0.60, color, 1.8)
    _circle(c, cx, y + size * 0.74, size * 0.05, color, 1.4, fill=color)


# ── Icon button factory ──────────────────────────────────────────────────────


class IconButton(tk.Canvas):
    """A square Canvas widget that paints a vector icon and behaves like
    a button: hover state, click callback, accent variant.

    Usage:
        btn = IconButton(parent, draw_send, on_click=cb,
                          size=32, bg="#15151a",
                          color="#9a9a9a", hover_color="#ececec",
                          variant="ghost")
        btn.pack(...)

    Variants:
        "ghost"  — bg unchanged on hover, only color brightens.
        "filled" — bg switches to hover_bg on hover.
        "accent" — accent bg, lighter hover.
    """

    def __init__(
        self,
        parent: tk.Misc,
        drawer,
        on_click,
        size: int = 32,
        bg: str = "#15151a",
        hover_bg: str = "#22232a",
        accent_bg: str = "#d23a3a",
        accent_hover: str = "#ff5555",
        color: str = "#9a9a9a",
        hover_color: str = "#ececec",
        accent_color: str = "#ececec",
        variant: str = "ghost",
        tooltip: str | None = None,
    ) -> None:
        super().__init__(parent, width=size, height=size, bg=bg,
                          highlightthickness=0, bd=0, cursor="hand2")
        self._drawer = drawer
        self._size = size
        self._bg = bg
        self._hover_bg = hover_bg
        self._accent_bg = accent_bg
        self._accent_hover = accent_hover
        self._color = color
        self._hover_color = hover_color
        self._accent_color = accent_color
        self._variant = variant
        self._on_click = on_click
        self._render(active=False)

        self.bind("<Button-1>", self._click)
        self.bind("<Enter>", lambda e: self._render(active=True))
        self.bind("<Leave>", lambda e: self._render(active=False))

        if tooltip:
            self._install_tooltip(tooltip)

    def _render(self, active: bool) -> None:
        if self._variant == "accent":
            new_bg = self._accent_hover if active else self._accent_bg
            new_color = self._accent_color
        elif self._variant == "filled":
            new_bg = self._hover_bg if active else self._bg
            new_color = self._hover_color if active else self._color
        else:  # ghost
            new_bg = self._hover_bg if active else self._bg
            new_color = self._hover_color if active else self._color
        self.configure(bg=new_bg)
        self.delete("icon")
        # Inset the icon slightly so it doesn't touch the button edge
        inset = self._size * 0.20
        x = inset
        y = inset
        s = self._size - 2 * inset
        # The drawer paints with the new color. We tag everything as
        # "icon" so we can wipe it on the next render.
        # Each helper uses create_* methods with no tags, so we wrap.
        n_before = len(self.find_all())
        self._drawer(self, x, y, s, new_color)
        n_after = len(self.find_all())
        # Tag everything that was just drawn so future renders can clear it.
        for item in self.find_all()[n_before:n_after]:
            self.addtag_withtag("icon", item)

    def _click(self, _event: object) -> None:
        try:
            self._on_click()
        except Exception:
            pass

    def _install_tooltip(self, text: str) -> None:
        tip: tk.Toplevel | None = None

        def show(_event: tk.Event) -> None:
            nonlocal tip
            if tip is not None:
                return
            tip = tk.Toplevel(self)
            tip.wm_overrideredirect(True)
            tip.configure(bg="#0a0a0d")
            x = self.winfo_rootx() + self.winfo_width() // 2
            y = self.winfo_rooty() + self.winfo_height() + 6
            tip.geometry(f"+{x}+{y}")
            tk.Label(tip, text=text, bg="#0a0a0d", fg="#ececec",
                     font=("TkDefaultFont", 9), padx=6, pady=2).pack()

        def hide(_event: tk.Event) -> None:
            nonlocal tip
            if tip is not None:
                try:
                    tip.destroy()
                except tk.TclError:
                    pass
                tip = None

        self.bind("<Enter>", show, add="+")
        self.bind("<Leave>", hide, add="+")
