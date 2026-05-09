"""
Tkinter desktop GUI for malphas.

The asyncio loop that drives the MalphasNode runs in a background
daemon thread (`AsyncBridge`). The Tk thread keeps the mainloop and
polls a `queue.Queue` every 50 ms to consume node-side callbacks
without blocking either side.

Entry point: `launch_gui(node, book, bridge, salt_path)`.
"""

from __future__ import annotations

import asyncio
import math
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from concurrent.futures import Future
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from .addressbook import AddressBook, Contact
from .invite import generate_invite, parse_invite
from .mnemonic import salt_to_mnemonic
from .node import MalphasNode
from .salt_store import SALT_LEN

# ── Design system ────────────────────────────────────────────────────────────
#
# Three-tier dark palette with intentionally amplified contrast between
# tiers, plus accent-tinted hover/active states. Tk is intrinsically
# flat — depth here comes from layering (BG_BASE → BG_SURFACE → BG_RAISED),
# divider lines, and accent borders on selection.

BG_BASE     = "#0a0a0d"   # window background
BG_SURFACE  = "#15151a"   # sidebars, header, status bar
BG_RAISED   = "#22232a"   # chat pane, input row, dialogs
BG_HOVER    = "#2a2b34"   # sidebar item hover
BG_ACTIVE   = "#33141a"   # sidebar item active (accent-tinted)
BG_DIVIDER  = "#34343d"   # 1px lines

FG_PRIMARY  = "#ececec"
FG_MUTED    = "#9a9a9a"
FG_FAINT    = "#5e5e68"

ACCENT      = "#d23a3a"   # malphas red
ACCENT_DIM  = "#7a2222"
ACCENT_GLOW = "#ff5555"
OK_GREEN    = "#5cb85c"
WARN_AMBER  = "#e0a830"
INFO_CYAN   = "#5b9fd8"

PAD_XS = 4
PAD_SM = 8
PAD_MD = 12
PAD_LG = 16
PAD_XL = 24

WIN_W = 1200
WIN_H = 780
SIDEBAR_W = 280

GITHUB_URL = "https://github.com/CristianDArrigo/malphas"


# ── Malphas seal (drawn via Canvas, no asset file) ───────────────────────────


def draw_malphas_seal(c: tk.Canvas, cx: float, cy: float, r: float,
                      ring: str, mark: str, dot: str) -> None:
    """Render an abstract Malphas-style demonic seal centered at (cx, cy)
    with outer radius `r`. Three concentric rings, an inverted triangle,
    a hexagram inside, four cardinal dots on the outer ring, a thin
    pin-down central spear.
    """
    # Outer ring (thick)
    c.create_oval(cx - r, cy - r, cx + r, cy + r,
                  outline=ring, width=max(2, int(r / 24)))
    # Mid ring (thin)
    rm = r * 0.78
    c.create_oval(cx - rm, cy - rm, cx + rm, cy + rm,
                  outline=mark, width=1)
    # Inner ring (thin, smaller)
    rs = r * 0.34
    c.create_oval(cx - rs, cy - rs, cx + rs, cy + rs,
                  outline=mark, width=1)

    # Inverted equilateral triangle (▽) inscribed in the mid ring
    pts = []
    for i in range(3):
        angle = math.pi / 2 + 2 * math.pi * i / 3 + math.pi  # rotate so apex is down
        pts.extend([cx + rm * math.cos(angle),
                    cy + rm * math.sin(angle)])
    c.create_polygon(*pts, outline=mark, fill="",
                     width=max(1, int(r / 32)))

    # Hexagram (Star of Solomon) inside — two overlapping triangles
    rh = r * 0.50
    pts1, pts2 = [], []
    for i in range(3):
        a1 = math.pi / 2 + 2 * math.pi * i / 3
        a2 = -math.pi / 2 + 2 * math.pi * i / 3
        pts1.extend([cx + rh * math.cos(a1), cy + rh * math.sin(a1)])
        pts2.extend([cx + rh * math.cos(a2), cy + rh * math.sin(a2)])
    c.create_polygon(*pts1, outline=ring, fill="", width=1)
    c.create_polygon(*pts2, outline=ring, fill="", width=1)

    # Vertical descending spear inside (Malphas iconography hint)
    c.create_line(cx, cy - rs * 0.85, cx, cy + r * 0.92,
                  fill=ring, width=1)
    # Cross-bar near the spear's top (small)
    c.create_line(cx - rs * 0.35, cy - rs * 0.55,
                  cx + rs * 0.35, cy - rs * 0.55,
                  fill=ring, width=1)

    # 4 cardinal dots on the outer ring
    for angle in (math.pi / 2, -math.pi / 2, 0.0, math.pi):
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)
        d = max(2.0, r / 18)
        c.create_oval(x - d, y - d, x + d, y + d, fill=dot, outline="")

    # Central dot
    cd = max(2.0, r / 22)
    c.create_oval(cx - cd, cy - cd, cx + cd, cy + cd,
                  fill=dot, outline="")


# ── AsyncBridge ──────────────────────────────────────────────────────────────


class AsyncBridge:
    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name="malphas-asyncio")
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def submit_coro(self, coro: Any) -> Future:
        if self.loop is None:
            raise RuntimeError("AsyncBridge not started")
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self, timeout: float = 3.0) -> None:
        if self.loop is None:
            return
        loop = self.loop
        loop.call_soon_threadsafe(loop.stop)
        self._thread.join(timeout=timeout)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _short(peer_id: str, n: int = 12) -> str:
    return peer_id[:n] + ("…" if len(peer_id) > n else "")


def _ts() -> str:
    return time.strftime("%H:%M")


def _pick_font(root: tk.Misc, candidates: list[str]) -> str:
    available = set(tkfont.families(root))
    for name in candidates:
        if name in available:
            return name
    return "TkDefaultFont"


# ── Sidebar item (custom widget) ─────────────────────────────────────────────


class SidebarItem(tk.Frame):
    """A clickable conversation row with hover + active states.

    Layered on plain tk.Frame so we can paint a left accent bar when
    selected (Treeview can't do that), and switch background on
    enter/leave for proper hover feedback.
    """

    def __init__(
        self,
        parent: tk.Misc,
        glyph: str,
        title: str,
        subtitle: str,
        unread: bool,
        on_click: Any,
        font_body: tkfont.Font,
        font_small: tkfont.Font,
    ) -> None:
        super().__init__(parent, bg=BG_SURFACE, bd=0, highlightthickness=0)
        self._on_click = on_click
        self._active = False

        # Left accent bar (hidden when inactive — same color as bg).
        self._bar = tk.Frame(self, bg=BG_SURFACE, width=3)
        self._bar.pack(side=tk.LEFT, fill=tk.Y)

        # Inner padding container
        self._inner = tk.Frame(self, bg=BG_SURFACE)
        self._inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                          padx=PAD_MD, pady=PAD_SM)

        # Glyph (●, ◦, ▣)
        self._glyph = tk.Label(self._inner, text=glyph, bg=BG_SURFACE,
                                fg=FG_MUTED, font=font_body)
        self._glyph.pack(side=tk.LEFT, padx=(0, PAD_SM))

        # Title + subtitle stacked
        text_box = tk.Frame(self._inner, bg=BG_SURFACE)
        text_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._title = tk.Label(text_box, text=title, bg=BG_SURFACE,
                                fg=FG_PRIMARY, font=font_body, anchor="w")
        self._title.pack(side=tk.TOP, fill=tk.X, anchor="w")
        if subtitle:
            self._sub = tk.Label(text_box, text=subtitle, bg=BG_SURFACE,
                                  fg=FG_FAINT, font=font_small, anchor="w")
            self._sub.pack(side=tk.TOP, fill=tk.X, anchor="w")
        else:
            self._sub = None

        # Unread badge on the right
        self._badge = tk.Label(self._inner, text="●" if unread else "",
                                bg=BG_SURFACE,
                                fg=ACCENT if unread else BG_SURFACE,
                                font=font_small)
        self._badge.pack(side=tk.RIGHT)

        # Bind click + hover on every child (Tk doesn't propagate)
        for w in (self, self._bar, self._inner, self._glyph,
                  self._title, self._badge,
                  *([self._sub] if self._sub else [])):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", self._enter)
            w.bind("<Leave>", self._leave)

    def _bg(self, color: str) -> None:
        for w in (self, self._inner, self._glyph, self._title, self._badge):
            w.configure(bg=color)
        if self._sub:
            self._sub.configure(bg=color)
        # Inner text_box parent of title/sub
        try:
            self._title.master.configure(bg=color)
        except tk.TclError:
            pass

    def _click(self, _event: object) -> None:
        try:
            self._on_click()
        except Exception:
            pass

    def _enter(self, _event: object) -> None:
        if not self._active:
            self._bg(BG_HOVER)

    def _leave(self, _event: object) -> None:
        if not self._active:
            self._bg(BG_SURFACE)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._bg(BG_ACTIVE)
            self._bar.configure(bg=ACCENT)
        else:
            self._bg(BG_SURFACE)
            self._bar.configure(bg=BG_SURFACE)


# ── MalphasGUI ───────────────────────────────────────────────────────────────


class MalphasGUI:
    def __init__(
        self,
        node: MalphasNode,
        book: AddressBook,
        bridge: AsyncBridge,
        salt_path: Path | None = None,
    ) -> None:
        self.node = node
        self.book = book
        self.bridge = bridge
        self.salt_path = salt_path
        self.active: str | None = None
        self._scrollback: dict[str, list[tuple[str, str]]] = {}
        self._pending_offers: dict[str, tuple[str, dict]] = {}
        self._completed_files: dict[str, tuple[str, str, bytes]] = {}
        self._unread: set[str] = set()
        self._sidebar_items: dict[str, SidebarItem] = {}
        self.event_queue: queue.Queue = queue.Queue()

        self.root = tk.Tk()
        self.root.title(f"malphas — {_short(node.identity.peer_id, 16)}")
        self.root.geometry(f"{WIN_W}x{WIN_H}")
        self.root.minsize(860, 580)
        self.root.configure(bg=BG_BASE)
        self.root.protocol("WM_DELETE_WINDOW", self._on_quit)

        self._init_fonts()
        self._setup_style()
        self._build_ui()
        self._wire_callbacks()

        self.root.after(50, self._drain_events)
        self.root.after(1000, self._refresh_status)

    # ── Fonts ──────────────────────────────────────────────────────────────

    def _init_fonts(self) -> None:
        sans = _pick_font(self.root, [
            "Inter", "IBM Plex Sans", "Roboto", "Cantarell",
            "DejaVu Sans", "Liberation Sans", "Helvetica Neue", "Arial",
        ])
        mono = _pick_font(self.root, [
            "JetBrains Mono", "IBM Plex Mono", "Fira Code", "Source Code Pro",
            "Liberation Mono", "Menlo", "Consolas", "DejaVu Sans Mono",
            "Courier",
        ])
        self.f_body  = tkfont.Font(family=sans, size=10)
        self.f_bold  = tkfont.Font(family=sans, size=10, weight="bold")
        self.f_h1    = tkfont.Font(family=sans, size=14, weight="bold")
        self.f_h2    = tkfont.Font(family=sans, size=11, weight="bold")
        self.f_small = tkfont.Font(family=sans, size=9)
        self.f_tiny  = tkfont.Font(family=sans, size=8)
        self.f_mono  = tkfont.Font(family=mono, size=10)
        self.f_mono_sm = tkfont.Font(family=mono, size=9)

    # ── Theme ───────────────────────────────────────────────────────────────

    def _setup_style(self) -> None:
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass

        s.configure(".", background=BG_BASE, foreground=FG_PRIMARY,
                    fieldbackground=BG_RAISED, borderwidth=0, font=self.f_body)
        s.configure("TFrame", background=BG_BASE)
        s.configure("Surface.TFrame", background=BG_SURFACE)
        s.configure("Raised.TFrame", background=BG_RAISED)

        s.configure("TLabel", background=BG_BASE, foreground=FG_PRIMARY)
        s.configure("Surface.TLabel", background=BG_SURFACE, foreground=FG_PRIMARY)
        s.configure("Heading.TLabel", background=BG_SURFACE,
                    foreground=FG_FAINT, font=self.f_tiny,
                    padding=(PAD_MD, PAD_LG, PAD_MD, PAD_XS))
        s.configure("Title.TLabel", background=BG_SURFACE,
                    foreground=FG_PRIMARY, font=self.f_h1)
        s.configure("Status.TLabel", background=BG_SURFACE,
                    foreground=FG_MUTED, font=self.f_small,
                    padding=(PAD_MD, PAD_SM))

        s.configure("TButton", background=BG_RAISED, foreground=FG_PRIMARY,
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=self.f_body)
        s.map("TButton",
              background=[("active", ACCENT_DIM), ("pressed", ACCENT_DIM)])
        s.configure("Accent.TButton", background=ACCENT, foreground=FG_PRIMARY,
                    borderwidth=0, padding=(PAD_LG, PAD_SM), font=self.f_bold)
        s.map("Accent.TButton",
              background=[("active", ACCENT_GLOW), ("pressed", ACCENT_DIM)])
        s.configure("Ghost.TButton", background=BG_SURFACE, foreground=FG_MUTED,
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=self.f_body)
        s.map("Ghost.TButton",
              background=[("active", BG_HOVER)],
              foreground=[("active", FG_PRIMARY)])

        s.configure("TEntry", fieldbackground=BG_RAISED, foreground=FG_PRIMARY,
                    insertcolor=ACCENT, borderwidth=0,
                    padding=(PAD_MD, PAD_SM), font=self.f_body)

        s.configure("Vertical.TScrollbar", background=BG_SURFACE,
                    troughcolor=BG_SURFACE, borderwidth=0, arrowsize=12)
        s.map("Vertical.TScrollbar",
              background=[("active", BG_RAISED), ("pressed", ACCENT_DIM)])

    # ── UI build ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_menubar()
        self._build_header()

        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_main(body)

        self._build_statusbar()

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self.root, bg=BG_SURFACE, fg=FG_PRIMARY,
                          activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                          borderwidth=0, font=self.f_body)
        self.root.config(menu=menubar)

        m_file = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                         activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                         font=self.f_body)
        m_file.add_command(label="Generate invite (copy to clipboard)",
                           command=self._action_export, accelerator="Ctrl+E")
        m_file.add_command(label="Import invite from clipboard…",
                           command=self._action_import, accelerator="Ctrl+I")
        m_file.add_separator()
        m_file.add_command(label="Backup: show 12-word mnemonic",
                           command=self._action_backup)
        m_file.add_separator()
        m_file.add_command(label="PANIC (wipe and exit)",
                           command=self._action_panic, foreground=ACCENT)
        m_file.add_separator()
        m_file.add_command(label="Quit", command=self._on_quit, accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=m_file)

        m_view = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                         activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                         font=self.f_body)
        m_view.add_command(label="Refresh peer list", command=self._refresh_sidebar,
                           accelerator="F5")
        menubar.add_cascade(label="View", menu=m_view)

        m_group = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                          activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                          font=self.f_body)
        m_group.add_command(label="Create new group…", command=self._action_group_new)
        m_group.add_command(label="Add member to active group…",
                            command=self._action_group_add)
        m_group.add_command(label="Leave active group", command=self._action_group_leave)
        menubar.add_cascade(label="Group", menu=m_group)

        m_help = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                         activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                         font=self.f_body)
        m_help.add_command(label="About malphas", command=self._action_about)
        m_help.add_command(label="Open GitHub repo",
                           command=lambda: webbrowser.open(GITHUB_URL))
        menubar.add_cascade(label="Help", menu=m_help)

        self.root.bind("<Control-e>", lambda e: self._action_export())
        self.root.bind("<Control-i>", lambda e: self._action_import())
        self.root.bind("<Control-q>", lambda e: self._on_quit())
        self.root.bind("<F5>", lambda e: self._refresh_sidebar())

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=BG_SURFACE, height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # Left: small seal + brand + peer_id
        left = tk.Frame(header, bg=BG_SURFACE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(PAD_LG, 0))

        seal = tk.Canvas(left, width=36, height=36, bg=BG_SURFACE,
                          highlightthickness=0, bd=0)
        seal.pack(side=tk.LEFT, pady=PAD_MD)
        draw_malphas_seal(seal, 18, 18, 16, ACCENT, FG_PRIMARY, ACCENT)

        text_box = tk.Frame(left, bg=BG_SURFACE)
        text_box.pack(side=tk.LEFT, padx=(PAD_MD, 0), pady=PAD_MD)
        tk.Label(text_box, text="malphas", bg=BG_SURFACE, fg=FG_PRIMARY,
                  font=self.f_h1).pack(anchor="w")
        tk.Label(text_box, text=_short(self.node.identity.peer_id, 16),
                  bg=BG_SURFACE, fg=FG_MUTED, font=self.f_mono_sm).pack(anchor="w")

        # Right: connection dot + counters
        right = tk.Frame(header, bg=BG_SURFACE)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, PAD_LG))

        rwrap = tk.Frame(right, bg=BG_SURFACE)
        rwrap.pack(side=tk.RIGHT, pady=PAD_MD)
        self.dot = tk.Label(rwrap, text="●", bg=BG_SURFACE, fg=FG_FAINT,
                             font=self.f_body)
        self.dot.pack(side=tk.RIGHT, padx=(PAD_SM, 0))
        self.header_status_var = tk.StringVar()
        tk.Label(rwrap, textvariable=self.header_status_var,
                  bg=BG_SURFACE, fg=FG_MUTED, font=self.f_small
                  ).pack(side=tk.RIGHT)

        # Bottom 1px divider
        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

    def _build_sidebar(self, parent: tk.Misc) -> None:
        sidebar = tk.Frame(parent, bg=BG_SURFACE, width=SIDEBAR_W)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Vertical divider on the right edge
        # (placed by parent layout — see _build_main)
        # Heading
        tk.Label(sidebar, text="CONVERSATIONS", bg=BG_SURFACE, fg=FG_FAINT,
                  font=self.f_tiny, anchor="w").pack(
                      anchor="w", padx=PAD_MD, pady=(PAD_LG, PAD_SM))

        # Scrollable container
        scroll_wrap = tk.Frame(sidebar, bg=BG_SURFACE)
        scroll_wrap.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(scroll_wrap, bg=BG_SURFACE, highlightthickness=0,
                            bd=0)
        sb = ttk.Scrollbar(scroll_wrap, orient="vertical", command=canvas.yview,
                            style="Vertical.TScrollbar")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._sidebar_canvas = canvas
        self._sidebar_inner = tk.Frame(canvas, bg=BG_SURFACE)
        self._sidebar_window = canvas.create_window(
            (0, 0), window=self._sidebar_inner, anchor="nw"
        )

        def _resize(event: object) -> None:
            canvas.itemconfigure(self._sidebar_window, width=canvas.winfo_width())
            canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.bind("<Configure>", _resize)
        self._sidebar_inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        # Mousewheel on hover
        canvas.bind("<Enter>",
                     lambda e: canvas.bind_all("<MouseWheel>", self._on_mousewheel))
        canvas.bind("<Leave>",
                     lambda e: canvas.unbind_all("<MouseWheel>"))

        # Bottom action area
        actions = tk.Frame(sidebar, bg=BG_SURFACE)
        actions.pack(fill=tk.X, padx=PAD_MD, pady=PAD_MD)
        ttk.Button(actions, text="+  Import invite", style="Ghost.TButton",
                    command=self._action_import).pack(fill=tk.X, pady=(0, PAD_XS))
        ttk.Button(actions, text="↗  Generate invite", style="Ghost.TButton",
                    command=self._action_export).pack(fill=tk.X)

        # Vertical divider between sidebar and main
        tk.Frame(parent, width=1, bg=BG_DIVIDER).pack(side=tk.LEFT, fill=tk.Y)

    def _on_mousewheel(self, event: tk.Event) -> None:
        try:
            self._sidebar_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass

    def _build_main(self, parent: tk.Misc) -> None:
        main = tk.Frame(parent, bg=BG_BASE)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Conversation header
        self.conv_header = tk.Frame(main, bg=BG_SURFACE, height=60)
        self.conv_header.pack(fill=tk.X, side=tk.TOP)
        self.conv_header.pack_propagate(False)

        title_box = tk.Frame(self.conv_header, bg=BG_SURFACE)
        title_box.pack(side=tk.LEFT, fill=tk.Y, padx=PAD_LG, pady=PAD_SM)
        self.conv_title_var = tk.StringVar(value="No conversation")
        self.conv_sub_var = tk.StringVar(value="")
        tk.Label(title_box, textvariable=self.conv_title_var, bg=BG_SURFACE,
                  fg=FG_PRIMARY, font=self.f_h2, anchor="w").pack(anchor="w")
        tk.Label(title_box, textvariable=self.conv_sub_var, bg=BG_SURFACE,
                  fg=FG_MUTED, font=self.f_mono_sm, anchor="w").pack(anchor="w")

        tk.Frame(main, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

        # Chat area (with empty-state overlay)
        chat_frame = tk.Frame(main, bg=BG_RAISED)
        chat_frame.pack(fill=tk.BOTH, expand=True)

        self.chat = tk.Text(chat_frame, bg=BG_RAISED, fg=FG_PRIMARY,
                             insertbackground=ACCENT, borderwidth=0,
                             padx=PAD_XL, pady=PAD_LG, wrap=tk.WORD,
                             state=tk.DISABLED, font=self.f_mono,
                             highlightthickness=0, spacing1=2, spacing3=4)
        chat_sb = ttk.Scrollbar(chat_frame, orient="vertical",
                                 command=self.chat.yview,
                                 style="Vertical.TScrollbar")
        self.chat.configure(yscrollcommand=chat_sb.set)
        self.chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        chat_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat.tag_configure("you",        foreground=FG_PRIMARY)
        self.chat.tag_configure("them",       foreground=FG_PRIMARY)
        self.chat.tag_configure("name_you",   foreground=FG_MUTED, font=self.f_bold)
        self.chat.tag_configure("name_them",  foreground=ACCENT,   font=self.f_bold)
        self.chat.tag_configure("ts",         foreground=FG_FAINT, font=self.f_small)
        self.chat.tag_configure("system",     foreground=WARN_AMBER, font=self.f_small)
        self.chat.tag_configure("group",      foreground=INFO_CYAN, font=self.f_bold)
        self.chat.tag_configure("ok",         foreground=OK_GREEN, font=self.f_small)
        self.chat.tag_configure("err",        foreground=ACCENT,   font=self.f_small)

        # Empty-state: a Canvas with the seal + tagline
        self.empty_canvas = tk.Canvas(chat_frame, bg=BG_RAISED,
                                       highlightthickness=0, bd=0)

        self._show_empty(True)
        chat_frame.bind("<Configure>", self._on_chat_resize)

        # Input row
        input_wrap = tk.Frame(main, bg=BG_RAISED)
        input_wrap.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(main, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.BOTTOM)

        input_inner = tk.Frame(input_wrap, bg=BG_RAISED)
        input_inner.pack(fill=tk.X, padx=PAD_LG, pady=PAD_LG)

        self.input_var = tk.StringVar()
        self.entry = ttk.Entry(input_inner, textvariable=self.input_var,
                                font=self.f_mono)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                         padx=(0, PAD_SM), ipady=PAD_XS)
        self.entry.bind("<Return>", self._on_send)

        ttk.Button(input_inner, text="📎  file", style="Ghost.TButton",
                    command=self._action_send_file).pack(side=tk.LEFT, padx=(0, PAD_XS))
        ttk.Button(input_inner, text="send", style="Accent.TButton",
                    command=self._on_send).pack(side=tk.LEFT)

    def _on_chat_resize(self, event: tk.Event) -> None:
        if not self.empty_canvas.winfo_ismapped():
            return
        self._draw_empty()

    def _draw_empty(self) -> None:
        c = self.empty_canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 50 or h < 50:
            return
        cx, cy = w / 2, h / 2 - 30
        r = min(w, h) * 0.18
        r = max(60.0, min(140.0, r))
        draw_malphas_seal(c, cx, cy, r, ACCENT, FG_FAINT, ACCENT_DIM)
        # Tagline
        c.create_text(cx, cy + r + PAD_LG * 2,
                       text="malphas",
                       fill=FG_MUTED, font=self.f_h1)
        c.create_text(cx, cy + r + PAD_LG * 2 + 28,
                       text="pick a conversation, or import an invite",
                       fill=FG_FAINT, font=self.f_body)

    def _build_statusbar(self) -> None:
        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status_var,
                  style="Status.TLabel", anchor="w").pack(side=tk.BOTTOM, fill=tk.X)
        self._set_status()

    def _show_empty(self, on: bool) -> None:
        if on:
            self.empty_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
            # draw after a tick so winfo_width has been resolved
            self.root.after(50, self._draw_empty)
        else:
            self.empty_canvas.place_forget()

    # ── Event drain ────────────────────────────────────────────────────────

    def _drain_events(self) -> None:
        try:
            for _ in range(50):
                ev = self.event_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(50, self._drain_events)

    def _handle_event(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "message":
            self._on_msg(ev[1], ev[2])
        elif kind == "receipt":
            self._append_chat(ev[2], "ok" if ev[3] else "err",
                              "    " + ("✓ delivered" if ev[3] else "✗ no receipt"))
        elif kind == "pin_violation":
            messagebox.showerror(
                "Key mismatch",
                f"Pinned key mismatch for {_short(ev[1])}.\n"
                f"Expected {ev[2][:16]}…\nReceived {ev[3][:16]}…\n\n"
                "Connection rejected. Use /trust via CLI.",
                parent=self.root)
        elif kind == "file_offer":
            self._on_file_offer(ev[1], ev[2])
        elif kind == "file_complete":
            self._on_file_complete(ev[1], ev[2])
        elif kind == "group_invite":
            self._on_group_invite(ev[1], ev[2], ev[3], ev[4])
        elif kind == "group_msg":
            self._on_group_msg(ev[1], ev[2], ev[3], ev[4])

    # ── Status / sidebar refresh ────────────────────────────────────────────

    def _set_status(self) -> None:
        n_peers = len(self.node._connections)
        active_label = "—"
        if self.active:
            group = self.node._groups.get_by_id(self.active)
            if group:
                active_label = f"group {group.name}"
            else:
                contact = self.book.get_by_peer_id(self.active)
                active_label = contact.label if contact else _short(self.active)
        onion = self.node.transport.public_address or ""
        tor_marker = "  ·  tor" if onion.endswith(".onion") else ""

        n_groups = len(self.node._groups.all_groups())
        self.header_status_var.set(
            f"{n_peers} peer{'s' if n_peers != 1 else ''}"
            f"   ·   {n_groups} group{'s' if n_groups != 1 else ''}"
            f"{tor_marker}")
        self.dot.configure(fg=OK_GREEN if n_peers > 0 else FG_FAINT)
        self.status_var.set(f"port {self.node.port}   ·   active: {active_label}")

    def _refresh_status(self) -> None:
        self._set_status()
        self.root.after(1000, self._refresh_status)

    def _refresh_sidebar(self) -> None:
        # Clear previous items
        for child in self._sidebar_inner.winfo_children():
            child.destroy()
        self._sidebar_items = {}

        # PEERS section
        tk.Label(self._sidebar_inner, text="PEERS", bg=BG_SURFACE,
                  fg=FG_FAINT, font=self.f_tiny, anchor="w").pack(
                      anchor="w", padx=PAD_MD, pady=(PAD_SM, PAD_XS))

        seen: set[str] = set()
        for c in self.book.all():
            seen.add(c.peer_id)
            sub = _short(c.peer_id, 12)
            item = SidebarItem(
                self._sidebar_inner, glyph="●", title=c.label, subtitle=sub,
                unread=c.peer_id in self._unread,
                on_click=lambda pid=c.peer_id: self._select(pid),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[c.peer_id] = item

        for p in self.node.discovery.all_peers():
            pid = p["peer_id"]
            if pid in seen:
                continue
            item = SidebarItem(
                self._sidebar_inner, glyph="◦", title=_short(pid, 12),
                subtitle="(unsaved)",
                unread=pid in self._unread,
                on_click=lambda x=pid: self._select(x),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[pid] = item

        # GROUPS section
        tk.Label(self._sidebar_inner, text="GROUPS", bg=BG_SURFACE,
                  fg=FG_FAINT, font=self.f_tiny, anchor="w").pack(
                      anchor="w", padx=PAD_MD, pady=(PAD_LG, PAD_XS))

        for g in self.node._groups.all_groups():
            item = SidebarItem(
                self._sidebar_inner, glyph="▣", title=g.name,
                subtitle=f"{g.member_count()} members",
                unread=g.group_id in self._unread,
                on_click=lambda gid=g.group_id: self._select(gid),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[g.group_id] = item

        # Empty state
        if not self.book.all() and not self.node._groups.all_groups() \
                and not self.node.discovery.all_peers():
            tk.Label(self._sidebar_inner,
                      text="No peers yet.\nImport an invite to start.",
                      bg=BG_SURFACE, fg=FG_FAINT, font=self.f_small,
                      justify="center"
                      ).pack(pady=PAD_XL, padx=PAD_LG)

        # Mark active item
        if self.active and self.active in self._sidebar_items:
            self._sidebar_items[self.active].set_active(True)

    def _select(self, key: str) -> None:
        # Mark previous inactive
        if self.active and self.active in self._sidebar_items:
            try:
                self._sidebar_items[self.active].set_active(False)
            except tk.TclError:
                pass
        self.active = key
        self._unread.discard(key)
        if key in self._sidebar_items:
            self._sidebar_items[key].set_active(True)
        self._render_active()

    def _render_active(self) -> None:
        if not self.active:
            self.conv_title_var.set("No conversation")
            self.conv_sub_var.set("")
            self.chat.config(state=tk.NORMAL)
            self.chat.delete("1.0", tk.END)
            self.chat.config(state=tk.DISABLED)
            self._show_empty(True)
            return
        self._show_empty(False)
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            self.conv_title_var.set(group.name)
            self.conv_sub_var.set(
                f"group  ·  {group.member_count()} members  ·  "
                f"{_short(group.group_id, 16)}")
        else:
            contact = self.book.get_by_peer_id(self.active)
            label = contact.label if contact else "(unsaved peer)"
            self.conv_title_var.set(label)
            self.conv_sub_var.set(_short(self.active, 24))

        self.chat.config(state=tk.NORMAL)
        self.chat.delete("1.0", tk.END)
        for tag, text in self._scrollback.get(self.active, []):
            self.chat.insert(tk.END, text + "\n", tag)
        self.chat.config(state=tk.DISABLED)
        self.chat.see(tk.END)
        self._set_status()

    # ── Append helpers ──────────────────────────────────────────────────────

    def _append_chat(self, conv_key: str, tag: str, text: str) -> None:
        self._scrollback.setdefault(conv_key, []).append((tag, text))
        if conv_key == self.active:
            self.chat.config(state=tk.NORMAL)
            self.chat.insert(tk.END, text + "\n", tag)
            self.chat.config(state=tk.DISABLED)
            self.chat.see(tk.END)

    def _append_message(self, conv_key: str, who: str, content: str,
                        is_self: bool, group_name: str | None = None) -> None:
        existing = self._scrollback.setdefault(conv_key, [])
        if existing:
            existing.append(("ts", ""))
            if conv_key == self.active:
                self.chat.config(state=tk.NORMAL)
                self.chat.insert(tk.END, "\n", "ts")
                self.chat.config(state=tk.DISABLED)
        head = f"[{_ts()}]  "
        prefix = f"[{group_name}] " if group_name else ""
        name_tag = "name_you" if is_self else "name_them"
        body_tag = "you" if is_self else "them"
        existing.append(("ts", head + prefix + who))
        existing.append((body_tag, "  " + content))
        if conv_key == self.active:
            self.chat.config(state=tk.NORMAL)
            self.chat.insert(tk.END, head, "ts")
            self.chat.insert(tk.END, prefix + who + "\n", name_tag)
            self.chat.insert(tk.END, "  " + content + "\n", body_tag)
            self.chat.config(state=tk.DISABLED)
            self.chat.see(tk.END)

    # ── Send ────────────────────────────────────────────────────────────────

    def _on_send(self, event: object | None = None) -> None:
        text = self.input_var.get().strip()
        if not text or not self.active:
            return
        self.input_var.set("")
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            self.bridge.submit_coro(self.node.send_group_message(group.group_id, text))
            self._append_message(self.active, "you", text, is_self=True,
                                  group_name=group.name)
        else:
            self.bridge.submit_coro(self.node.send_message(self.active, text))
            self._append_message(self.active, "you", text, is_self=True)

    # ── Node-callback handlers ─────────────────────────────────────────────

    def _conv_label(self, peer_id: str) -> str:
        contact = self.book.get_by_peer_id(peer_id)
        return contact.label if contact else _short(peer_id, 12)

    def _on_msg(self, from_id: str, content: str) -> None:
        label = self._conv_label(from_id)
        self._append_message(from_id, label, content, is_self=False)
        if self.active != from_id:
            self._unread.add(from_id)
            self._refresh_sidebar()

    def _on_file_offer(self, from_id: str, offer: dict) -> None:
        fid = offer.get("file_id", "")
        if not fid:
            return
        self._pending_offers[fid] = (from_id, offer)
        label = self._conv_label(from_id)
        ok = messagebox.askyesno(
            "Incoming file",
            f"{label} wants to send '{offer.get('name')}'\n"
            f"({offer.get('size')} bytes).\n\nAccept?",
            parent=self.root)
        if ok:
            self.node.accept_file_offer(offer)
            self._append_chat(from_id, "system",
                              f"  ⇣  accepting {offer.get('name')} from {label}")
        else:
            self._pending_offers.pop(fid, None)

    def _on_file_complete(self, file_id: str, data: bytes) -> None:
        offer_entry = self._pending_offers.pop(file_id, None)
        from_id = offer_entry[0] if offer_entry else "?"
        name = offer_entry[1].get("name", "file.bin") if offer_entry else "file.bin"
        self._completed_files[file_id] = (from_id, name, data)
        label = self._conv_label(from_id) if from_id != "?" else "?"
        self._append_chat(from_id, "ok",
                          f"  ✓ received {name} ({len(data)} bytes) from {label}")

        path = filedialog.asksaveasfilename(parent=self.root, initialfile=name,
                                             title=f"Save '{name}' as…")
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                self._append_chat(from_id, "ok", f"  ✓ saved to {path}")
                self._completed_files.pop(file_id, None)
            except OSError as e:
                messagebox.showerror("Save failed", str(e), parent=self.root)

    def _on_group_invite(self, from_id: str, group_id: str, group_name: str,
                          members: list) -> None:
        label = self._conv_label(from_id)
        self._append_chat(group_id, "system",
                          f"  ⊕  {label} added you to '{group_name}' "
                          f"({len(members)} members)")
        self._refresh_sidebar()

    def _on_group_msg(self, from_id: str, group_id: str, group_name: str,
                       content: str) -> None:
        label = self._conv_label(from_id)
        self._append_message(group_id, label, content, is_self=False,
                              group_name=group_name)
        if self.active != group_id:
            self._unread.add(group_id)
            self._refresh_sidebar()

    # ── Menu actions ────────────────────────────────────────────────────────

    def _action_export(self) -> None:
        host = self.node.host
        port = self.node.port
        onion = self.node.transport.public_address \
            if self.node.transport.public_address \
            and self.node.transport.public_address.endswith(".onion") else None
        url = generate_invite(self.node.identity, host, port, onion=onion)
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        messagebox.showinfo(
            "Invite copied",
            "A signed malphas:// invite is on your clipboard. "
            "Send it to the peer over a channel you trust.",
            parent=self.root)

    def _action_import(self) -> None:
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Clipboard empty", "Nothing to import.",
                                  parent=self.root)
            return
        try:
            data = parse_invite(text)
        except ValueError as e:
            messagebox.showerror("Invalid invite", str(e), parent=self.root)
            return

        ok = messagebox.askyesno(
            "Import invite",
            f"Connect to peer_id\n\n{_short(data['peer_id'], 24)}\n\n"
            f"at {data.get('host')}:{data.get('port')}?",
            parent=self.root)
        if not ok:
            return

        async def _connect() -> bool:
            host = data.get("onion") or data["host"]
            port = 80 if "onion" in data else data["port"]
            return await self.node.connect_to_peer(
                host, port, data["peer_id"],
                bytes.fromhex(data["x25519_pub"]),
                bytes.fromhex(data["ed25519_pub"]))

        future = self.bridge.submit_coro(_connect())
        try:
            success = future.result(timeout=35.0)
        except Exception as e:
            messagebox.showerror("Connection failed", str(e), parent=self.root)
            return
        if not success:
            messagebox.showerror("Connection failed", "Could not reach the peer.",
                                  parent=self.root)
            return

        label = simpledialog.askstring("Save to address book",
                                        "Label (leave empty to skip):",
                                        parent=self.root)
        if label:
            save_host = data.get("onion", data["host"])
            save_port = 80 if "onion" in data else data["port"]
            self.book.add(Contact(
                label=label, peer_id=data["peer_id"],
                host=save_host, port=save_port,
                x25519_pub=data["x25519_pub"],
                ed25519_pub=data["ed25519_pub"]))
        self._refresh_sidebar()

    def _action_send_file(self) -> None:
        if not self.active:
            messagebox.showwarning("No active conversation",
                                    "Pick a peer first.", parent=self.root)
            return
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            messagebox.showinfo("Not supported",
                                 "File send to a group is not implemented.",
                                 parent=self.root)
            return
        path = filedialog.askopenfilename(parent=self.root, title="File to send")
        if not path:
            return
        peer_id = self.active

        async def _send() -> str | None:
            return await self.node.send_file(peer_id, path)

        future = self.bridge.submit_coro(_send())
        try:
            file_id = future.result(timeout=120.0)
        except Exception as e:
            messagebox.showerror("Send failed", str(e), parent=self.root)
            return
        if file_id is None:
            messagebox.showerror("Send failed",
                                  "Could not start the transfer.",
                                  parent=self.root)
            return
        self._append_chat(peer_id, "system",
                          f"  ⇡  sending {Path(path).name} "
                          f"(file_id {file_id[:16]}…)")

    def _action_backup(self) -> None:
        if self.salt_path is None:
            messagebox.showerror("Backup unavailable",
                                  "Salt path not configured.", parent=self.root)
            return
        try:
            data = self.salt_path.read_bytes()
        except OSError as e:
            messagebox.showerror("Backup failed", f"Cannot read salt: {e}",
                                  parent=self.root)
            return
        if len(data) != SALT_LEN:
            messagebox.showerror("Backup failed",
                                  f"Salt has wrong length: {len(data)}",
                                  parent=self.root)
            return
        words = salt_to_mnemonic(data).split()
        self._show_mnemonic_dialog(words)

    def _show_mnemonic_dialog(self, words: list[str]) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Recovery mnemonic")
        dlg.configure(bg=BG_BASE)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("560x460")

        # Heading + small seal
        head = tk.Frame(dlg, bg=BG_BASE)
        head.pack(fill=tk.X, padx=PAD_XL, pady=(PAD_XL, PAD_XS))
        seal = tk.Canvas(head, width=44, height=44, bg=BG_BASE,
                          highlightthickness=0, bd=0)
        seal.pack(side=tk.LEFT)
        draw_malphas_seal(seal, 22, 22, 18, ACCENT, FG_PRIMARY, ACCENT)
        title_box = tk.Frame(head, bg=BG_BASE)
        title_box.pack(side=tk.LEFT, padx=(PAD_MD, 0))
        tk.Label(title_box, text="Recovery mnemonic", bg=BG_BASE,
                  fg=FG_PRIMARY, font=self.f_h1).pack(anchor="w")
        tk.Label(title_box, text="The only way to recover this identity",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_small).pack(anchor="w")

        tk.Label(dlg, text="Write these 12 words down, in order. "
                            "Lose them and ~/.malphas/salt and you "
                            "lose this identity forever.",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_small,
                  wraplength=500, justify="left").pack(
                      anchor="w", padx=PAD_XL, pady=(PAD_LG, PAD_LG))

        grid = tk.Frame(dlg, bg=BG_RAISED)
        grid.pack(fill=tk.X, padx=PAD_XL, pady=PAD_SM)
        for i, word in enumerate(words):
            row, col = i % 6, i // 6
            tk.Label(grid, text=f"{i+1:>2}", bg=BG_RAISED, fg=FG_FAINT,
                      font=self.f_mono_sm).grid(
                          row=row, column=col*2, sticky="e",
                          padx=(PAD_LG, PAD_XS), pady=PAD_XS)
            tk.Label(grid, text=word, bg=BG_RAISED, fg=FG_PRIMARY,
                      font=self.f_mono).grid(
                          row=row, column=col*2+1, sticky="w",
                          padx=(PAD_XS, PAD_XL), pady=PAD_XS)

        tk.Label(dlg, text="Treat them like a password: do NOT screenshot, "
                            "do NOT paste into a chat.",
                  bg=BG_BASE, fg=WARN_AMBER, font=self.f_small,
                  wraplength=500, justify="left").pack(
                      anchor="w", padx=PAD_XL, pady=(PAD_LG, PAD_XS))

        btn_row = tk.Frame(dlg, bg=BG_BASE)
        btn_row.pack(fill=tk.X, padx=PAD_XL, pady=PAD_LG)
        ttk.Button(btn_row, text="Copy to clipboard", style="Ghost.TButton",
                    command=lambda: self._copy_words(dlg, words)).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Done", style="Accent.TButton",
                    command=dlg.destroy).pack(side=tk.RIGHT)

    def _copy_words(self, dlg: tk.Toplevel, words: list[str]) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(" ".join(words))
        messagebox.showwarning(
            "Mnemonic on clipboard",
            "The 12 words are now on your clipboard. Paste them somewhere "
            "safe, then clear the clipboard.",
            parent=dlg)

    def _action_panic(self) -> None:
        ok = messagebox.askyesno(
            "PANIC",
            "This wipes ALL in-memory state and exits immediately.\n"
            "The address book and salt files on disk are NOT touched.\n\n"
            "Continue?",
            parent=self.root, icon="warning")
        if not ok:
            return
        try:
            self.node.panic()
            self.book.wipe_memory()
        finally:
            self.bridge.stop(timeout=1.0)
            self.root.destroy()

    def _action_group_new(self) -> None:
        name = simpledialog.askstring("New group", "Group name:",
                                        parent=self.root)
        if not name:
            return

        async def _create() -> str | None:
            return await self.node.create_group(name, [])

        future = self.bridge.submit_coro(_create())
        try:
            gid = future.result(timeout=5.0)
        except Exception as e:
            messagebox.showerror("Group create failed", str(e),
                                  parent=self.root)
            return
        if gid is None:
            messagebox.showerror("Group create failed",
                                  "Name already in use, or empty name.",
                                  parent=self.root)
            return
        self._append_chat(gid, "system",
                          f"  ⊕  group '{name}' created  ({gid[:16]}…)")
        self._refresh_sidebar()

    def _action_group_add(self) -> None:
        if not self.active:
            messagebox.showwarning("No active group", "Pick a group first.",
                                    parent=self.root)
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            messagebox.showwarning("Not a group",
                                    "Active conversation is not a group.",
                                    parent=self.root)
            return
        target = simpledialog.askstring("Add member",
                                         "Peer label or peer_id:",
                                         parent=self.root)
        if not target:
            return
        contact = self.book.get(target)
        peer_id = contact.peer_id if contact else target

        async def _add() -> bool:
            return await self.node.add_group_member(group.group_id, peer_id)

        future = self.bridge.submit_coro(_add())
        try:
            ok = future.result(timeout=5.0)
        except Exception as e:
            messagebox.showerror("Add failed", str(e), parent=self.root)
            return
        if not ok:
            messagebox.showerror("Add failed",
                                  "Peer offline, cap reached, or unknown.",
                                  parent=self.root)
            return
        self._refresh_sidebar()

    def _action_group_leave(self) -> None:
        if not self.active:
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            return
        ok = messagebox.askyesno(
            "Leave group",
            f"Leave '{group.name}' locally?\n\n"
            "Other members will not be notified.",
            parent=self.root)
        if not ok:
            return
        self.node.leave_group(group.group_id)
        if self.active == group.group_id:
            self.active = None
            self._render_active()
        self._refresh_sidebar()

    def _action_about(self) -> None:
        from . import __version__
        dlg = tk.Toplevel(self.root)
        dlg.title("About malphas")
        dlg.configure(bg=BG_BASE)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("420x340")

        body = tk.Frame(dlg, bg=BG_BASE)
        body.pack(fill=tk.BOTH, expand=True, padx=PAD_XL, pady=PAD_XL)

        seal = tk.Canvas(body, width=120, height=120, bg=BG_BASE,
                          highlightthickness=0, bd=0)
        seal.pack(pady=(0, PAD_LG))
        draw_malphas_seal(seal, 60, 60, 50, ACCENT, FG_PRIMARY, ACCENT)

        tk.Label(body, text="malphas", bg=BG_BASE, fg=FG_PRIMARY,
                  font=self.f_h1).pack()
        tk.Label(body, text=f"version {__version__}", bg=BG_BASE,
                  fg=FG_MUTED, font=self.f_small).pack(pady=(0, PAD_MD))
        tk.Label(body, text="Privacy-first P2P messenger\nwith onion routing",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_body,
                  justify="center").pack()
        tk.Label(body, text=self.node.identity.peer_id, bg=BG_BASE,
                  fg=FG_FAINT, font=self.f_mono_sm,
                  wraplength=360).pack(pady=(PAD_LG, 0))

        ttk.Button(body, text="Close", style="Accent.TButton",
                    command=dlg.destroy).pack(pady=(PAD_LG, 0))

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def _wire_callbacks(self) -> None:
        q = self.event_queue

        def push(name: str, *args: Any) -> None:
            q.put((name, *args))

        self.node.on_message(lambda f, c: push("message", f, c))
        self.node.on_receipt(lambda mid, dst, ok: push("receipt", mid, dst, ok))
        self.node.on_pin_violation(lambda pid, ex, rcv: push("pin_violation", pid, ex, rcv))
        self.node.on_file_offer(lambda f, o: push("file_offer", f, o))
        self.node.on_file_complete(lambda fid, d: push("file_complete", fid, d))
        self.node.on_group_invite(
            lambda f, gid, gname, members: push("group_invite", f, gid, gname, members))
        self.node.on_group_message(
            lambda f, gid, gname, c: push("group_msg", f, gid, gname, c))

    def _on_quit(self) -> None:
        try:
            future = self.bridge.submit_coro(self.node.stop())
            try:
                future.result(timeout=3.0)
            except Exception:
                pass
            self.bridge.stop(timeout=2.0)
        finally:
            self.root.destroy()

    def run(self) -> None:
        async def _auto() -> None:
            for c in self.book.all():
                try:
                    await self.node.connect_to_peer(
                        c.host, c.port, c.peer_id,
                        bytes.fromhex(c.x25519_pub),
                        bytes.fromhex(c.ed25519_pub))
                except Exception:
                    pass

        self.bridge.submit_coro(_auto())
        self._refresh_sidebar()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._on_quit()


# ── Entry point ──────────────────────────────────────────────────────────────


def launch_gui(node: MalphasNode, book: AddressBook,
                bridge: AsyncBridge, salt_path: Path | None = None) -> None:
    """Build the GUI and enter the Tk mainloop. Blocks until the
    window closes or panic fires."""
    gui = MalphasGUI(node, book, bridge, salt_path=salt_path)
    gui.run()
