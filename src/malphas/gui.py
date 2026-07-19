"""
Tkinter desktop GUI for malphas.

Telegram/WhatsApp-flavored chat layout: bubble messages, circular
peer avatars, search-filtered sidebar, vector icon buttons (no
emoji), the malphas sigil PNG bundled as a package asset.

The asyncio loop that drives MalphasNode runs in a background daemon
thread (`AsyncBridge`). The Tk thread keeps the mainloop and polls a
`queue.Queue` every 50 ms to consume node-side callbacks.

Entry point: `launch_gui(node, book, bridge, recovery_mnemonic)`.
"""

from __future__ import annotations

import asyncio
import hashlib
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from concurrent.futures import Future
from importlib.resources import files
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from .addressbook import AddressBook, Contact
from .gui_icons import (
    IconButton,
    draw_alert,
    draw_copy,
    draw_door_out,
    draw_lock,
    draw_paperclip,
    draw_plus,
    draw_search,
    draw_send,
    draw_share,
    draw_user_plus,
    draw_users,
)
from .gui_theme import (
    ACCENT,
    ACCENT_DIM,
    ACCENT_GLOW,
    BG_ACTIVE,
    BG_BASE,
    BG_DIVIDER,
    BG_HOVER,
    BG_RAISED,
    BG_SURFACE,
    BUBBLE_SYS,
    BUBBLE_THEM,
    BUBBLE_YOU,
    FG_FAINT,
    FG_MUTED,
    FG_PRIMARY,
    INFO_CYAN,
    OK_GREEN,
    PAD_LG,
    PAD_MD,
    PAD_SM,
    PAD_XL,
    PAD_XS,
    WARN_AMBER,
)
from .invite import generate_invite, parse_invite
from .node import MalphasNode

# Avatar palette — distinct, well-saturated, hashed by peer_id.
AVATAR_PALETTE = [
    "#c44e4e", "#c47e4e", "#c4a44e", "#7eb84e", "#4eb88a",
    "#4e9bc4", "#4e72c4", "#7e4ec4", "#b84e9b", "#b8584e",
]

WIN_W = 1240
WIN_H = 800
SIDEBAR_W = 320

GITHUB_URL = "https://github.com/CristianDArrigo/malphas"


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


def _avatar_color(peer_id: str) -> str:
    """Deterministic color from peer_id hash."""
    h = hashlib.blake2s(peer_id.encode("utf-8"), digest_size=4).digest()
    idx = int.from_bytes(h, "big") % len(AVATAR_PALETTE)
    return AVATAR_PALETTE[idx]


def _avatar_initial(label: str) -> str:
    label = label.strip()
    if not label:
        return "?"
    return label[0].upper()


def _load_sigil() -> tk.PhotoImage | None:
    """Load the bundled malphas-sigil.png. Returns None if missing
    (e.g. installed without assets, dev tree without copy).

    Tk's PhotoImage accepts `file=` for a filesystem path (the typical
    editable install or wheel-on-disk case) and `data=` only for
    base64-encoded bytes. We prefer the file path; fall back to base64
    when the resource is virtual (zipapp / packaged wheel)."""
    import base64
    try:
        path = files("malphas").joinpath("assets/sigil.png")
        on_disk = str(path)
        try:
            if Path(on_disk).is_file():
                return tk.PhotoImage(file=on_disk)
        except Exception:
            pass
        # Resource lives inside a zip/wheel: read bytes, base64-encode,
        # hand to PhotoImage as data.
        with path.open("rb") as f:
            raw = f.read()
        return tk.PhotoImage(data=base64.b64encode(raw).decode("ascii"))
    except Exception:
        return None


def _scale_photo(img: tk.PhotoImage, target: int) -> tk.PhotoImage:
    """Subsample a PhotoImage to approximately `target` pixels per side."""
    src = img.width()
    if src <= 0 or target <= 0:
        return img
    factor = max(1, src // target)
    if factor > 1:
        return img.subsample(factor, factor)
    return img


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


# ── Avatar widget ────────────────────────────────────────────────────────────


class Avatar(tk.Canvas):
    """A circular avatar with a single-letter initial.

    Color derived deterministically from peer_id (or group_id).
    """

    def __init__(self, parent: tk.Misc, label: str, key: str,
                 size: int = 36, bg: str = BG_SURFACE,
                 font: tkfont.Font | None = None) -> None:
        super().__init__(parent, width=size, height=size, bg=bg,
                          highlightthickness=0, bd=0)
        color = _avatar_color(key)
        # Filled circle
        self.create_oval(2, 2, size - 2, size - 2, fill=color, outline="")
        # Initial
        f = font or tkfont.Font(family="TkDefaultFont",
                                  size=max(9, int(size * 0.40)),
                                  weight="bold")
        self.create_text(size / 2, size / 2,
                         text=_avatar_initial(label),
                         fill=FG_PRIMARY, font=f)


# ── Sidebar item ─────────────────────────────────────────────────────────────


class SidebarItem(tk.Frame):
    """A clickable conversation row: avatar + title/subtitle + unread.

    Hover and active states; left accent bar on active.
    """

    def __init__(
        self,
        parent: tk.Misc,
        kind: str,             # "peer" | "group"
        key: str,              # peer_id or group_id
        title: str,
        subtitle: str,
        unread: bool,
        on_click,
        font_body: tkfont.Font,
        font_small: tkfont.Font,
    ) -> None:
        super().__init__(parent, bg=BG_SURFACE, bd=0, highlightthickness=0)
        self._on_click = on_click
        self._active = False
        self._kind = kind
        self.key = key

        self._bar = tk.Frame(self, bg=BG_SURFACE, width=3)
        self._bar.pack(side=tk.LEFT, fill=tk.Y)

        self._inner = tk.Frame(self, bg=BG_SURFACE)
        self._inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                          padx=PAD_MD, pady=PAD_SM)

        # Avatar
        self._avatar = Avatar(self._inner, title, key, size=36, bg=BG_SURFACE)
        self._avatar.pack(side=tk.LEFT, padx=(0, PAD_MD))

        text_box = tk.Frame(self._inner, bg=BG_SURFACE)
        text_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        title_row = tk.Frame(text_box, bg=BG_SURFACE)
        title_row.pack(fill=tk.X)
        self._title = tk.Label(title_row, text=title, bg=BG_SURFACE,
                                fg=FG_PRIMARY, font=font_body, anchor="w")
        self._title.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Group tag (small "GROUP" badge for group rows)
        if kind == "group":
            tk.Label(title_row, text="GROUP", bg=BG_SURFACE, fg=INFO_CYAN,
                      font=font_small).pack(side=tk.RIGHT)

        self._sub = tk.Label(text_box, text=subtitle, bg=BG_SURFACE,
                              fg=FG_FAINT, font=font_small, anchor="w")
        self._sub.pack(fill=tk.X)

        # Unread badge container (to the right of the avatar/text row)
        self._badge_text = tk.StringVar(value="●" if unread else "")
        self._badge = tk.Label(self._inner, textvariable=self._badge_text,
                                bg=BG_SURFACE,
                                fg=ACCENT if unread else BG_SURFACE,
                                font=font_small)
        self._badge.pack(side=tk.RIGHT)

        # Bind click + hover on every leaf
        self._bind_recursive(self)

    def _bind_recursive(self, w: tk.Misc) -> None:
        w.bind("<Button-1>", self._click)
        w.bind("<Enter>", self._enter)
        w.bind("<Leave>", self._leave)
        for child in w.winfo_children():
            self._bind_recursive(child)

    def _bg(self, color: str) -> None:
        for w in (self, self._inner, self._title, self._sub, self._badge,
                  self._avatar):
            try:
                w.configure(bg=color)
            except tk.TclError:
                pass
        # text_box
        try:
            self._title.master.configure(bg=color)
        except tk.TclError:
            pass
        try:
            self._title.master.master.configure(bg=color)
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


# ── Message bubble ───────────────────────────────────────────────────────────


class MessageBubble(tk.Frame):
    """A single chat bubble — left for them, right for you, full-width
    for system. Includes timestamp under the bubble.
    """

    def __init__(
        self,
        parent: tk.Misc,
        sender: str,           # display name (or "" for system)
        body: str,
        kind: str,             # "you" | "them" | "system"
        font_body: tkfont.Font,
        font_small: tkfont.Font,
        color: str | None = None,
        avatar_key: str | None = None,
    ) -> None:
        super().__init__(parent, bg=BG_RAISED)

        if kind == "system":
            row = tk.Frame(self, bg=BG_RAISED)
            row.pack(fill=tk.X, pady=(PAD_SM, PAD_SM))
            inner = tk.Frame(row, bg=BUBBLE_SYS)
            inner.pack(anchor="center")
            tk.Label(inner, text=body, bg=BUBBLE_SYS,
                      fg=FG_MUTED, font=font_small,
                      padx=PAD_MD, pady=PAD_XS).pack()
            return

        is_self = (kind == "you")
        bubble_bg = BUBBLE_YOU if is_self else BUBBLE_THEM
        align = "e" if is_self else "w"

        row = tk.Frame(self, bg=BG_RAISED)
        row.pack(fill=tk.X, padx=PAD_LG, pady=(PAD_XS, 0))

        # Avatar on the left for "them"; we omit it for "you" to keep
        # outgoing aligned right.
        if not is_self and avatar_key:
            av = Avatar(row, sender, avatar_key, size=32, bg=BG_RAISED)
            av.pack(side=tk.LEFT, anchor="n", padx=(0, PAD_SM))

        bubble_wrap = tk.Frame(row, bg=BG_RAISED)
        bubble_wrap.pack(side=tk.RIGHT if is_self else tk.LEFT,
                          anchor=align, fill=tk.NONE, expand=False)

        bubble = tk.Frame(bubble_wrap, bg=bubble_bg)
        bubble.pack(anchor=align)

        # Sender name (for them, or for groups where color hint helps)
        if not is_self and sender:
            tk.Label(bubble, text=sender, bg=bubble_bg,
                      fg=color or ACCENT, font=font_small,
                      padx=PAD_MD, pady=(PAD_XS, 0),
                      anchor="w").pack(fill=tk.X)

        # Body. Use a Label with wraplength so long messages wrap.
        body_label = tk.Label(bubble, text=body, bg=bubble_bg,
                               fg=FG_PRIMARY, font=font_body,
                               wraplength=560, justify="left",
                               padx=PAD_MD,
                               pady=PAD_SM if not (sender and not is_self) else PAD_XS,
                               anchor="w")
        body_label.pack(fill=tk.X)

        # Timestamp under the bubble
        ts_label = tk.Label(bubble_wrap, text=_ts(), bg=BG_RAISED,
                             fg=FG_FAINT, font=font_small)
        ts_label.pack(anchor=align, padx=PAD_XS, pady=(2, 0))


# ── Scrollable chat container ────────────────────────────────────────────────


class ChatPane(tk.Frame):
    """A vertically scrollable list of widgets (MessageBubble instances).

    Built on a Canvas + inner Frame so we can pack arbitrary widgets
    (not just text rows) and they all scroll together.
    """

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, bg=BG_RAISED)
        self._canvas = tk.Canvas(self, bg=BG_RAISED, highlightthickness=0,
                                  bd=0)
        self._sb = ttk.Scrollbar(self, orient="vertical",
                                  command=self._canvas.yview,
                                  style="Vertical.TScrollbar")
        self._canvas.configure(yscrollcommand=self._sb.set)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.inner = tk.Frame(self._canvas, bg=BG_RAISED)
        self._win = self._canvas.create_window((0, 0), window=self.inner,
                                                 anchor="nw")

        self._canvas.bind("<Configure>", self._on_canvas_resize)
        self.inner.bind("<Configure>", self._on_inner_resize)

        self._canvas.bind(
            "<Enter>",
            lambda e: self._canvas.bind_all("<MouseWheel>", self._on_wheel),
        )
        self._canvas.bind(
            "<Leave>",
            lambda e: self._canvas.unbind_all("<MouseWheel>"),
        )
        # Linux: Button-4/5
        self._canvas.bind(
            "<Enter>",
            lambda e: (
                self._canvas.bind_all("<MouseWheel>", self._on_wheel),
                self._canvas.bind_all("<Button-4>",
                                       lambda ev: self._canvas.yview_scroll(-1, "units")),
                self._canvas.bind_all("<Button-5>",
                                       lambda ev: self._canvas.yview_scroll(1, "units")),
            ),
            add="+",
        )

    def _on_canvas_resize(self, event: tk.Event) -> None:
        self._canvas.itemconfigure(self._win, width=event.width)

    def _on_inner_resize(self, _event: object) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_wheel(self, event: tk.Event) -> None:
        try:
            self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass

    def clear(self) -> None:
        for child in self.inner.winfo_children():
            child.destroy()

    def add_widget(self, w: tk.Misc) -> None:
        w.pack(fill=tk.X)
        self.scroll_to_end()

    def scroll_to_end(self) -> None:
        self.update_idletasks()
        self._canvas.yview_moveto(1.0)


# ── MalphasGUI ───────────────────────────────────────────────────────────────


class MalphasGUI:
    def __init__(
        self,
        node: MalphasNode,
        book: AddressBook,
        bridge: AsyncBridge,
        recovery_mnemonic: str | None = None,
    ) -> None:
        self.node = node
        self.book = book
        self.bridge = bridge
        self.recovery_mnemonic = recovery_mnemonic
        self.active: str | None = None
        # Per-conversation list of (kind, sender, body, color, ts) tuples,
        # so we can re-render the chat pane on selection switch.
        self._scrollback: dict[str, list[dict[str, Any]]] = {}
        self._pending_offers: dict[str, tuple[str, dict]] = {}
        self._completed_files: dict[str, tuple[str, str, bytes]] = {}
        self._unread: set[str] = set()
        self._sidebar_items: dict[str, SidebarItem] = {}
        self._search_query = ""
        self.event_queue: queue.Queue = queue.Queue()

        self.root = tk.Tk()
        self.root.title(f"malphas — {_short(node.identity.peer_id, 16)}")
        self.root.geometry(f"{WIN_W}x{WIN_H}")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG_BASE)
        self.root.protocol("WM_DELETE_WINDOW", self._on_quit)

        self._init_fonts()
        self._setup_style()
        self._sigil_full = _load_sigil()
        # Pre-scaled images for the various spots that show the sigil.
        self._sigil_header = _scale_photo(self._sigil_full, 28) if self._sigil_full else None
        self._sigil_empty  = _scale_photo(self._sigil_full, 180) if self._sigil_full else None
        self._sigil_dialog = _scale_photo(self._sigil_full, 110) if self._sigil_full else None

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
        self.f_h1    = tkfont.Font(family=sans, size=15, weight="bold")
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
        s.configure("Search.TEntry", fieldbackground=BG_HOVER,
                    foreground=FG_PRIMARY, insertcolor=ACCENT,
                    borderwidth=0, padding=(PAD_MD, PAD_SM),
                    font=self.f_body)

        s.configure("Vertical.TScrollbar", background=BG_SURFACE,
                    troughcolor=BG_SURFACE, borderwidth=0, arrowsize=12)
        s.map("Vertical.TScrollbar",
              background=[("active", BG_RAISED), ("pressed", ACCENT_DIM)])

    # ── UI build ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_menubar()
        self._build_header()

        body = tk.Frame(self.root, bg=BG_BASE)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_main(body)

        self._build_statusbar()

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self.root, bg=BG_SURFACE, fg=FG_PRIMARY,
                          activebackground=ACCENT_DIM, activeforeground=FG_PRIMARY,
                          borderwidth=0, font=self.f_body)
        self.root.config(menu=menubar)

        def mk(parent: tk.Menu) -> tk.Menu:
            return tk.Menu(parent, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                            activebackground=ACCENT_DIM,
                            activeforeground=FG_PRIMARY, font=self.f_body)

        m_file = mk(menubar)
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

        m_view = mk(menubar)
        m_view.add_command(label="Refresh peer list",
                           command=self._refresh_sidebar, accelerator="F5")
        menubar.add_cascade(label="View", menu=m_view)

        m_group = mk(menubar)
        m_group.add_command(label="Create new group…",
                            command=self._action_group_new)
        m_group.add_command(label="Add member to active group…",
                            command=self._action_group_add)
        m_group.add_command(label="Leave active group",
                            command=self._action_group_leave)
        menubar.add_cascade(label="Group", menu=m_group)

        m_help = mk(menubar)
        m_help.add_command(label="About malphas", command=self._action_about)
        m_help.add_command(label="Open GitHub repo",
                           command=lambda: webbrowser.open(GITHUB_URL))
        menubar.add_cascade(label="Help", menu=m_help)

        self.root.bind("<Control-e>", lambda e: self._action_export())
        self.root.bind("<Control-i>", lambda e: self._action_import())
        self.root.bind("<Control-q>", lambda e: self._on_quit())
        self.root.bind("<F5>", lambda e: self._refresh_sidebar())

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=BG_SURFACE, height=64)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # Left: sigil + brand + peer_id
        left = tk.Frame(header, bg=BG_SURFACE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(PAD_LG, 0))

        if self._sigil_header is not None:
            tk.Label(left, image=self._sigil_header, bg=BG_SURFACE
                      ).pack(side=tk.LEFT, pady=PAD_MD)
        text_box = tk.Frame(left, bg=BG_SURFACE)
        text_box.pack(side=tk.LEFT, padx=(PAD_MD, 0), pady=PAD_MD)
        tk.Label(text_box, text="malphas", bg=BG_SURFACE, fg=FG_PRIMARY,
                  font=self.f_h1).pack(anchor="w")
        tk.Label(text_box, text=_short(self.node.identity.peer_id, 16),
                  bg=BG_SURFACE, fg=FG_MUTED, font=self.f_mono_sm
                  ).pack(anchor="w")

        # Right: lock icon (security indicator) + counters + dot
        right = tk.Frame(header, bg=BG_SURFACE)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, PAD_LG))

        rwrap = tk.Frame(right, bg=BG_SURFACE)
        rwrap.pack(side=tk.RIGHT, pady=PAD_MD)

        # Connection status dot
        self.dot = tk.Label(rwrap, text="●", bg=BG_SURFACE, fg=FG_FAINT,
                             font=self.f_body)
        self.dot.pack(side=tk.RIGHT, padx=(PAD_SM, 0))

        # Counters
        self.header_status_var = tk.StringVar()
        tk.Label(rwrap, textvariable=self.header_status_var,
                  bg=BG_SURFACE, fg=FG_MUTED, font=self.f_small
                  ).pack(side=tk.RIGHT, padx=(0, PAD_SM))

        # Tor lock indicator (only shown if we're on .onion)
        self._lock_btn = IconButton(
            rwrap, drawer=draw_lock, on_click=lambda: None,
            size=34, bg=BG_SURFACE, hover_bg=BG_SURFACE,
            color=OK_GREEN, hover_color=OK_GREEN,
            variant="ghost",
            tooltip="end-to-end encrypted",
        )
        self._lock_btn.pack(side=tk.RIGHT, padx=(0, PAD_SM))

        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

    def _build_sidebar(self, parent: tk.Misc) -> None:
        sidebar = tk.Frame(parent, bg=BG_SURFACE, width=SIDEBAR_W)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Search row
        search_wrap = tk.Frame(sidebar, bg=BG_SURFACE)
        search_wrap.pack(fill=tk.X, padx=PAD_MD, pady=(PAD_MD, PAD_SM))

        # Search icon (left of entry)
        search_icon = tk.Canvas(search_wrap, width=34, height=34,
                                  bg=BG_HOVER, highlightthickness=0, bd=0)
        search_icon.pack(side=tk.LEFT, fill=tk.Y, ipady=PAD_XS)
        draw_search(search_icon, 4, 4, 26, FG_MUTED)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        search_entry = ttk.Entry(search_wrap, textvariable=self.search_var,
                                  style="Search.TEntry")
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=PAD_XS)

        # Action buttons row
        actions = tk.Frame(sidebar, bg=BG_SURFACE)
        actions.pack(fill=tk.X, padx=PAD_MD, pady=(0, PAD_SM))

        IconButton(actions, drawer=draw_share, on_click=self._action_export,
                   size=46, bg=BG_SURFACE, hover_bg=BG_HOVER,
                   color=FG_MUTED, hover_color=FG_PRIMARY,
                   tooltip="Generate invite").pack(side=tk.LEFT, padx=(0, PAD_XS))
        IconButton(actions, drawer=draw_plus, on_click=self._action_import,
                   size=46, bg=BG_SURFACE, hover_bg=BG_HOVER,
                   color=FG_MUTED, hover_color=FG_PRIMARY,
                   tooltip="Import invite from clipboard"
                   ).pack(side=tk.LEFT, padx=(0, PAD_XS))
        IconButton(actions, drawer=draw_users, on_click=self._action_group_new,
                   size=46, bg=BG_SURFACE, hover_bg=BG_HOVER,
                   color=FG_MUTED, hover_color=FG_PRIMARY,
                   tooltip="Create new group").pack(side=tk.LEFT)

        # Conversations list (scrollable)
        scroll_wrap = tk.Frame(sidebar, bg=BG_SURFACE)
        scroll_wrap.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(scroll_wrap, bg=BG_SURFACE, highlightthickness=0,
                            bd=0)
        sb = ttk.Scrollbar(scroll_wrap, orient="vertical",
                            command=canvas.yview,
                            style="Vertical.TScrollbar")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self._sidebar_canvas = canvas
        self._sidebar_inner = tk.Frame(canvas, bg=BG_SURFACE)
        self._sidebar_window = canvas.create_window(
            (0, 0), window=self._sidebar_inner, anchor="nw"
        )

        canvas.bind("<Configure>",
                     lambda e: canvas.itemconfigure(self._sidebar_window,
                                                     width=e.width))
        self._sidebar_inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind("<Enter>",
                     lambda e: canvas.bind_all("<MouseWheel>",
                                                 self._on_sidebar_wheel))
        canvas.bind("<Leave>",
                     lambda e: canvas.unbind_all("<MouseWheel>"))

        # Vertical divider on the right edge
        tk.Frame(parent, width=1, bg=BG_DIVIDER).pack(side=tk.LEFT, fill=tk.Y)

    def _on_sidebar_wheel(self, event: tk.Event) -> None:
        try:
            self._sidebar_canvas.yview_scroll(int(-1 * (event.delta / 120)),
                                                "units")
        except tk.TclError:
            pass

    def _on_search_change(self, *args: object) -> None:
        self._search_query = self.search_var.get().strip().lower()
        self._refresh_sidebar()

    def _build_main(self, parent: tk.Misc) -> None:
        main = tk.Frame(parent, bg=BG_BASE)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Conversation header (peer / group title bar)
        self.conv_header = tk.Frame(main, bg=BG_SURFACE, height=64)
        self.conv_header.pack(fill=tk.X, side=tk.TOP)
        self.conv_header.pack_propagate(False)

        self.conv_header_inner = tk.Frame(self.conv_header, bg=BG_SURFACE)
        self.conv_header_inner.pack(fill=tk.BOTH, expand=True,
                                     padx=PAD_LG, pady=PAD_SM)

        tk.Frame(main, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

        # Chat area: ChatPane + empty-state overlay
        self.chat_area = tk.Frame(main, bg=BG_RAISED)
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        self.chat_pane = ChatPane(self.chat_area)
        self.chat_pane.pack(fill=tk.BOTH, expand=True)

        # Empty-state overlay (Frame above the ChatPane)
        self.empty_frame = tk.Frame(self.chat_area, bg=BG_RAISED)
        if self._sigil_empty is not None:
            tk.Label(self.empty_frame, image=self._sigil_empty, bg=BG_RAISED
                      ).pack(pady=(PAD_XL * 2, PAD_LG))
        tk.Label(self.empty_frame, text="malphas", bg=BG_RAISED,
                  fg=FG_MUTED, font=self.f_h1).pack()
        tk.Label(self.empty_frame, text="pick a conversation, "
                                          "or import an invite to start",
                  bg=BG_RAISED, fg=FG_FAINT, font=self.f_body
                  ).pack(pady=(PAD_XS, 0))
        self._show_empty(True)

        # Input row at the bottom
        tk.Frame(main, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.BOTTOM)
        input_wrap = tk.Frame(main, bg=BG_SURFACE)
        input_wrap.pack(fill=tk.X, side=tk.BOTTOM)

        input_inner = tk.Frame(input_wrap, bg=BG_SURFACE)
        input_inner.pack(fill=tk.X, padx=PAD_LG, pady=PAD_MD)

        # File button (left)
        IconButton(input_inner, drawer=draw_paperclip,
                   on_click=self._action_send_file,
                   size=52, bg=BG_SURFACE, hover_bg=BG_HOVER,
                   color=FG_MUTED, hover_color=FG_PRIMARY,
                   tooltip="Send a file").pack(side=tk.LEFT, padx=(0, PAD_SM))

        # Entry container (rounded look via bg + padding)
        entry_wrap = tk.Frame(input_inner, bg=BG_RAISED)
        entry_wrap.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, PAD_SM))
        self.input_var = tk.StringVar()
        self.entry = tk.Entry(entry_wrap, textvariable=self.input_var,
                                bg=BG_RAISED, fg=FG_PRIMARY,
                                insertbackground=ACCENT,
                                relief=tk.FLAT, font=self.f_body, bd=0,
                                highlightthickness=0)
        self.entry.pack(fill=tk.X, padx=PAD_MD, pady=PAD_SM, ipady=4)
        self.entry.bind("<Return>", self._on_send)

        # Send button (right, accent variant)
        IconButton(input_inner, drawer=draw_send,
                   on_click=self._on_send,
                   size=52, bg=ACCENT, hover_bg=ACCENT,
                   accent_bg=ACCENT, accent_hover=ACCENT_GLOW,
                   color=FG_PRIMARY, hover_color=FG_PRIMARY,
                   accent_color=FG_PRIMARY,
                   variant="accent",
                   tooltip="Send (Enter)").pack(side=tk.LEFT)

    def _build_statusbar(self) -> None:
        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status_var,
                  style="Status.TLabel", anchor="w").pack(side=tk.BOTTOM, fill=tk.X)
        self._set_status()

    def _show_empty(self, on: bool) -> None:
        if on:
            self.empty_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        else:
            self.empty_frame.place_forget()

    # ── Conversation header ─────────────────────────────────────────────────

    def _redraw_conv_header(self) -> None:
        for child in self.conv_header_inner.winfo_children():
            child.destroy()
        if not self.active:
            tk.Label(self.conv_header_inner, text="No conversation selected",
                      bg=BG_SURFACE, fg=FG_MUTED, font=self.f_h2,
                      anchor="w").pack(side=tk.LEFT)
            return

        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            label = group.name
            sub = (f"group · {group.member_count()} members · "
                   f"{_short(group.group_id, 16)}")
            avatar_key = group.group_id
        else:
            contact = self.book.get_by_peer_id(self.active)
            label = contact.label if contact else "(unsaved peer)"
            sub = _short(self.active, 32)
            avatar_key = self.active

        # Avatar
        Avatar(self.conv_header_inner, label, avatar_key, size=44,
                bg=BG_SURFACE).pack(side=tk.LEFT, padx=(0, PAD_MD))

        # Title + sub
        text_box = tk.Frame(self.conv_header_inner, bg=BG_SURFACE)
        text_box.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(text_box, text=label, bg=BG_SURFACE, fg=FG_PRIMARY,
                  font=self.f_h2, anchor="w").pack(anchor="w")
        tk.Label(text_box, text=sub, bg=BG_SURFACE, fg=FG_MUTED,
                  font=self.f_mono_sm, anchor="w").pack(anchor="w")

        # Right side: group action buttons (only when active is group)
        if group is not None:
            right = tk.Frame(self.conv_header_inner, bg=BG_SURFACE)
            right.pack(side=tk.RIGHT, fill=tk.Y)
            IconButton(right, drawer=draw_user_plus,
                        on_click=self._action_group_add,
                        size=44, bg=BG_SURFACE, hover_bg=BG_HOVER,
                        color=FG_MUTED, hover_color=FG_PRIMARY,
                        tooltip="Add member to group"
                        ).pack(side=tk.LEFT, padx=(PAD_XS, 0))
            IconButton(right, drawer=draw_door_out,
                        on_click=self._action_group_leave,
                        size=44, bg=BG_SURFACE, hover_bg=BG_HOVER,
                        color=FG_MUTED, hover_color=FG_PRIMARY,
                        tooltip="Leave group").pack(side=tk.LEFT, padx=(PAD_XS, 0))

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
            ok = ev[3]
            self._add_system(ev[2],
                             "delivered" if ok else "no receipt",
                             icon=draw_send if ok else draw_alert,
                             color=OK_GREEN if ok else WARN_AMBER)
        elif kind == "pin_violation":
            messagebox.showerror("Key mismatch",
                f"Pinned key mismatch for {_short(ev[1], parent=self.root)}.\n"
                f"Expected {ev[2][:16]}…\nReceived {ev[3][:16]}…\n\n"
                "Connection rejected. Use /trust via CLI.")
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
        is_tor = onion.endswith(".onion")
        tor_marker = "  ·  tor" if is_tor else ""
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
        # Wipe
        for child in self._sidebar_inner.winfo_children():
            child.destroy()
        self._sidebar_items = {}

        q = self._search_query

        def matches(*fields: str) -> bool:
            if not q:
                return True
            return any(q in f.lower() for f in fields if f)

        peers_added = 0
        seen: set[str] = set()
        for c in self.book.all():
            if not matches(c.label, c.peer_id):
                continue
            seen.add(c.peer_id)
            sub = _short(c.peer_id, 18)
            item = SidebarItem(
                self._sidebar_inner, kind="peer", key=c.peer_id,
                title=c.label, subtitle=sub,
                unread=c.peer_id in self._unread,
                on_click=lambda pid=c.peer_id: self._select(pid),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[c.peer_id] = item
            peers_added += 1

        for p in self.node.discovery.all_peers():
            pid = p["peer_id"]
            if pid in seen:
                continue
            if not matches(pid):
                continue
            item = SidebarItem(
                self._sidebar_inner, kind="peer", key=pid,
                title=_short(pid, 12), subtitle="(unsaved)",
                unread=pid in self._unread,
                on_click=lambda x=pid: self._select(x),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[pid] = item
            peers_added += 1

        groups_added = 0
        for g in self.node._groups.all_groups():
            if not matches(g.name, g.group_id):
                continue
            item = SidebarItem(
                self._sidebar_inner, kind="group", key=g.group_id,
                title=g.name,
                subtitle=f"{g.member_count()} members",
                unread=g.group_id in self._unread,
                on_click=lambda gid=g.group_id: self._select(gid),
                font_body=self.f_body, font_small=self.f_mono_sm,
            )
            item.pack(fill=tk.X)
            self._sidebar_items[g.group_id] = item
            groups_added += 1

        if peers_added == 0 and groups_added == 0:
            empty_text = ("No matches" if q else
                          "No conversations yet.\nImport an invite to start.")
            tk.Label(self._sidebar_inner, text=empty_text, bg=BG_SURFACE,
                      fg=FG_FAINT, font=self.f_small, justify="center"
                      ).pack(pady=PAD_XL, padx=PAD_LG)

        if self.active and self.active in self._sidebar_items:
            self._sidebar_items[self.active].set_active(True)

    def _select(self, key: str) -> None:
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
        self._redraw_conv_header()
        self.chat_pane.clear()
        if not self.active:
            self._show_empty(True)
            return
        self._show_empty(False)
        for entry in self._scrollback.get(self.active, []):
            self._render_entry(entry)
        self.chat_pane.scroll_to_end()
        self._set_status()

    def _render_entry(self, entry: dict) -> None:
        kind = entry["kind"]
        if kind == "system":
            bubble = MessageBubble(self.chat_pane.inner,
                                    sender="", body=entry["body"],
                                    kind="system",
                                    font_body=self.f_body,
                                    font_small=self.f_small)
        else:
            bubble = MessageBubble(
                self.chat_pane.inner,
                sender=entry["sender"],
                body=entry["body"],
                kind=kind,
                font_body=self.f_body,
                font_small=self.f_small,
                color=entry.get("color"),
                avatar_key=entry.get("avatar_key"),
            )
        self.chat_pane.add_widget(bubble)

    # ── Append helpers ──────────────────────────────────────────────────────

    def _record(self, conv_key: str, entry: dict) -> None:
        self._scrollback.setdefault(conv_key, []).append(entry)
        if conv_key == self.active:
            self._render_entry(entry)

    def _add_message(self, conv_key: str, sender: str, body: str,
                      is_self: bool, avatar_key: str | None = None,
                      color: str | None = None) -> None:
        entry = {
            "kind": "you" if is_self else "them",
            "sender": sender,
            "body": body,
            "avatar_key": avatar_key or conv_key,
            "color": color,
        }
        self._record(conv_key, entry)

    def _add_system(self, conv_key: str, body: str,
                     icon=None, color: str | None = None) -> None:
        self._record(conv_key, {"kind": "system", "body": body})

    # ── Send ────────────────────────────────────────────────────────────────

    def _on_send(self, event: object | None = None) -> None:
        text = self.input_var.get().strip()
        if not text or not self.active:
            return
        self.input_var.set("")
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            self.bridge.submit_coro(
                self.node.send_group_message(group.group_id, text)
            )
            self._add_message(self.active, "you", text, is_self=True)
        else:
            self.bridge.submit_coro(self.node.send_message(self.active, text))
            self._add_message(self.active, "you", text, is_self=True)

    # ── Node-callback handlers ─────────────────────────────────────────────

    def _conv_label(self, peer_id: str) -> str:
        contact = self.book.get_by_peer_id(peer_id)
        return contact.label if contact else _short(peer_id, 12)

    def _on_msg(self, from_id: str, content: str) -> None:
        label = self._conv_label(from_id)
        self._add_message(from_id, label, content, is_self=False,
                           avatar_key=from_id,
                           color=_avatar_color(from_id))
        if self.active != from_id:
            self._unread.add(from_id)
            self._refresh_sidebar()

    def _on_file_offer(self, from_id: str, offer: dict) -> None:
        fid = offer.get("file_id", "")
        if not fid:
            return
        self._pending_offers[fid] = (from_id, offer)
        label = self._conv_label(from_id)
        ok = messagebox.askyesno("Incoming file",
            f"{label} wants to send '{offer.get('name', parent=self.root)}'\n"
            f"({offer.get('size')} bytes).\n\nAccept?")
        if ok:
            self.node.accept_file_offer(offer)
            self._add_system(from_id,
                              f"accepting {offer.get('name')} from {label}")
        else:
            self._pending_offers.pop(fid, None)

    def _on_file_complete(self, file_id: str, data: bytes) -> None:
        offer_entry = self._pending_offers.pop(file_id, None)
        from_id = offer_entry[0] if offer_entry else "?"
        name = offer_entry[1].get("name", "file.bin") if offer_entry else "file.bin"
        self._completed_files[file_id] = (from_id, name, data)
        label = self._conv_label(from_id) if from_id != "?" else "?"
        self._add_system(from_id,
                          f"received {name} ({len(data)} bytes) from {label}")

        path = filedialog.asksaveasfilename(parent=self.root, initialfile=name,
                                             title=f"Save '{name}' as…")
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                self._add_system(from_id, f"saved to {path}")
                self._completed_files.pop(file_id, None)
            except OSError as e:
                messagebox.showerror("Save failed", str(e, parent=self.root))

    def _on_group_invite(self, from_id: str, group_id: str, group_name: str,
                          members: list) -> None:
        label = self._conv_label(from_id)
        self._add_system(group_id,
                          f"{label} added you to '{group_name}' "
                          f"({len(members)} members)")
        self._refresh_sidebar()

    def _on_group_msg(self, from_id: str, group_id: str, group_name: str,
                       content: str) -> None:
        label = self._conv_label(from_id)
        self._add_message(group_id, label, content, is_self=False,
                           avatar_key=from_id,
                           color=_avatar_color(from_id))
        if self.active != group_id:
            self._unread.add(group_id)
            self._refresh_sidebar()

    # ── Menu actions ────────────────────────────────────────────────────────

    def _action_export(self) -> None:
        host = self.node.public_address
        port = self.node.port
        onion = self.node.transport.public_address \
            if self.node.transport.public_address \
            and self.node.transport.public_address.endswith(".onion") else None
        url = generate_invite(
            self.node.identity, host, port, onion=onion,
            spk=self.node.signed_prekey_pub,
            opks=self.node.one_time_prekeys_pub)
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        messagebox.showinfo("Invite copied",
            "A signed malphas:// invite is on your clipboard.\n"
            "Send it to the peer over a channel you trust.", parent=self.root)

    def _action_import(self) -> None:
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Clipboard empty", "Nothing to import.", parent=self.root)
            return
        try:
            data = parse_invite(text)
        except ValueError as e:
            messagebox.showerror("Invalid invite", str(e, parent=self.root))
            return

        if data["peer_id"] == self.node.identity.peer_id:
            messagebox.showerror(
                "That's your own invite",
                "You can't add yourself as a contact. Share this invite "
                "with someone else to start a conversation.",
                parent=self.root,
            )
            return

        ok = messagebox.askyesno(
            "Import invite",
            f"Connect to peer_id\n\n{_short(data['peer_id'], 24)}\n\n"
            f"at {data.get('host')}:{data.get('port')}?",
            parent=self.root,
        )
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
            messagebox.showerror("Connection failed", str(e, parent=self.root))
            return
        if not success:
            messagebox.showerror("Connection failed", "Could not reach the peer.", parent=self.root)
            return

        label = simpledialog.askstring("Save to address book", "Label (leave empty to skip, parent=self.root):")
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
                                 "File send to a group is not implemented.", parent=self.root)
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
            messagebox.showerror("Send failed", str(e, parent=self.root))
            return
        if file_id is None:
            messagebox.showerror("Send failed",
                                  "Could not start the transfer.", parent=self.root)
            return
        self._add_system(peer_id,
                          f"sending {Path(path).name} "
                          f"(file_id {file_id[:16]}…)")

    def _action_backup(self) -> None:
        if not self.recovery_mnemonic:
            messagebox.showerror("Backup unavailable",
                                  "Recovery mnemonic not available.", parent=self.root)
            return
        self._show_mnemonic_dialog(self.recovery_mnemonic.split())

    def _show_mnemonic_dialog(self, words: list[str]) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Recovery mnemonic")
        dlg.configure(bg=BG_BASE)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("580x500")

        head = tk.Frame(dlg, bg=BG_BASE)
        head.pack(fill=tk.X, padx=PAD_XL, pady=(PAD_XL, PAD_XS))
        if self._sigil_dialog is not None:
            tk.Label(head, image=self._sigil_dialog, bg=BG_BASE
                      ).pack(side=tk.LEFT)
        title_box = tk.Frame(head, bg=BG_BASE)
        title_box.pack(side=tk.LEFT, padx=(PAD_LG, 0))
        tk.Label(title_box, text="Recovery mnemonic", bg=BG_BASE,
                  fg=FG_PRIMARY, font=self.f_h1).pack(anchor="w")
        tk.Label(title_box, text="The only way to recover this identity",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_small).pack(anchor="w")

        tk.Label(dlg, text="Write these 24 words down, in order. "
                            "Lose them and ~/.malphas/identity and you "
                            "lose this identity forever.",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_small,
                  wraplength=520, justify="left").pack(
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
                  wraplength=520, justify="left").pack(
                      anchor="w", padx=PAD_XL, pady=(PAD_LG, PAD_XS))

        btn_row = tk.Frame(dlg, bg=BG_BASE)
        btn_row.pack(fill=tk.X, padx=PAD_XL, pady=PAD_LG)

        copy_wrap = tk.Frame(btn_row, bg=BG_BASE)
        copy_wrap.pack(side=tk.LEFT)
        IconButton(copy_wrap, drawer=draw_copy,
                    on_click=lambda: self._copy_words(dlg, words),
                    size=48, bg=BG_BASE, hover_bg=BG_HOVER,
                    color=FG_MUTED, hover_color=FG_PRIMARY,
                    tooltip="Copy mnemonic to clipboard"
                    ).pack(side=tk.LEFT)
        tk.Label(copy_wrap, text=" copy", bg=BG_BASE, fg=FG_MUTED,
                  font=self.f_body).pack(side=tk.LEFT)

        ttk.Button(btn_row, text="Done", style="Accent.TButton",
                    command=dlg.destroy).pack(side=tk.RIGHT)

    def _copy_words(self, dlg: tk.Toplevel, words: list[str]) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(" ".join(words))
        messagebox.showwarning(
            "Mnemonic on clipboard",
            "The 12 words are now on your clipboard. Paste them somewhere "
            "safe, then clear the clipboard.",
            parent=dlg,
        )

    def _action_panic(self) -> None:
        ok = messagebox.askyesno(
            "PANIC",
            "This wipes ALL in-memory state and exits immediately.\n"
            "The address book, identity and pin files on disk are NOT touched.\n\n"
            "Continue?",
            parent=self.root, icon="warning",
        )
        if not ok:
            return
        try:
            self.node.panic()
            self.book.wipe_memory()
        finally:
            self.bridge.stop(timeout=1.0)
            self.root.destroy()

    def _action_group_new(self) -> None:
        name = simpledialog.askstring("New group", "Group name:", parent=self.root)
        if not name:
            return

        async def _create() -> str | None:
            return await self.node.create_group(name, [])

        future = self.bridge.submit_coro(_create())
        try:
            gid = future.result(timeout=5.0)
        except Exception as e:
            messagebox.showerror("Group create failed", str(e, parent=self.root))
            return
        if gid is None:
            messagebox.showerror("Group create failed",
                                  "Name already in use, or empty name.", parent=self.root)
            return
        self._add_system(gid, f"group '{name}' created  ({gid[:16]}…)")
        self._refresh_sidebar()

    def _action_group_add(self) -> None:
        if not self.active:
            messagebox.showwarning("No active group", "Pick a group first.", parent=self.root)
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            messagebox.showwarning("Not a group",
                                    "Active conversation is not a group.", parent=self.root)
            return
        target = simpledialog.askstring("Add member", "Peer label or peer_id:", parent=self.root)
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
            messagebox.showerror("Add failed", str(e, parent=self.root))
            return
        if not ok:
            messagebox.showerror("Add failed",
                                  "Peer offline, cap reached, or unknown.", parent=self.root)
            return
        self._refresh_sidebar()

    def _action_group_leave(self) -> None:
        if not self.active:
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            return
        ok = messagebox.askyesno("Leave group",
            f"Leave '{group.name}'?\n\n"
            "Other members will be notified.", parent=self.root)
        if not ok:
            return
        self.bridge.submit_coro(self.node.leave_group_async(group.group_id))
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
        dlg.geometry("440x380")

        body = tk.Frame(dlg, bg=BG_BASE)
        body.pack(fill=tk.BOTH, expand=True, padx=PAD_XL, pady=PAD_XL)

        if self._sigil_dialog is not None:
            tk.Label(body, image=self._sigil_dialog, bg=BG_BASE
                      ).pack(pady=(0, PAD_LG))

        tk.Label(body, text="malphas", bg=BG_BASE, fg=FG_PRIMARY,
                  font=self.f_h1).pack()
        tk.Label(body, text=f"version {__version__}", bg=BG_BASE,
                  fg=FG_MUTED, font=self.f_small).pack(pady=(0, PAD_MD))
        tk.Label(body, text="Privacy-first P2P messenger\nwith onion routing",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_body,
                  justify="center").pack()
        tk.Label(body, text=self.node.identity.peer_id, bg=BG_BASE,
                  fg=FG_FAINT, font=self.f_mono_sm,
                  wraplength=380).pack(pady=(PAD_LG, 0))

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
        self._redraw_conv_header()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._on_quit()


# ── Entry point ──────────────────────────────────────────────────────────────


def launch_gui(node: MalphasNode, book: AddressBook,
                bridge: AsyncBridge, recovery_mnemonic: str | None = None) -> None:
    """Build the GUI and enter the Tk mainloop. Blocks until the
    window closes or panic fires."""
    gui = MalphasGUI(node, book, bridge, recovery_mnemonic=recovery_mnemonic)
    gui.run()
