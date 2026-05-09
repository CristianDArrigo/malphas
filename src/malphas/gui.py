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

BG_BASE     = "#0e0e10"
BG_SURFACE  = "#16161a"
BG_RAISED   = "#1d1d22"
BG_DIVIDER  = "#26262d"

FG_PRIMARY  = "#ececec"
FG_MUTED    = "#9a9a9a"
FG_FAINT    = "#666670"

ACCENT      = "#d23a3a"
ACCENT_SOFT = "#5a1f1f"
ACCENT_TINT = "#2a1414"
OK_GREEN    = "#5cb85c"
WARN_AMBER  = "#e0a830"
INFO_CYAN   = "#5b9fd8"

PAD_XS = 4
PAD_SM = 8
PAD_MD = 12
PAD_LG = 16
PAD_XL = 24

WIN_W = 1180
WIN_H = 760
SIDEBAR_W = 260

GITHUB_URL = "https://github.com/CristianDArrigo/malphas"


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
        self.event_queue: queue.Queue = queue.Queue()

        self.root = tk.Tk()
        self.root.title(f"malphas — {_short(node.identity.peer_id, 16)}")
        self.root.geometry(f"{WIN_W}x{WIN_H}")
        self.root.minsize(820, 560)
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
                    foreground=FG_FAINT, font=self.f_small,
                    padding=(PAD_MD, PAD_MD, PAD_MD, PAD_XS))
        s.configure("Title.TLabel", background=BG_SURFACE,
                    foreground=FG_PRIMARY, font=self.f_h1)
        s.configure("Status.TLabel", background=BG_SURFACE,
                    foreground=FG_MUTED, font=self.f_small,
                    padding=(PAD_MD, PAD_SM))

        s.configure("TButton", background=BG_RAISED, foreground=FG_PRIMARY,
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=self.f_body)
        s.map("TButton",
              background=[("active", ACCENT_SOFT), ("pressed", ACCENT_SOFT)])
        s.configure("Accent.TButton", background=ACCENT, foreground=FG_PRIMARY,
                    borderwidth=0, padding=(PAD_LG, PAD_SM), font=self.f_bold)
        s.map("Accent.TButton",
              background=[("active", ACCENT_SOFT), ("pressed", ACCENT_SOFT)])
        s.configure("Ghost.TButton", background=BG_SURFACE, foreground=FG_MUTED,
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=self.f_body)
        s.map("Ghost.TButton",
              background=[("active", BG_RAISED)],
              foreground=[("active", FG_PRIMARY)])

        s.configure("TEntry", fieldbackground=BG_RAISED, foreground=FG_PRIMARY,
                    insertcolor=ACCENT, borderwidth=0,
                    padding=(PAD_MD, PAD_SM), font=self.f_body)

        s.configure("Sidebar.Treeview", background=BG_SURFACE, foreground=FG_PRIMARY,
                    fieldbackground=BG_SURFACE, borderwidth=0,
                    rowheight=28, font=self.f_body)
        s.map("Sidebar.Treeview",
              background=[("selected", ACCENT_TINT)],
              foreground=[("selected", FG_PRIMARY)])
        s.layout("Sidebar.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        s.configure("Vertical.TScrollbar", background=BG_SURFACE,
                    troughcolor=BG_SURFACE, borderwidth=0, arrowsize=12)
        s.map("Vertical.TScrollbar",
              background=[("active", BG_RAISED), ("pressed", ACCENT_SOFT)])

    # ── UI build ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_menubar()
        self._build_header()

        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)

        paned = ttk.PanedWindow(body, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(paned)
        self._build_main(paned)
        try:
            paned.sashpos(0, SIDEBAR_W)
        except tk.TclError:
            pass

        self._build_statusbar()

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self.root, bg=BG_SURFACE, fg=FG_PRIMARY,
                          activebackground=ACCENT_SOFT, activeforeground=FG_PRIMARY,
                          borderwidth=0, font=self.f_body)
        self.root.config(menu=menubar)

        m_file = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                         activebackground=ACCENT_SOFT, activeforeground=FG_PRIMARY,
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
                         activebackground=ACCENT_SOFT, activeforeground=FG_PRIMARY,
                         font=self.f_body)
        m_view.add_command(label="Refresh peer list", command=self._refresh_sidebar,
                           accelerator="F5")
        menubar.add_cascade(label="View", menu=m_view)

        m_group = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                          activebackground=ACCENT_SOFT, activeforeground=FG_PRIMARY,
                          font=self.f_body)
        m_group.add_command(label="Create new group…", command=self._action_group_new)
        m_group.add_command(label="Add member to active group…",
                            command=self._action_group_add)
        m_group.add_command(label="Leave active group", command=self._action_group_leave)
        menubar.add_cascade(label="Group", menu=m_group)

        m_help = tk.Menu(menubar, tearoff=0, bg=BG_SURFACE, fg=FG_PRIMARY,
                         activebackground=ACCENT_SOFT, activeforeground=FG_PRIMARY,
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
        header = ttk.Frame(self.root, style="Surface.TFrame",
                            padding=(PAD_LG, PAD_MD))
        header.pack(fill=tk.X, side=tk.TOP)

        left = ttk.Frame(header, style="Surface.TFrame")
        left.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Label(left, text="malphas", style="Title.TLabel").pack(side=tk.LEFT)
        tk.Label(left, text=f"  ·  {_short(self.node.identity.peer_id, 16)}",
                 bg=BG_SURFACE, fg=FG_MUTED, font=self.f_mono_sm).pack(side=tk.LEFT)

        right = ttk.Frame(header, style="Surface.TFrame")
        right.pack(side=tk.RIGHT, fill=tk.Y)
        self.dot = tk.Label(right, text="●", bg=BG_SURFACE, fg=FG_FAINT,
                             font=self.f_body)
        self.dot.pack(side=tk.RIGHT, padx=(PAD_SM, 0))
        self.header_status_var = tk.StringVar()
        tk.Label(right, textvariable=self.header_status_var,
                 bg=BG_SURFACE, fg=FG_MUTED, font=self.f_small
                 ).pack(side=tk.RIGHT)

        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

    def _build_sidebar(self, parent: ttk.PanedWindow) -> None:
        sidebar = ttk.Frame(parent, style="Surface.TFrame")
        parent.add(sidebar, weight=0)

        ttk.Label(sidebar, text="CONVERSATIONS", style="Heading.TLabel"
                  ).pack(anchor="w", fill=tk.X)

        wrap = ttk.Frame(sidebar, style="Surface.TFrame")
        wrap.pack(fill=tk.BOTH, expand=True, padx=PAD_XS, pady=(0, PAD_SM))
        self.tree = ttk.Treeview(wrap, show="tree", selectmode="browse",
                                  style="Sidebar.Treeview")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview,
                            style="Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure("section", foreground=FG_FAINT,
                                 font=self.f_small)
        self.tree.tag_configure("group", foreground=INFO_CYAN)
        self.tree.tag_configure("unread", foreground=ACCENT, font=self.f_bold)

        actions = ttk.Frame(sidebar, style="Surface.TFrame")
        actions.pack(fill=tk.X, padx=PAD_SM, pady=(0, PAD_SM))
        ttk.Button(actions, text="+  Import invite", style="Ghost.TButton",
                   command=self._action_import).pack(fill=tk.X, pady=(0, PAD_XS))
        ttk.Button(actions, text="↗  Generate invite", style="Ghost.TButton",
                   command=self._action_export).pack(fill=tk.X)

    def _build_main(self, parent: ttk.PanedWindow) -> None:
        main = ttk.Frame(parent)
        parent.add(main, weight=3)

        self.conv_header = ttk.Frame(main, style="Surface.TFrame",
                                      padding=(PAD_LG, PAD_MD, PAD_LG, PAD_MD))
        self.conv_header.pack(fill=tk.X, side=tk.TOP)
        self.conv_title_var = tk.StringVar(value="No conversation")
        self.conv_sub_var = tk.StringVar(value="")
        title_box = ttk.Frame(self.conv_header, style="Surface.TFrame")
        title_box.pack(side=tk.LEFT)
        tk.Label(title_box, textvariable=self.conv_title_var, bg=BG_SURFACE,
                 fg=FG_PRIMARY, font=self.f_h2).pack(anchor="w")
        tk.Label(title_box, textvariable=self.conv_sub_var, bg=BG_SURFACE,
                 fg=FG_MUTED, font=self.f_mono_sm).pack(anchor="w")

        tk.Frame(main, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.TOP)

        chat_frame = ttk.Frame(main, style="Raised.TFrame")
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

        self.empty_var = tk.StringVar(
            value="Pick a conversation from the sidebar,\n"
                  "or import an invite from the clipboard\n"
                  "to start chatting."
        )
        self.empty_label = tk.Label(chat_frame, textvariable=self.empty_var,
                                     bg=BG_RAISED, fg=FG_FAINT,
                                     font=self.f_body, justify="center")
        self._show_empty(True)

        input_wrap = ttk.Frame(main, style="Raised.TFrame",
                                padding=(PAD_LG, PAD_SM, PAD_LG, PAD_LG))
        input_wrap.pack(fill=tk.X, side=tk.BOTTOM)

        self.input_var = tk.StringVar()
        self.entry = ttk.Entry(input_wrap, textvariable=self.input_var,
                                font=self.f_mono)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                         padx=(0, PAD_SM), ipady=PAD_XS)
        self.entry.bind("<Return>", self._on_send)

        ttk.Button(input_wrap, text="📎  file", style="Ghost.TButton",
                   command=self._action_send_file).pack(side=tk.LEFT, padx=(0, PAD_XS))
        ttk.Button(input_wrap, text="send", style="Accent.TButton",
                   command=self._on_send).pack(side=tk.LEFT)

    def _build_statusbar(self) -> None:
        tk.Frame(self.root, height=1, bg=BG_DIVIDER).pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status_var,
                  style="Status.TLabel", anchor="w").pack(side=tk.BOTTOM, fill=tk.X)
        self._set_status()

    def _show_empty(self, on: bool) -> None:
        if on:
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.empty_label.place_forget()

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
        self.tree.delete(*self.tree.get_children())

        peers_node = self.tree.insert("", "end", text="PEERS", open=True,
                                       tags=("section",))
        seen: set[str] = set()
        for c in self.book.all():
            seen.add(c.peer_id)
            iid = f"peer:{c.peer_id}"
            tag = ("unread",) if c.peer_id in self._unread else ()
            badge = "  ●" if c.peer_id in self._unread else ""
            self.tree.insert(peers_node, "end", iid=iid,
                              text=f"   ●  {c.label}{badge}", tags=tag)
        for p in self.node.discovery.all_peers():
            pid = p["peer_id"]
            if pid in seen:
                continue
            self.tree.insert(peers_node, "end", iid=f"peer:{pid}",
                              text=f"   ◦  {_short(pid, 12)}",
                              tags=("section",))

        groups_node = self.tree.insert("", "end", text="GROUPS", open=True,
                                        tags=("section",))
        for g in self.node._groups.all_groups():
            iid = f"group:{g.group_id}"
            unread = "  ●" if g.group_id in self._unread else ""
            tag = ("group", "unread") if g.group_id in self._unread else ("group",)
            self.tree.insert(groups_node, "end", iid=iid,
                              text=f"   ▣  {g.name}  ({g.member_count()}){unread}",
                              tags=tag)

        if self.active:
            tag = "group" if self.node._groups.get_by_id(self.active) else "peer"
            iid = f"{tag}:{self.active}"
            try:
                self.tree.selection_set(iid)
                self.tree.see(iid)
            except tk.TclError:
                pass

    def _on_tree_select(self, event: object | None = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith("peer:"):
            self.active = iid[5:]
        elif iid.startswith("group:"):
            self.active = iid[6:]
        else:
            return
        self._unread.discard(self.active)
        self._render_active()
        self._refresh_sidebar()

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
        dlg.geometry("540x440")

        tk.Label(dlg, text="Recovery mnemonic", bg=BG_BASE, fg=FG_PRIMARY,
                 font=self.f_h1).pack(anchor="w", padx=PAD_XL, pady=(PAD_XL, PAD_XS))
        tk.Label(dlg, text="Write these 12 words down. They are the only way "
                            "to recover your identity if ~/.malphas/salt is lost.",
                  bg=BG_BASE, fg=FG_MUTED, font=self.f_small,
                  wraplength=480, justify="left").pack(
                      anchor="w", padx=PAD_XL, pady=(0, PAD_LG))

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
                  wraplength=480, justify="left").pack(
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
        messagebox.showinfo(
            "malphas",
            f"malphas {__version__}\n"
            "Privacy-first P2P messenger with onion routing.\n\n"
            f"peer_id: {self.node.identity.peer_id}\n"
            f"port:    {self.node.port}",
            parent=self.root)

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
