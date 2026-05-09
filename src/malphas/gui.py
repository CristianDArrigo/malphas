"""
Tkinter desktop GUI for malphas (v0.10.0).

The asyncio loop that drives the MalphasNode runs in a background
daemon thread (`AsyncBridge`). The Tk thread keeps the mainloop and
polls a `queue.Queue` every 50 ms to consume node-side callbacks
(message arrival, receipt, file offer, group invite, etc.) without
blocking either side.

Entry point: `launch_gui(node, book, salt_path)`. Called by
`__main__.py` when `--mode gui`.
"""

from __future__ import annotations

import asyncio
import base64
import queue
import threading
import time
import tkinter as tk
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

# ── Theme ────────────────────────────────────────────────────────────────────

BG          = "#1a1a1a"
BG_SOFT     = "#222222"
FG          = "#e0e0e0"
FG_DIM      = "#888888"
ACCENT      = "#c83232"   # malphas red
ACCENT_DIM  = "#7a2020"
OK_GREEN    = "#3a8a3a"
WARN_AMBER  = "#c08030"
LINK_BLUE   = "#5b9fd8"

GITHUB_URL = "https://github.com/CristianDArrigo/malphas"


# ── AsyncBridge ──────────────────────────────────────────────────────────────


class AsyncBridge:
    """Run an asyncio event loop in a background daemon thread.

    The Tk thread submits coroutines via `submit_coro` and either
    waits on the returned Future or fires-and-forgets. `stop()` is
    safe to call from the Tk thread; it stops the loop and joins
    the worker thread.
    """

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="malphas-asyncio")
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
        """Schedule a coroutine on the worker loop. Returns a Future
        the Tk thread can `.result(timeout=...)` if needed."""
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


# ── MalphasGUI ───────────────────────────────────────────────────────────────


class MalphasGUI:
    """The desktop interface to a running MalphasNode."""

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
        # Active conversation: peer_id, group_id, or None.
        self.active: str | None = None
        # Per-conversation chat scrollback (list of (style, text) lines).
        self._scrollback: dict[str, list[tuple[str, str]]] = {}
        # File-transfer state mirrored from cli_ui patterns.
        self._pending_offers: dict[str, tuple[str, dict]] = {}
        self._completed_files: dict[str, tuple[str, str, bytes]] = {}
        # Tk → asyncio events go through this queue; drained on the
        # Tk thread so widget mutation stays single-threaded.
        self.event_queue: queue.Queue = queue.Queue()

        self.root = tk.Tk()
        self.root.title(f"malphas — {_short(node.identity.peer_id, 16)}")
        self.root.geometry("1100x720")
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_quit)

        self._setup_style()
        self._build_ui()
        self._wire_callbacks()

        # Pulsers
        self.root.after(50, self._drain_events)
        self.root.after(1000, self._refresh_status)

    # ── Theme ───────────────────────────────────────────────────────────────

    def _setup_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_SOFT)
        style.configure("TFrame", background=BG)
        style.configure("Sidebar.TFrame", background=BG_SOFT)
        style.configure("Status.TLabel", background=BG_SOFT, foreground=FG_DIM,
                        padding=(8, 4))
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TButton", background=BG_SOFT, foreground=FG,
                        borderwidth=0, padding=(10, 4))
        style.map("TButton", background=[("active", ACCENT_DIM)])
        style.configure("Accent.TButton", background=ACCENT, foreground=FG)
        style.map("Accent.TButton", background=[("active", ACCENT_DIM)])
        style.configure("TEntry", fieldbackground=BG_SOFT, foreground=FG,
                        insertcolor=FG, borderwidth=0, padding=6)
        style.configure("Treeview", background=BG_SOFT, foreground=FG,
                        fieldbackground=BG_SOFT, borderwidth=0)
        style.map("Treeview",
                  background=[("selected", ACCENT_DIM)],
                  foreground=[("selected", FG)])
        style.configure("Treeview.Heading", background=BG, foreground=FG_DIM,
                        borderwidth=0)

    # ── UI build ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_menubar()

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(paned)
        self._build_main(paned)
        self._build_statusbar()

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self.root, bg=BG, fg=FG, activebackground=ACCENT_DIM,
                          activeforeground=FG, borderwidth=0)
        self.root.config(menu=menubar)

        m_file = tk.Menu(menubar, tearoff=0, bg=BG, fg=FG,
                         activebackground=ACCENT_DIM, activeforeground=FG)
        m_file.add_command(label="Generate invite (copy to clipboard)",
                           command=self._action_export)
        m_file.add_command(label="Import invite from clipboard…",
                           command=self._action_import)
        m_file.add_separator()
        m_file.add_command(label="Backup: show 12-word mnemonic",
                           command=self._action_backup)
        m_file.add_separator()
        m_file.add_command(label="PANIC (wipe and exit)", command=self._action_panic,
                           foreground=ACCENT)
        m_file.add_separator()
        m_file.add_command(label="Quit", command=self._on_quit)
        menubar.add_cascade(label="File", menu=m_file)

        m_view = tk.Menu(menubar, tearoff=0, bg=BG, fg=FG,
                         activebackground=ACCENT_DIM, activeforeground=FG)
        m_view.add_command(label="Refresh peer list", command=self._refresh_sidebar)
        menubar.add_cascade(label="View", menu=m_view)

        m_group = tk.Menu(menubar, tearoff=0, bg=BG, fg=FG,
                          activebackground=ACCENT_DIM, activeforeground=FG)
        m_group.add_command(label="Create new group…", command=self._action_group_new)
        m_group.add_command(label="Add member to active group…",
                            command=self._action_group_add)
        m_group.add_command(label="Leave active group", command=self._action_group_leave)
        menubar.add_cascade(label="Group", menu=m_group)

        m_help = tk.Menu(menubar, tearoff=0, bg=BG, fg=FG,
                         activebackground=ACCENT_DIM, activeforeground=FG)
        m_help.add_command(label="About malphas", command=self._action_about)
        m_help.add_command(label="Open GitHub repo",
                           command=lambda: webbrowser.open(GITHUB_URL))
        menubar.add_cascade(label="Help", menu=m_help)

    def _build_sidebar(self, parent: ttk.PanedWindow) -> None:
        sidebar = ttk.Frame(parent, style="Sidebar.TFrame", padding=4)
        parent.add(sidebar, weight=1)

        ttk.Label(sidebar, text="conversations",
                  background=BG_SOFT, foreground=FG_DIM).pack(anchor="w", padx=4, pady=(4, 2))
        self.tree = ttk.Treeview(sidebar, show="tree", selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure("group", foreground=LINK_BLUE)
        self.tree.tag_configure("active", foreground=ACCENT)

        # Connect button
        connect_btn = ttk.Button(sidebar, text="+ Add peer (manual)",
                                 command=self._action_add_peer)
        connect_btn.pack(fill=tk.X, padx=2, pady=(4, 6))

    def _build_main(self, parent: ttk.PanedWindow) -> None:
        main = ttk.Frame(parent, padding=4)
        parent.add(main, weight=3)

        self.chat = tk.Text(main, bg=BG_SOFT, fg=FG, insertbackground=FG,
                            borderwidth=0, padx=10, pady=8, wrap=tk.WORD,
                            state=tk.DISABLED, font=("Liberation Mono", 10))
        self.chat.pack(fill=tk.BOTH, expand=True, padx=2, pady=(2, 4))
        self.chat.tag_configure("you", foreground=FG)
        self.chat.tag_configure("them", foreground=ACCENT)
        self.chat.tag_configure("ts", foreground=FG_DIM)
        self.chat.tag_configure("system", foreground=WARN_AMBER)
        self.chat.tag_configure("group", foreground=LINK_BLUE)
        self.chat.tag_configure("ok", foreground=OK_GREEN)

        # Input row
        input_row = ttk.Frame(main)
        input_row.pack(fill=tk.X, padx=2, pady=(0, 2))

        self.input_var = tk.StringVar()
        self.entry = ttk.Entry(input_row, textvariable=self.input_var)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.entry.bind("<Return>", self._on_send)

        send_btn = ttk.Button(input_row, text="send", style="Accent.TButton",
                              command=self._on_send)
        send_btn.pack(side=tk.LEFT, padx=2)

        file_btn = ttk.Button(input_row, text="📎 file",
                              command=self._action_send_file)
        file_btn.pack(side=tk.LEFT, padx=2)

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar()
        bar = ttk.Label(self.root, textvariable=self.status_var,
                        style="Status.TLabel", anchor="w")
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self._set_status()

    # ── Event drain (Tk thread) ────────────────────────────────────────────

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
            from_id, content = ev[1], ev[2]
            self._on_msg(from_id, content)
        elif kind == "receipt":
            msg_id, dest, ok = ev[1], ev[2], ev[3]
            self._append_chat(dest, "ok" if ok else "system",
                              "  " + ("✓ delivered" if ok else "✗ no receipt"))
        elif kind == "pin_violation":
            peer_id, expected, received = ev[1], ev[2], ev[3]
            messagebox.showerror("Key mismatch",
                                 f"Pinned key mismatch for {_short(peer_id)}.\n"
                                 f"Expected {expected[:16]}…\n"
                                 f"Received {received[:16]}…\n\n"
                                 "Connection rejected. Use /trust to reset (CLI).",
                                 parent=self.root)
        elif kind == "file_offer":
            from_id, offer = ev[1], ev[2]
            self._on_file_offer(from_id, offer)
        elif kind == "file_complete":
            file_id, data = ev[1], ev[2]
            self._on_file_complete(file_id, data)
        elif kind == "group_invite":
            from_id, gid, gname, members = ev[1], ev[2], ev[3], ev[4]
            self._on_group_invite(from_id, gid, gname, members)
        elif kind == "group_msg":
            from_id, gid, gname, content = ev[1], ev[2], ev[3], ev[4]
            self._on_group_msg(from_id, gid, gname, content)

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
        tor_marker = "  •  tor" if onion.endswith(".onion") else ""
        self.status_var.set(f"{n_peers} peers   |   chat: {active_label}{tor_marker}")

    def _refresh_status(self) -> None:
        self._set_status()
        self.root.after(1000, self._refresh_status)

    def _refresh_sidebar(self) -> None:
        self.tree.delete(*self.tree.get_children())
        peers_node = self.tree.insert("", "end", text="PEERS", open=True,
                                      values=("",))
        for c in self.book.all():
            self.tree.insert(peers_node, "end", iid=f"peer:{c.peer_id}",
                             text=f"  {c.label}  ·  {_short(c.peer_id, 8)}")
        # Also peers in routing table that are NOT in the book
        for p in self.node.discovery.all_peers():
            pid = p["peer_id"]
            if not self.book.get_by_peer_id(pid):
                self.tree.insert(peers_node, "end", iid=f"peer:{pid}",
                                 text=f"  (unsaved)  ·  {_short(pid, 8)}")
        groups_node = self.tree.insert("", "end", text="GROUPS", open=True,
                                       values=("",))
        for g in self.node._groups.all_groups():
            self.tree.insert(groups_node, "end", iid=f"group:{g.group_id}",
                             text=f"  {g.name}  ·  {g.member_count()}",
                             tags=("group",))

    def _on_tree_select(self, event: object | None = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith("peer:"):
            peer_id = iid[5:]
            self.active = peer_id
            self._render_active()
        elif iid.startswith("group:"):
            gid = iid[6:]
            self.active = gid
            self._render_active()

    def _render_active(self) -> None:
        # Refresh chat pane from scrollback
        self.chat.config(state=tk.NORMAL)
        self.chat.delete("1.0", tk.END)
        for tag, text in self._scrollback.get(self.active or "", []):
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

    # ── Send (Tk thread → asyncio) ──────────────────────────────────────────

    def _on_send(self, event: object | None = None) -> None:
        text = self.input_var.get().strip()
        if not text or not self.active:
            return
        self.input_var.set("")
        # Group?
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            self.bridge.submit_coro(self.node.send_group_message(group.group_id, text))
            self._append_chat(self.active, "you",
                              f"[{_ts()}] [{group.name}] you: {text}")
        else:
            self.bridge.submit_coro(self.node.send_message(self.active, text))
            self._append_chat(self.active, "you", f"[{_ts()}] you: {text}")

    # ── Node-callback handlers (Tk thread, called from drain) ──────────────

    def _conv_label(self, peer_id: str) -> str:
        contact = self.book.get_by_peer_id(peer_id)
        return contact.label if contact else _short(peer_id, 12)

    def _on_msg(self, from_id: str, content: str) -> None:
        label = self._conv_label(from_id)
        self._append_chat(from_id, "them", f"[{_ts()}] {label}: {content}")
        if self.active != from_id:
            self._refresh_sidebar()

    def _on_file_offer(self, from_id: str, offer: dict) -> None:
        fid = offer.get("file_id", "")
        if not fid:
            return
        self._pending_offers[fid] = (from_id, offer)
        label = self._conv_label(from_id)
        ok = messagebox.askyesno(
            "Incoming file",
            f"{label} wants to send you '{offer.get('name')}' "
            f"({offer.get('size')} bytes). Accept?",
            parent=self.root,
        )
        if ok:
            self.node.accept_file_offer(offer)
            self._append_chat(from_id, "system",
                              f"[{_ts()}] *** accepting {offer.get('name')} from {label} ***")
        else:
            self._pending_offers.pop(fid, None)

    def _on_file_complete(self, file_id: str, data: bytes) -> None:
        offer_entry = self._pending_offers.pop(file_id, None)
        from_id = offer_entry[0] if offer_entry else "?"
        name = offer_entry[1].get("name", "file.bin") if offer_entry else "file.bin"
        self._completed_files[file_id] = (from_id, name, data)
        label = self._conv_label(from_id) if from_id != "?" else "?"
        self._append_chat(from_id, "ok",
                          f"[{_ts()}] ✓ received {name} ({len(data)} bytes) from {label}")

        path = filedialog.asksaveasfilename(
            parent=self.root,
            initialfile=name,
            title=f"Save '{name}' as…",
        )
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                self._append_chat(from_id, "ok",
                                  f"[{_ts()}] saved to {path}")
                # Drop the in-RAM copy after disk save (zero-disk policy
                # for the in-process buffer).
                self._completed_files.pop(file_id, None)
            except OSError as e:
                messagebox.showerror("Save failed", str(e), parent=self.root)

    def _on_group_invite(self, from_id: str, group_id: str,
                         group_name: str, members: list) -> None:
        label = self._conv_label(from_id)
        self._append_chat(group_id, "system",
                          f"[{_ts()}] *** {label} added you to {group_name} "
                          f"({len(members)} members) ***")
        self._refresh_sidebar()

    def _on_group_msg(self, from_id: str, group_id: str,
                      group_name: str, content: str) -> None:
        label = self._conv_label(from_id)
        self._append_chat(group_id, "them",
                          f"[{_ts()}] [{group_name}] {label}: {content}")
        if self.active != group_id:
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
        messagebox.showinfo("Invite copied", "A signed malphas:// invite is on "
                            "your clipboard. Send it to the peer over a channel "
                            "you trust.", parent=self.root)

    def _action_import(self) -> None:
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Clipboard empty", "Nothing to import.", parent=self.root)
            return
        try:
            data = parse_invite(text)
        except ValueError as e:
            messagebox.showerror("Invalid invite", str(e), parent=self.root)
            return

        ok = messagebox.askyesno(
            "Import invite",
            f"Connect to peer_id {data['peer_id'][:16]}…\n"
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
                bytes.fromhex(data["ed25519_pub"]),
            )

        future = self.bridge.submit_coro(_connect())
        try:
            success = future.result(timeout=35.0)
        except Exception as e:
            messagebox.showerror("Connection failed", str(e), parent=self.root)
            return
        if not success:
            messagebox.showerror("Connection failed",
                                 "Could not reach the peer.", parent=self.root)
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
                ed25519_pub=data["ed25519_pub"],
            ))
        self._refresh_sidebar()

    def _action_add_peer(self) -> None:
        messagebox.showinfo(
            "Add peer manually",
            "Use File → Import invite from clipboard, or run /add via "
            "the CLI mode (--mode cli) for a manual peer add with all "
            "three fields.",
            parent=self.root,
        )

    def _action_send_file(self) -> None:
        if not self.active:
            messagebox.showwarning("No active conversation",
                                   "Pick a peer first.", parent=self.root)
            return
        # Group or peer?
        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            messagebox.showinfo("Not supported",
                                "File send to a group is not implemented; "
                                "send 1-to-1 instead.", parent=self.root)
            return

        path = filedialog.askopenfilename(parent=self.root,
                                           title="File to send")
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
                                 "Could not start the transfer (peer offline, "
                                 "file too large, or no circuit).",
                                 parent=self.root)
            return
        self._append_chat(peer_id, "system",
                          f"[{_ts()}] *** sending {Path(path).name} (file_id {file_id[:16]}…) ***")

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
        body = "  ".join(f"{i+1:>2}. {w}" for i, w in enumerate(words[:6])) + "\n"
        body += "  ".join(f"{i+1:>2}. {w}" for i, w in enumerate(words[6:], start=6))
        messagebox.showinfo(
            "Recovery mnemonic — write this down",
            "These 12 words are the only way to recover your identity "
            "if ~/.malphas/salt is lost.\n\n" + body + "\n\n"
            "Treat them like a password: do NOT screenshot, do NOT paste "
            "into a chat.",
            parent=self.root,
        )

    def _action_panic(self) -> None:
        ok = messagebox.askyesno("PANIC",
                                  "This wipes ALL in-memory state and exits "
                                  "immediately. The address book and salt "
                                  "files on disk are NOT touched. Continue?",
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
        name = simpledialog.askstring("New group", "Group name:", parent=self.root)
        if not name:
            return

        async def _create() -> str | None:
            return await self.node.create_group(name, [])

        future = self.bridge.submit_coro(_create())
        try:
            gid = future.result(timeout=5.0)
        except Exception as e:
            messagebox.showerror("Group create failed", str(e), parent=self.root)
            return
        if gid is None:
            messagebox.showerror("Group create failed",
                                 "Name already in use, or empty name.",
                                 parent=self.root)
            return
        self._append_chat(gid, "system",
                          f"[{_ts()}] *** group '{name}' created ({gid[:16]}…) ***")
        self._refresh_sidebar()

    def _action_group_add(self) -> None:
        if not self.active:
            messagebox.showwarning("No active group", "Pick a group first.",
                                   parent=self.root)
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            messagebox.showwarning("Not a group", "Active conversation is not "
                                                  "a group.", parent=self.root)
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
        ok = messagebox.askyesno("Leave group",
                                  f"Leave '{group.name}' locally? "
                                  "Other members will not be notified.",
                                  parent=self.root)
        if not ok:
            return
        self.node.leave_group(group.group_id)
        if self.active == group.group_id:
            self.active = None
            self.chat.config(state=tk.NORMAL)
            self.chat.delete("1.0", tk.END)
            self.chat.config(state=tk.DISABLED)
        self._refresh_sidebar()

    def _action_about(self) -> None:
        from . import __version__
        messagebox.showinfo(
            "malphas",
            f"malphas {__version__}\n"
            "Privacy-first P2P messenger with onion routing.\n\n"
            f"peer_id: {self.node.identity.peer_id}\n"
            f"port:    {self.node.port}",
            parent=self.root,
        )

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def _wire_callbacks(self) -> None:
        # Each callback pushes into the queue from whichever thread
        # calls it (asyncio thread for the node callbacks). The Tk
        # drain consumes from the Tk thread.
        q = self.event_queue

        def push(name: str, *args: Any) -> None:
            q.put((name, *args))

        self.node.on_message(lambda f, c: push("message", f, c))
        self.node.on_receipt(lambda mid, dst, ok: push("receipt", mid, dst, ok))
        self.node.on_pin_violation(lambda pid, ex, rcv: push("pin_violation", pid, ex, rcv))
        self.node.on_file_offer(lambda f, o: push("file_offer", f, o))
        self.node.on_file_complete(lambda fid, d: push("file_complete", fid, d))
        self.node.on_group_invite(
            lambda f, gid, gname, members: push("group_invite", f, gid, gname, members)
        )
        self.node.on_group_message(
            lambda f, gid, gname, c: push("group_msg", f, gid, gname, c)
        )

    def _on_quit(self) -> None:
        # Submit node.stop on the asyncio thread, then bring down the
        # bridge and Tk root.
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
        # Auto-connect address book entries on startup.
        async def _auto() -> None:
            for c in self.book.all():
                try:
                    await self.node.connect_to_peer(
                        c.host, c.port, c.peer_id,
                        bytes.fromhex(c.x25519_pub),
                        bytes.fromhex(c.ed25519_pub),
                    )
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
