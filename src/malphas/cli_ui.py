"""
Malphas CLI — interactive terminal messenger.

prompt_toolkit for split-pane layout and readline input.
rich for formatted output.

Commands:
  /id                     show own identity (peer_id + pubkeys)
  /peers                  list connected peers
  /book                   list address book contacts
  /book add <label>       save active peer to address book
  /book rm <label>        remove contact from address book
  /add <host> <port>      connect to peer manually
  /chat <peer_id|label>   open conversation
  /history                show conversation history
  /export                 generate shareable invite URL
  /import <url>           import peer from invite URL
  /wipe                   wipe all messages from memory
  /panic                  EMERGENCY: wipe everything and exit
  /quit                   shutdown
  <text>                  send message to active conversation
"""

import asyncio
import os
import re
import sys
import time
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit import print_formatted_text as ptk_print
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .addressbook import AddressBook, Contact
from .invite import generate_invite, parse_invite
from .node import MalphasNode

PEER_ID_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# ── Rich console that captures to string ─────────────────────────────────────

def _make_console() -> Console:
    return Console(
        highlight=False,
        force_terminal=True,
        color_system="256",
        width=100,
    )


# ── Colors ───────────────────────────────────────────────────────────────────

C_OK = "green4"
C_ERR = "red3"
C_WARN = "yellow4"
C_DIM = "grey50"
C_ACCENT = "red3"
C_SENT = "grey70"
C_LABEL = "grey62"
C_BORDER = "grey30"


# ── Tab completion ───────────────────────────────────────────────────────────

COMMANDS = [
    "/id", "/peers", "/book", "/add", "/chat", "/history",
    "/export", "/import", "/trust", "/wipe", "/panic", "/help", "/github", "/quit", "/exit",
    "/sendfile", "/accept", "/reject", "/savefile", "/files",
    "/backup",
    "/group",
]

GITHUB_URL = "https://github.com/CristianDArrigo/malphas"


class MalphasCompleter(Completer):
    def __init__(self, node: MalphasNode, book: AddressBook):
        self._node = node
        self._book = book

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()

        if not words or (len(words) == 1 and not text.endswith(" ")):
            # First word — complete commands
            prefix = words[0] if words else ""
            for cmd in COMMANDS:
                if cmd.startswith(prefix):
                    yield Completion(cmd, start_position=-len(prefix))

        elif len(words) >= 1 and text.endswith(" ") or len(words) >= 2:
            cmd = words[0].lower()
            partial = words[-1] if not text.endswith(" ") else ""

            if cmd == "/chat":
                # Complete from address book labels + peer ids
                for c in self._book.all():
                    if c.label.lower().startswith(partial.lower()):
                        yield Completion(c.label, start_position=-len(partial))
                for p in self._node.discovery.all_peers():
                    short = p["peer_id"][:8]
                    if short.startswith(partial):
                        yield Completion(short, start_position=-len(partial))

            elif cmd == "/book" and len(words) >= 2 and words[1] == "rm":
                # Complete labels for removal
                for c in self._book.all():
                    if c.label.lower().startswith(partial.lower()):
                        yield Completion(c.label, start_position=-len(partial))


# ── CLI class ────────────────────────────────────────────────────────────────

class MalphasCLI:
    def __init__(
        self,
        node: MalphasNode,
        book: AddressBook,
        salt_path: "Path | None" = None,
    ):
        self.node = node
        self.book = book
        self.active_peer: str | None = None
        self._running = True
        self._console = _make_console()
        self._salt_path = salt_path
        # File transfer UI state — keyed by file_id.
        # _pending_offers: offers received and awaiting /accept or /reject.
        # _completed_files: payloads ready for /savefile to flush to disk.
        self._pending_offers: dict[str, tuple[str, dict]] = {}
        # _accepted_offers: offers we accepted, kept so _on_file_complete can
        # recover the original name/sender once the transfer assembles
        # (the entry is removed from _pending_offers on accept).
        self._accepted_offers: dict[str, tuple[str, dict]] = {}
        self._completed_files: dict[str, tuple[str, str, bytes]] = {}

    # ── Output helpers ───────────────────────────────────────────────────

    def _print(self, *args, **kwargs):
        """Print via rich console."""
        self._console.print(*args, **kwargs)

    def _status(self, msg: str, style: str = C_OK):
        """Print a status line with prefix."""
        self._print(Text(msg, style=style))

    def _ok(self, msg: str):
        self._print(f"  [{C_OK}][ok][/{C_OK}] {msg}")

    def _err(self, msg: str):
        self._print(f"  [{C_ERR}][err][/{C_ERR}] {msg}")

    def _warn(self, msg: str):
        self._print(f"  [{C_WARN}][!][/{C_WARN}] {msg}")

    def _info(self, msg: str, tag: str = ""):
        if tag:
            self._print(f"  [{C_DIM}][{tag}][/{C_DIM}] {msg}")
        else:
            self._print(f"  {msg}")

    def _status_bar(self) -> str:
        """Build status bar content (plain text for prompt_toolkit toolbar)."""
        parts = []

        n_peers = len(list(self.node._connections.keys()))
        parts.append(f"{n_peers} peers")

        if self.active_peer:
            contact = self.book.get_by_peer_id(self.active_peer)
            label = contact.label if contact else self.active_peer[:8]
            parts.append(f"chat: {label}")

        pending = self.node.receipts.pending_count()
        if pending > 0:
            parts.append(f"{pending} receipts")

        onion = self.node.transport.public_address
        if onion and onion.endswith(".onion"):
            parts.append("tor")

        return "  |  ".join(parts)

    # ── Callbacks ────────────────────────────────────────────────────────
    # These fire asynchronously — use plain print() to avoid
    # rich ANSI issues outside patch_stdout context.

    def _plain(self, msg: str):
        """Print with ANSI colors, compatible with prompt_toolkit."""
        ptk_print(ANSI(msg))

    async def _on_message(self, from_id: str, content: str) -> None:
        contact = self.book.get_by_peer_id(from_id)
        label = contact.label if contact else from_id[:8]
        ts = time.strftime("%H:%M")

        if from_id == self.active_peer:
            self._plain(f"  \033[90m{ts}\033[0m \033[31m{label}\033[0m  {content}")
        else:
            self._plain(f"  \033[33m<\033[0m {label}: {content}")

    async def _on_receipt(self, msg_id: str, dest_peer_id: str, received: bool) -> None:
        if received:
            self._plain("  \033[32m\u2713\033[0m")
        else:
            contact = self.book.get_by_peer_id(dest_peer_id)
            label = contact.label if contact else dest_peer_id[:8]
            self._plain(f"  \033[33m!\033[0m no receipt from {label}")

    # ── Commands ─────────────────────────────────────────────────────────

    def _print_identity(self):
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style=C_DIM)
        t.add_column()
        t.add_row("peer_id", self.node.identity.peer_id)
        t.add_row("x25519_pub", self.node.identity.x25519_pub_bytes.hex())
        t.add_row("ed25519_pub", self.node.identity.ed25519_pub_bytes.hex())
        t.add_row("port", str(self.node.port))
        onion = self.node.transport.public_address
        if onion and onion.endswith(".onion"):
            t.add_row("onion", onion)
        self._print(Panel(t, border_style=C_BORDER, title="[dim]identity[/dim]", title_align="left"))

    def _print_peers(self):
        peers = self.node.discovery.all_peers()
        if not peers:
            self._info("no peers connected", tag="peers")
            return
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(width=3)
        t.add_column()
        t.add_column(style=C_DIM)
        t.add_column(style=C_LABEL)
        for i, p in enumerate(peers):
            contact = self.book.get_by_peer_id(p["peer_id"])
            label = contact.label if contact else ""
            marker = "*" if p["peer_id"] == self.active_peer else str(i)
            t.add_row(marker, p["peer_id"][:16] + "...", f"{p['host']}:{p['port']}", label)
        self._print(Panel(t, border_style=C_BORDER, title="[dim]peers[/dim]", title_align="left"))

    def _print_book(self):
        contacts = self.book.all()
        if not contacts:
            self._info("address book is empty", tag="book")
            return
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(width=3)
        t.add_column(width=20)
        t.add_column()
        t.add_column(style=C_DIM)
        for c in contacts:
            marker = "*" if c.peer_id == self.active_peer else " "
            t.add_row(marker, c.label, c.peer_id[:16] + "...", f"{c.host}:{c.port}")
        self._print(Panel(t, border_style=C_BORDER, title="[dim]address book[/dim]", title_align="left"))

    def _print_conversation(self, peer_id: str):
        msgs = self.node.store.get_conversation(self.node.identity.peer_id, peer_id)
        if not msgs:
            self._info("no messages yet")
            return
        for m in msgs:
            ts = time.strftime("%H:%M", time.localtime(m["timestamp"]))
            if m["from_peer"] == self.node.identity.peer_id:
                self._plain(f"  \033[90m{ts}  you\033[0m  {m['content']}")
            else:
                contact = self.book.get_by_peer_id(m["from_peer"])
                name = contact.label if contact else m["from_peer"][:8]
                self._plain(f"  \033[90m{ts}\033[0m \033[31m{name}\033[0m  {m['content']}")

    def _print_help(self):
        cmds = [
            ("/id", "show peer_id and public keys"),
            ("/peers", "list connected peers"),
            ("/book", "list address book contacts"),
            ("/book add <label>", "save active peer to address book"),
            ("/book rm <label>", "remove contact from address book"),
            ("/add <host> <port>", "connect to a peer manually"),
            ("/chat <peer_id|label>", "open a conversation"),
            ("/history", "show conversation history"),
            ("/export", "generate shareable invite URL"),
            ("/import <url>", "import peer from invite URL"),
            ("/trust <peer_id|label>", "reset pinned key for a peer"),
            ("/github", "open the project page in the browser"),
            ("/wipe", "wipe all messages from memory"),
            ("/panic", "EMERGENCY: wipe everything and exit"),
            ("/sendfile <peer> <path>", "send a file to a peer (32 KB chunks, 100 MB cap)"),
            ("/accept <file_id>", "accept a pending incoming file"),
            ("/reject <file_id>", "reject a pending incoming file"),
            ("/savefile <file_id> [path]", "write a completed file to disk (default ~/)"),
            ("/files", "list pending and completed file transfers"),
            ("/quit", "shutdown"),
            ("<text>", "send message to active conversation"),
        ]
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style=C_DIM, width=28)
        t.add_column()
        for cmd, desc in cmds:
            t.add_row(cmd, desc)
        self._print(Panel(t, border_style=C_BORDER, title="[dim]commands[/dim]", title_align="left"))

    async def _cmd_add(self, args: list) -> None:
        if len(args) < 2:
            self._err("usage: /add <host> <port>")
            return
        host = args[0]
        try:
            port = int(args[1])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self._err("invalid port")
            return

        # Use prompt_session for input within the command
        peer_id = input("  peer_id (40-char hex): ").strip().lower()
        if not PEER_ID_RE.match(peer_id):
            self._err("invalid peer_id")
            return
        x25519_pub = input("  x25519_pub (64-char hex): ").strip().lower()
        if not HEX64_RE.match(x25519_pub):
            self._err("invalid x25519_pub")
            return
        ed25519_pub = input("  ed25519_pub (64-char hex): ").strip().lower()
        if not HEX64_RE.match(ed25519_pub):
            self._err("invalid ed25519_pub")
            return

        self._info(f"connecting to {host}:{port}...", tag="...")
        ok = await self.node.connect_to_peer(
            host, port, peer_id,
            bytes.fromhex(x25519_pub),
            bytes.fromhex(ed25519_pub),
        )

        if ok:
            self._ok(f"connected  {peer_id[:16]}...")
            save = input("  save to address book? [y/N] ").strip().lower()
            if save == "y":
                label = input("  label: ").strip()
                if label:
                    self.book.add(Contact(
                        label=label, peer_id=peer_id,
                        host=host, port=port,
                        x25519_pub=x25519_pub, ed25519_pub=ed25519_pub,
                    ))
                    self._ok(f"saved as '{label}'")
                else:
                    self._info("label empty, not saved")
        else:
            self._err("connection failed")

    async def _cmd_book(self, args: list) -> None:
        if not args:
            self._print_book()
            return
        sub = args[0].lower()

        if sub == "add":
            if not self.active_peer:
                self._err("no active conversation")
                return
            label = " ".join(args[1:]).strip() or input("  label: ").strip()
            if not label:
                self._err("label cannot be empty")
                return
            peer = self.node.discovery.get_peer(self.active_peer)
            if not peer:
                self._err("peer not in routing table")
                return
            self.book.add(Contact(
                label=label, peer_id=self.active_peer,
                host=peer.host, port=peer.port,
                x25519_pub=peer.x25519_pub.hex(),
                ed25519_pub=peer.ed25519_pub.hex(),
            ))
            self._ok(f"saved as '{label}'")

        elif sub == "rm":
            if len(args) < 2:
                self._err("usage: /book rm <label>")
                return
            label = " ".join(args[1:]).strip()
            if self.book.remove(label):
                self._ok(f"removed '{label}'")
            else:
                self._err(f"'{label}' not found")
        else:
            self._err("unknown subcommand")

    async def _cmd_chat(self, args: list) -> None:
        if not args:
            self._err("usage: /chat <peer_id|label|group_id|group_name>")
            return
        target = " ".join(args).strip()

        # Group lookup first — group names should win over similarly-
        # named address book labels (groups are typically more
        # distinctive).
        group = self.node._groups.lookup(target)
        if group is not None:
            self.active_peer = group.group_id
            self._ok(f"chatting in group {group.name} "
                     f"({group.member_count()} members)")
            return

        contact = self.book.get(target)
        if contact:
            peer_id = contact.peer_id
            if not self.node.discovery.get_peer(peer_id):
                self._info(f"connecting to {contact.label}...", tag="...")
                ok = await self.node.connect_to_peer(
                    contact.host, contact.port, contact.peer_id,
                    bytes.fromhex(contact.x25519_pub),
                    bytes.fromhex(contact.ed25519_pub),
                )
                if not ok:
                    self._err(f"could not reach {contact.label}")
                    return
        elif PEER_ID_RE.match(target.lower()):
            peer_id = target.lower()
        elif target.isdigit():
            peers = self.node.discovery.all_peers()
            idx = int(target)
            if 0 <= idx < len(peers):
                peer_id = peers[idx]["peer_id"]
            else:
                self._err("index out of range")
                return
        elif all(c in "0123456789abcdef" for c in target.lower()) and len(target) >= 4:
            # Partial peer_id prefix match
            prefix = target.lower()
            matches = [
                p for p in self.node.discovery.all_peers()
                if p["peer_id"].startswith(prefix)
            ]
            if len(matches) == 1:
                peer_id = matches[0]["peer_id"]
            elif len(matches) > 1:
                self._err(f"ambiguous: {len(matches)} peers match '{prefix}'")
                return
            else:
                self._err(f"no peer starts with '{prefix}'")
                return
        else:
            self._err("peer not found in book or routing table")
            return

        self.active_peer = peer_id
        contact = self.book.get_by_peer_id(peer_id)
        label = contact.label if contact else peer_id[:16] + "..."
        self._info(f"conversation with [{C_ACCENT}]{label}[/{C_ACCENT}]", tag="chat")
        self._print_conversation(peer_id)

    async def _cmd_export(self) -> None:
        onion = self.node.transport.public_address
        onion_addr = onion if onion and onion.endswith(".onion") else None

        url = generate_invite(
            self.node.identity,
            self.node.public_address,
            self.node.port,
            onion=onion_addr,
        )

        self._print()
        self._print(f"  {url}")
        self._print()
        if onion_addr:
            self._print(Panel(
                "[dim]your peer will connect via your .onion address.\n"
                "the .onion is permanent — same passphrase, same address.\n"
                "host:port in the invite is a fallback for LAN/direct connections.[/dim]",
                border_style=C_BORDER,
                title=f"[{C_DIM}]tor[/{C_DIM}]",
                title_align="left",
            ))
        else:
            self._print(Panel(
                "[dim]this invite contains your current host and port.\n"
                "it will stop working if your IP changes.\n"
                "use --tor for a permanent .onion address.[/dim]",
                border_style=C_BORDER,
                title=f"[{C_WARN}]warning[/{C_WARN}]",
                title_align="left",
            ))

    async def _cmd_import(self, args: list) -> None:
        if not args:
            self._err("usage: /import malphas://...")
            return
        url = args[0].strip()

        try:
            data = parse_invite(url)
        except ValueError as e:
            self._err(f"invalid invite: {e}")
            return

        # Show summary
        self._print()
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style=C_DIM)
        t.add_column()
        t.add_row("peer_id", data["peer_id"])
        t.add_row("host", f"{data['host']}:{data['port']}")
        if "onion" in data:
            t.add_row("onion", data["onion"])
        self._print(Panel(t, border_style=C_BORDER, title="[dim]invite[/dim]", title_align="left"))

        confirm = input("  connect? [Y/n] ").strip().lower()
        if confirm == "n":
            self._info("cancelled")
            return

        # Prefer .onion if available — hidden service maps port 80 to local port
        host = data["host"]
        port = data["port"]
        if "onion" in data:
            host = data["onion"]
            port = 80

        self._info(f"connecting to {host}:{port}...", tag="...")
        ok = await self.node.connect_to_peer(
            host, port, data["peer_id"],
            bytes.fromhex(data["x25519_pub"]),
            bytes.fromhex(data["ed25519_pub"]),
        )
        if ok:
            self._ok(f"connected  {data['peer_id'][:16]}...")
            save = input("  save to address book? [y/N] ").strip().lower()
            if save == "y":
                label = input("  label: ").strip()
                if label:
                    # Save .onion as host if available — enables auto-reconnect via Tor
                    save_host = data.get("onion", data["host"])
                    save_port = 80 if "onion" in data else data["port"]
                    self.book.add(Contact(
                        label=label, peer_id=data["peer_id"],
                        host=save_host, port=save_port,
                        x25519_pub=data["x25519_pub"],
                        ed25519_pub=data["ed25519_pub"],
                    ))
                    self._ok(f"saved as '{label}'")
        else:
            self._err("connection failed")

    async def _cmd_trust(self, args: list) -> None:
        if not args:
            self._err("usage: /trust <peer_id|label>")
            return
        target = args[0].strip()

        # Resolve label to peer_id
        contact = self.book.get(target)
        if contact:
            peer_id = contact.peer_id
        elif PEER_ID_RE.match(target.lower()):
            peer_id = target.lower()
        else:
            self._err("peer not found")
            return

        self.node.pins.trust(peer_id)
        self._ok(f"pin reset for {peer_id[:16]}... — next connection will re-pin")

    def _cmd_github(self) -> None:
        import webbrowser
        webbrowser.open(GITHUB_URL)
        self._info(GITHUB_URL, tag="github")

    async def _cmd_panic(self) -> None:
        import gc
        self.active_peer = None
        self.node.panic()
        self.book.wipe_memory()
        self._running = False
        gc.collect()
        self._print(f"\n  [{C_ERR}]wiped.[/{C_ERR}]")
        sys.exit(0)

    async def _cmd_wipe(self) -> None:
        confirm = input("  wipe all messages? [y/N] ").strip().lower()
        if confirm == "y":
            self.node.store.wipe()
            self._ok("all messages wiped")
        else:
            self._info("cancelled")

    async def _cmd_send(self, text: str) -> None:
        if not self.active_peer:
            self._err("no active conversation — use /chat <peer_id|label>")
            return
        # Group dispatch: if active_peer matches a group_id (or name we
        # have aliased to a group_id in our local state), do a fanout
        # via send_group_message.
        group = self.node._groups.lookup(self.active_peer)
        if group is not None:
            ok = await self.node.send_group_message(group.group_id, text)
            if ok:
                ts = time.strftime("%H:%M")
                self._plain(
                    f"  \033[90m{ts}\033[0m  \033[36m[{group.name}]\033[0m  "
                    f"\033[90myou\033[0m  {text}"
                )
            else:
                self._err("group send failed")
            return
        ok = await self.node.send_message(self.active_peer, text)
        if ok:
            ts = time.strftime("%H:%M")
            self._plain(f"  \033[90m{ts}  you\033[0m  {text}")
        else:
            self._err("send failed: peer unreachable or no circuit")

    # ── File transfer commands ──────────────────────────────────────────────

    def _resolve_target(self, target: str) -> str | None:
        """Resolve a label or full peer_id to a peer_id, or None if unknown."""
        target = target.strip()
        contact = self.book.get(target)
        if contact:
            return contact.peer_id
        if PEER_ID_RE.match(target.lower()):
            pid = target.lower()
            if self.node.discovery.get_peer(pid):
                return pid
            # Allow sending if peer exists in routing even without book entry
            return pid if self.node.discovery.get_peer(pid) else None
        return None

    async def _cmd_sendfile(self, args: list) -> None:
        if len(args) < 2:
            self._err("usage: /sendfile <peer_id|label> <path>")
            return
        target, path = args[0], " ".join(args[1:])

        peer_id = self._resolve_target(target)
        if not peer_id:
            self._err(f"unknown peer or label: {target}")
            return

        import os as _os
        if not _os.path.exists(path):
            self._err(f"file not found: {path}")
            return
        if not _os.path.isfile(path):
            self._err(f"not a regular file: {path}")
            return

        self._info(f"sending {_os.path.basename(path)} to {target}...", tag="...")
        file_id = await self.node.send_file(peer_id, path)
        if file_id is None:
            self._err("send_file failed (peer offline, file too large, or no circuit)")
            return
        self._ok(f"file_id  {file_id}")

    @staticmethod
    def _resolve_file_id(prefix: str, pool: dict) -> str | None:
        """Resolve a (display-truncated) file_id prefix to a full key.

        Offers are shown with a 16-char prefix, so /accept, /reject and
        /savefile must accept that prefix. Exact match wins; otherwise a
        unique startswith match; None on no match or ambiguity.
        """
        if prefix in pool:
            return prefix
        matches = [k for k in pool if k.startswith(prefix)]
        return matches[0] if len(matches) == 1 else None

    async def _cmd_accept(self, args: list) -> None:
        if not args:
            self._err("usage: /accept <file_id>")
            return
        fid = self._resolve_file_id(args[0], self._pending_offers)
        if fid is None:
            self._err(f"no pending offer with file_id {args[0]}")
            return
        from_id, offer = self._pending_offers[fid]
        ok = self.node.accept_file_offer(offer)
        if ok:
            self._ok(f"accepted {offer.get('name', '?')} from {from_id[:8]}")
            del self._pending_offers[fid]
            # Remember the offer so _on_file_complete can show the real name.
            self._accepted_offers[fid] = (from_id, offer)
            # Tell the sender we're ready so it streams the chunks now.
            await self.node.send_file_resume(from_id, fid)
        else:
            self._err("accept failed (malformed offer)")

    async def _cmd_reject(self, args: list) -> None:
        if not args:
            self._err("usage: /reject <file_id>")
            return
        fid = self._resolve_file_id(args[0], self._pending_offers)
        if fid is None:
            self._err(f"no pending offer with file_id {args[0]}")
            return
        del self._pending_offers[fid]
        self._ok(f"rejected {fid[:16]}")

    async def _cmd_savefile(self, args: list) -> None:
        if not args:
            self._err("usage: /savefile <file_id> [path]   (path defaults to ~/)")
            return
        # Path is optional: default to the home directory, which (being a
        # directory) saves under the file's original name below.
        raw_path = " ".join(args[1:]) if len(args) > 1 else "~/"
        out_path = os.path.expanduser(raw_path)
        fid = self._resolve_file_id(args[0], self._completed_files)
        if fid is None:
            self._err(f"no completed file with id {args[0]}")
            return
        entry = self._completed_files.get(fid)
        if not entry:
            self._err(f"no completed file with id {args[0]}")
            return
        from_id, name, payload = entry
        # If a directory was given, save under the original file name.
        if os.path.isdir(out_path):
            out_path = os.path.join(out_path, os.path.basename(name) or "file.bin")
        try:
            with open(out_path, "wb") as f:
                f.write(payload)
        except OSError as e:
            self._err(f"write failed: {e}")
            return
        self._ok(f"saved {len(payload)} bytes to {out_path}")
        # After saving, we drop the in-memory copy to honor zero-disk policy
        # for the in-process buffer.
        del self._completed_files[fid]

    async def _cmd_files(self, args: list) -> None:
        if not self._pending_offers and not self._completed_files:
            self._info("no file transfers", tag="files")
            return
        t = Table(show_header=True, box=None, padding=(0, 2))
        t.add_column("status", style=C_DIM, width=10)
        t.add_column("file_id", width=20)
        t.add_column("from")
        t.add_column("name")
        t.add_column("size", style=C_DIM)
        for fid, (from_id, offer) in self._pending_offers.items():
            t.add_row(
                "pending",
                fid[:16] + "...",
                from_id[:8],
                offer.get("name", "?"),
                str(offer.get("size", "?")),
            )
        for fid, (from_id, name, data) in self._completed_files.items():
            t.add_row(
                "ready",
                fid[:16] + "...",
                from_id[:8],
                name,
                str(len(data)),
            )
        self._print(Panel(t, border_style=C_BORDER, title="[dim]files[/dim]", title_align="left"))

    # ── Group chat (v0.9.0) ──────────────────────────────────────────────────

    async def _cmd_group(self, args: list) -> None:
        """Subcommand dispatcher for /group new|list|add|members|leave."""
        if not args:
            self._err(
                "usage: /group new <name> | list | add <name> <peer> | "
                "members <name> | leave <name>"
            )
            return
        sub = args[0].lower()

        if sub == "new":
            if len(args) < 2:
                self._err("usage: /group new <name>")
                return
            name = args[1]
            gid = await self.node.create_group(name, [])
            if gid is None:
                self._err(f"could not create group '{name}' (name taken?)")
                return
            self._ok(f"group {name} created  (group_id {gid})")
            self._info("add members with: /group add <name> <peer|label|peer_id>")
            return

        if sub == "list":
            groups = self.node._groups.all_groups()
            if not groups:
                self._info("no groups", tag="group")
                return
            t = Table(show_header=True, box=None, padding=(0, 2))
            t.add_column("name")
            t.add_column("group_id", style=C_DIM)
            t.add_column("members", style=C_DIM)
            for g in groups:
                t.add_row(g.name, g.group_id[:16] + "...", str(g.member_count()))
            self._print(Panel(t, border_style=C_BORDER,
                              title="[dim]groups[/dim]", title_align="left"))
            return

        if sub == "add":
            if len(args) < 3:
                self._err("usage: /group add <name> <peer|label|peer_id>")
                return
            group = self.node._groups.lookup(args[1])
            if group is None:
                self._err(f"unknown group: {args[1]}")
                return
            target = args[2]
            peer_id = self._resolve_target(target)
            if not peer_id:
                self._err(f"unknown peer or label: {target}")
                return
            ok = await self.node.add_group_member(group.group_id, peer_id)
            if ok:
                self._ok(f"added {target} to {group.name} "
                         f"({group.member_count()} members)")
            else:
                self._err("add failed (cap reached or peer offline)")
            return

        if sub == "members":
            if len(args) < 2:
                self._err("usage: /group members <name>")
                return
            group = self.node._groups.lookup(args[1])
            if group is None:
                self._err(f"unknown group: {args[1]}")
                return
            for m in group.members:
                contact = self.book.get_by_peer_id(m)
                label = contact.label if contact else m[:16]
                marker = "(you)" if m == self.node.identity.peer_id else ""
                self._info(f"{label:<24} {m[:16]}...  {marker}", tag="m")
            return

        if sub == "leave":
            if len(args) < 2:
                self._err("usage: /group leave <name>")
                return
            group = self.node._groups.lookup(args[1])
            if group is None:
                self._err(f"unknown group: {args[1]}")
                return
            self.node.leave_group(group.group_id)
            self._ok(f"left {group.name}")
            if self.active_peer == group.group_id:
                self.active_peer = None
            return

        self._err(f"unknown subcommand: /group {sub}")

    async def _on_group_invite(self, from_id: str, group_id: str,
                               group_name: str, members: list) -> None:
        contact = self.book.get_by_peer_id(from_id)
        from_label = contact.label if contact else from_id[:8]
        self._plain(
            f"  \033[36m*** {from_label} added you to group '{group_name}' "
            f"({len(members)} members) ***\033[0m"
        )
        self._plain(
            f"  \033[36m*** /chat {group_name}  to start writing ***\033[0m"
        )

    async def _on_group_message(self, from_id: str, group_id: str,
                                group_name: str, content: str) -> None:
        contact = self.book.get_by_peer_id(from_id)
        from_label = contact.label if contact else from_id[:8]
        ts = time.strftime("%H:%M")
        if self.active_peer == group_id or self.active_peer == group_name:
            self._plain(
                f"  \033[90m{ts}\033[0m  \033[36m[{group_name}]\033[0m  "
                f"\033[31m{from_label}\033[0m  {content}"
            )
        else:
            self._plain(
                f"  \033[33m<\033[0m \033[36m[{group_name}]\033[0m "
                f"{from_label}: {content}"
            )

    async def _cmd_backup(self, args: list) -> None:
        """Print the 12-word BIP39 mnemonic of the per-user salt.

        The mnemonic is the only way to recover the identity if
        ~/.malphas/salt is lost. Treat the printed words like a
        passphrase: write them down, do not screenshot, do not paste
        into a chat.
        """
        if self._salt_path is None:
            self._err("salt path not configured (running without --salt?)")
            return
        try:
            from .mnemonic import salt_to_mnemonic
            from .salt_store import SALT_LEN
        except ImportError as e:
            self._err(f"backup unavailable: {e}")
            return
        try:
            data = self._salt_path.read_bytes()
        except OSError as e:
            self._err(f"cannot read salt at {self._salt_path}: {e}")
            return
        if len(data) != SALT_LEN:
            self._err(f"salt at {self._salt_path} has wrong length ({len(data)})")
            return
        words = salt_to_mnemonic(data).split()
        self._print()
        self._warn("write these 12 words down — they recover your identity")
        for i, word in enumerate(words, start=1):
            self._print(f"  [{C_DIM}]{i:>2}.[/{C_DIM}] [{C_LABEL}]{word}[/{C_LABEL}]")
        self._print()

    async def _on_file_offer(self, from_id: str, offer: dict) -> None:
        """Hook fired by the node when a new file offer arrives."""
        fid = offer.get("file_id", "")
        if not fid:
            return
        contact = self.book.get_by_peer_id(from_id)
        from_label = contact.label if contact else from_id[:8]
        self._pending_offers[fid] = (from_id, offer)
        name = offer.get("name", "?")
        size = offer.get("size", 0)
        self._plain(
            f"  \033[33m*** offer from {from_label}: {name} ({size} bytes)\033[0m"
        )
        self._plain(
            f"  \033[33m*** /accept {fid[:16]}  or  /reject {fid[:16]} ***\033[0m"
        )

    async def _on_file_complete(self, file_id: str, data: bytes) -> None:
        """Hook fired by the node when a transfer is fully assembled."""
        # Recover the original name/sender from the offer we accepted (or a
        # still-pending one, e.g. auto-accept).
        offer_entry = (self._accepted_offers.pop(file_id, None)
                       or self._pending_offers.pop(file_id, None))
        if offer_entry is not None:
            from_id, offer = offer_entry
            name = offer.get("name", "file.bin")
        else:
            from_id, name = "?", "file.bin"
        self._completed_files[file_id] = (from_id, name, data)
        contact = self.book.get_by_peer_id(from_id)
        label = contact.label if contact else from_id[:8]
        self._plain(
            f"  \033[32m*** received {name} ({len(data)} bytes) from {label}\033[0m"
        )
        self._plain(
            f"  \033[32m*** /savefile {file_id[:16]} [path]  (path defaults to ~/) ***\033[0m"
        )

    async def _auto_connect(self) -> None:
        contacts = self.book.all()
        if not contacts:
            return
        self._info(f"auto-connecting {len(contacts)} contact(s)...", tag="book")
        for c in contacts:
            try:
                ok = await self.node.connect_to_peer(
                    c.host, c.port, c.peer_id,
                    bytes.fromhex(c.x25519_pub),
                    bytes.fromhex(c.ed25519_pub),
                )
                if ok:
                    self._ok(f"connected: {c.label}")
                else:
                    self._info(f"unreachable: {c.label}", tag="-")
            except Exception:
                self._info(f"unreachable: {c.label}", tag="-")

    # ── Main loop ────────────────────────────────────────────────────────

    def _on_pin_violation(self, peer_id: str, expected: str, received: str):
        contact = self.book.get_by_peer_id(peer_id)
        label = contact.label if contact else peer_id[:8]
        self._plain(f"  \033[31m!!! KEY MISMATCH for {label} !!!\033[0m")
        self._plain(f"  \033[31mexpected {expected[:16]}... got {received[:16]}...\033[0m")
        self._plain(f"  \033[31mconnection rejected. use /trust {peer_id[:8]} to reset\033[0m")

    async def run(self) -> None:
        self.node.on_message(self._on_message)
        self.node.on_receipt(self._on_receipt)
        self.node.on_pin_violation(self._on_pin_violation)
        self.node.on_file_offer(self._on_file_offer)
        self.node.on_file_complete(self._on_file_complete)
        self.node.on_group_invite(self._on_group_invite)
        self.node.on_group_message(self._on_group_message)
        self.node.set_reconnect_book(self.book)

        # Banner
        self._print()
        self._print(Panel(
            f"  [dim]peer_id[/dim]  {self.node.identity.peer_id}\n"
            f"  [dim]port[/dim]     {self.node.port}\n"
            + (f"  [dim]book[/dim]     {len(self.book)} contact(s)\n" if len(self.book) > 0 else "")
            + "\n  [dim]/help for commands[/dim]",
            title=f"[{C_DIM}]malphas[/{C_DIM}]",
            border_style=C_BORDER,
            title_align="left",
        ))
        self._print()

        if len(self.book) > 0:
            asyncio.create_task(self._auto_connect())

        session = PromptSession(
            history=InMemoryHistory(),
            completer=MalphasCompleter(self.node, self.book),
            complete_while_typing=False,
        )

        while self._running:
            try:
                # Build bottom toolbar with status
                toolbar_text = self._status_bar()

                with patch_stdout():
                    line = await session.prompt_async(
                        "> ",
                        bottom_toolbar=lambda: toolbar_text,
                    )

                if not line:
                    continue
                line = line.strip()
                if not line:
                    continue

                if line.startswith("/"):
                    parts = line[1:].split()
                    cmd = parts[0].lower() if parts else ""
                    args = parts[1:]

                    if cmd in ("quit", "exit"):
                        self._running = False
                        break
                    elif cmd == "id":
                        self._print_identity()
                    elif cmd == "peers":
                        self._print_peers()
                    elif cmd == "book":
                        await self._cmd_book(args)
                    elif cmd == "add":
                        await self._cmd_add(args)
                    elif cmd == "chat":
                        await self._cmd_chat(args)
                    elif cmd == "history":
                        if self.active_peer:
                            self._print_conversation(self.active_peer)
                        else:
                            self._err("no active conversation")
                    elif cmd == "export":
                        await self._cmd_export()
                    elif cmd == "import":
                        await self._cmd_import(args)
                    elif cmd == "trust":
                        await self._cmd_trust(args)
                    elif cmd == "github":
                        self._cmd_github()
                    elif cmd == "wipe":
                        await self._cmd_wipe()
                    elif cmd == "panic":
                        await self._cmd_panic()
                    elif cmd == "sendfile":
                        await self._cmd_sendfile(args)
                    elif cmd == "accept":
                        await self._cmd_accept(args)
                    elif cmd == "reject":
                        await self._cmd_reject(args)
                    elif cmd == "savefile":
                        await self._cmd_savefile(args)
                    elif cmd == "files":
                        await self._cmd_files(args)
                    elif cmd == "backup":
                        await self._cmd_backup(args)
                    elif cmd == "group":
                        await self._cmd_group(args)
                    elif cmd == "help":
                        self._print_help()
                    else:
                        self._err(f"unknown command: /{cmd}  (/help)")
                else:
                    await self._cmd_send(line)

            except (KeyboardInterrupt, EOFError):
                break
            except Exception:
                pass

        self._print(f"\n  [{C_DIM}]shutting down...[/{C_DIM}]")
