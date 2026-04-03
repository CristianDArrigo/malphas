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
import re
import sys
import time
from io import StringIO
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
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
    "/export", "/import", "/wipe", "/panic", "/help", "/quit", "/exit",
]


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
    def __init__(self, node: MalphasNode, book: AddressBook):
        self.node = node
        self.book = book
        self.active_peer: Optional[str] = None
        self._running = True
        self._console = _make_console()

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

    async def _on_message(self, from_id: str, content: str) -> None:
        contact = self.book.get_by_peer_id(from_id)
        label = contact.label if contact else from_id[:8]
        ts = time.strftime("%H:%M")

        if from_id == self.active_peer:
            self._print(f"  [{C_DIM}]{ts}[/{C_DIM}] [{C_ACCENT}]{label}[/{C_ACCENT}]  {content}")
        else:
            self._warn(f"new message from [{C_ACCENT}]{label}[/{C_ACCENT}]  (/chat {from_id[:8]})")

    async def _on_receipt(self, msg_id: str, dest_peer_id: str, received: bool) -> None:
        contact = self.book.get_by_peer_id(dest_peer_id)
        label = contact.label if contact else dest_peer_id[:8]
        if received:
            self._ok(f"read by {label}")
        else:
            self._warn(f"no receipt from {label}")

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
                self._print(f"  [{C_DIM}]{ts}  you[/{C_DIM}]  {m['content']}")
            else:
                contact = self.book.get_by_peer_id(m["from_peer"])
                name = contact.label if contact else m["from_peer"][:8]
                self._print(f"  [{C_DIM}]{ts}[/{C_DIM}]  [{C_ACCENT}]{name}[/{C_ACCENT}]  {m['content']}")

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
            ("/wipe", "wipe all messages from memory"),
            ("/panic", "EMERGENCY: wipe everything and exit"),
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
            self._err("usage: /chat <peer_id|label>")
            return
        target = " ".join(args).strip()

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
        self._print(Panel(
            "[dim]this invite contains your current host and port.\n"
            "it will stop working if your IP changes.\n"
            "if running with --tor, the .onion address is permanent.[/dim]",
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

        # Prefer .onion if available
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
                    self.book.add(Contact(
                        label=label, peer_id=data["peer_id"],
                        host=data["host"], port=data["port"],
                        x25519_pub=data["x25519_pub"],
                        ed25519_pub=data["ed25519_pub"],
                    ))
                    self._ok(f"saved as '{label}'")
        else:
            self._err("connection failed")

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
        ok = await self.node.send_message(self.active_peer, text)
        if ok:
            ts = time.strftime("%H:%M")
            self._print(f"  [{C_DIM}]{ts}  you[/{C_DIM}]  {text}")
        else:
            self._err("send failed: peer unreachable or no circuit")

    async def _auto_connect(self) -> None:
        contacts = self.book.all()
        if not contacts:
            return
        self._info(f"auto-connecting {len(contacts)} contact(s)...", tag="book")
        for c in contacts:
            ok = await self.node.connect_to_peer(
                c.host, c.port, c.peer_id,
                bytes.fromhex(c.x25519_pub),
                bytes.fromhex(c.ed25519_pub),
            )
            if ok:
                self._ok(f"connected: {c.label}")
            else:
                self._info(f"unreachable: {c.label}", tag="-")

    # ── Main loop ────────────────────────────────────────────────────────

    async def run(self) -> None:
        self.node.on_message(self._on_message)
        self.node.on_receipt(self._on_receipt)

        # Banner
        self._print()
        self._print(Panel(
            f"  [dim]peer_id[/dim]  {self.node.identity.peer_id}\n"
            f"  [dim]port[/dim]     {self.node.port}\n"
            + (f"  [dim]book[/dim]     {len(self.book)} contact(s)\n" if len(self.book) > 0 else "")
            + f"\n  [dim]/help for commands[/dim]",
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
                    elif cmd == "wipe":
                        await self._cmd_wipe()
                    elif cmd == "panic":
                        await self._cmd_panic()
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
