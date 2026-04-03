"""
Malphas CLI — interactive terminal messenger with encrypted address book.

Commands:
  /id                     show own identity (peer_id + pubkeys)
  /peers                  list connected peers
  /book                   list address book contacts
  /book add <label>       save active peer to address book
  /book rm <label>        remove contact from address book
  /add <host> <port>      connect to peer manually
  /chat <peer_id|label>   open conversation
  /history                show conversation history
  /wipe                   wipe all messages from memory
  /quit                   shutdown
  <text>                  send message to active conversation
"""

import asyncio
import sys
import re
import shutil
from typing import Optional

from .addressbook import AddressBook, Contact
from .node import MalphasNode

PEER_ID_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TERM_WIDTH = shutil.get_terminal_size((80, 24)).columns


def _hr():
    return "─" * TERM_WIDTH


def _clear_line():
    sys.stdout.write("\r\033[2K")
    sys.stdout.flush()


def _print(msg: str, prefix: str = ""):
    _clear_line()
    if prefix:
        print(f"\033[90m{prefix}\033[0m {msg}")
    else:
        print(msg)
    _redraw_prompt()


def _redraw_prompt():
    sys.stdout.write("\033[90m›\033[0m ")
    sys.stdout.flush()


class MalphasCLI:
    def __init__(self, node: MalphasNode, book: AddressBook):
        self.node = node
        self.book = book
        self.active_peer: Optional[str] = None
        self._running = True

    async def _on_message(self, from_id: str, content: str) -> None:
        contact = self.book.get_by_peer_id(from_id)
        label = contact.label if contact else from_id[:8]
        if from_id == self.active_peer:
            _print(content, prefix=f"[{label}]")
        else:
            _print(f"new message from {label}  (/chat {from_id[:8]})", prefix="[!]")

    async def _on_receipt(self, msg_id: str, dest_peer_id: str, received: bool) -> None:
        contact = self.book.get_by_peer_id(dest_peer_id)
        label = contact.label if contact else dest_peer_id[:8]
        if received:
            _print(f"read by {label}", prefix="[ok]")
        else:
            _print(f"no receipt from {label} — circuit issue or peer offline", prefix="[!]")

    def _print_identity(self):
        id_ = self.node.identity
        print()
        print(_hr())
        print(f"  peer_id     {id_.peer_id}")
        print(f"  x25519_pub  {id_.x25519_pub_bytes.hex()}")
        print(f"  ed25519_pub {id_.ed25519_pub_bytes.hex()}")
        print(f"  port        {self.node.port}")
        print(_hr())
        print()

    def _print_peers(self):
        peers = self.node.discovery.all_peers()
        if not peers:
            _print("no peers connected", prefix="[peers]")
            return
        print()
        print(_hr())
        for i, p in enumerate(peers):
            contact = self.book.get_by_peer_id(p["peer_id"])
            label = f"  {contact.label}" if contact else ""
            marker = " *" if p["peer_id"] == self.active_peer else f" {i}"
            print(f"{marker}  {p['peer_id'][:16]}…  {p['host']}:{p['port']}{label}")
        print(_hr())
        print()

    def _print_book(self):
        contacts = self.book.all()
        if not contacts:
            _print("address book is empty", prefix="[book]")
            return
        print()
        print(_hr())
        for c in contacts:
            marker = " *" if c.peer_id == self.active_peer else "  "
            print(f"{marker} {c.label:<20}  {c.peer_id[:16]}…  {c.host}:{c.port}")
        print(_hr())
        print()

    def _print_conversation(self, peer_id: str):
        import time
        msgs = self.node.store.get_conversation(self.node.identity.peer_id, peer_id)
        if not msgs:
            _print("no messages yet", prefix="")
            return
        print()
        print(_hr())
        for m in msgs:
            ts = time.strftime("%H:%M", time.localtime(m["timestamp"]))
            if m["from_peer"] == self.node.identity.peer_id:
                label = f"\033[90m[{ts}] you\033[0m"
            else:
                contact = self.book.get_by_peer_id(m["from_peer"])
                name = contact.label if contact else m["from_peer"][:8]
                label = f"\033[90m[{ts}] {name}\033[0m"
            print(f"  {label}  {m['content']}")
        print(_hr())
        print()

    def _print_help(self):
        cmds = [
            ("/id",                     "show peer_id and public keys"),
            ("/peers",                  "list connected peers"),
            ("/book",                   "list address book contacts"),
            ("/book add <label>",       "save active peer to address book"),
            ("/book rm <label>",        "remove contact from address book"),
            ("/add <host> <port>",      "connect to a peer manually"),
            ("/chat <peer_id|label>",   "open a conversation"),
            ("/history",                "show conversation history"),
            ("/wipe",                   "wipe all messages from memory"),
            ("/panic",                  "EMERGENCY: wipe everything and exit immediately"),
            ("/quit",                   "shutdown"),
            ("<text>",                  "send message to active conversation"),
        ]
        print()
        print(_hr())
        for cmd, desc in cmds:
            print(f"  \033[90m{cmd:<30}\033[0m {desc}")
        print(_hr())
        print()

    async def _cmd_add(self, args: list) -> None:
        if len(args) < 2:
            _print("usage: /add <host> <port>", prefix="[err]")
            return
        host = args[0]
        try:
            port = int(args[1])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            _print("invalid port", prefix="[err]")
            return

        print()
        peer_id = input("  peer_id (40-char hex): ").strip().lower()
        if not PEER_ID_RE.match(peer_id):
            _print("invalid peer_id", prefix="[err]")
            return
        x25519_pub = input("  x25519_pub (64-char hex): ").strip().lower()
        if not HEX64_RE.match(x25519_pub):
            _print("invalid x25519_pub", prefix="[err]")
            return
        ed25519_pub = input("  ed25519_pub (64-char hex): ").strip().lower()
        if not HEX64_RE.match(ed25519_pub):
            _print("invalid ed25519_pub", prefix="[err]")
            return

        print()
        _print(f"connecting to {host}:{port}…", prefix="[…]")
        ok = await self.node.connect_to_peer(
            host, port, peer_id,
            bytes.fromhex(x25519_pub),
            bytes.fromhex(ed25519_pub),
        )

        if ok:
            _print(f"connected  {peer_id[:16]}…", prefix="[ok]")
            save = input("  save to address book? [y/N] ").strip().lower()
            if save == "y":
                label = input("  label: ").strip()
                if label:
                    self.book.add(Contact(
                        label=label, peer_id=peer_id,
                        host=host, port=port,
                        x25519_pub=x25519_pub, ed25519_pub=ed25519_pub,
                    ))
                    _print(f"saved as '{label}'", prefix="[book]")
                else:
                    _print("label empty, not saved", prefix="[—]")
        else:
            _print("connection failed", prefix="[err]")

    async def _cmd_book(self, args: list) -> None:
        if not args:
            self._print_book()
            return
        sub = args[0].lower()

        if sub == "add":
            if not self.active_peer:
                _print("no active conversation", prefix="[err]")
                return
            label = " ".join(args[1:]).strip() or input("  label: ").strip()
            if not label:
                _print("label cannot be empty", prefix="[err]")
                return
            peer = self.node.discovery.get_peer(self.active_peer)
            if not peer:
                _print("peer not in routing table", prefix="[err]")
                return
            self.book.add(Contact(
                label=label, peer_id=self.active_peer,
                host=peer.host, port=peer.port,
                x25519_pub=peer.x25519_pub.hex(),
                ed25519_pub=peer.ed25519_pub.hex(),
            ))
            _print(f"saved as '{label}'", prefix="[book]")

        elif sub == "rm":
            if len(args) < 2:
                _print("usage: /book rm <label>", prefix="[err]")
                return
            label = " ".join(args[1:]).strip()
            if self.book.remove(label):
                _print(f"removed '{label}'", prefix="[book]")
            else:
                _print(f"'{label}' not found", prefix="[err]")
        else:
            _print("unknown subcommand — /book | /book add <label> | /book rm <label>", prefix="[err]")

    async def _cmd_chat(self, args: list) -> None:
        if not args:
            _print("usage: /chat <peer_id|label>", prefix="[err]")
            return
        target = " ".join(args).strip()

        # Try address book label first
        contact = self.book.get(target)
        if contact:
            peer_id = contact.peer_id
            if not self.node.discovery.get_peer(peer_id):
                _print(f"connecting to {contact.label}…", prefix="[…]")
                ok = await self.node.connect_to_peer(
                    contact.host, contact.port, contact.peer_id,
                    bytes.fromhex(contact.x25519_pub),
                    bytes.fromhex(contact.ed25519_pub),
                )
                if not ok:
                    _print(f"could not reach {contact.label}", prefix="[err]")
                    return
        elif PEER_ID_RE.match(target.lower()):
            peer_id = target.lower()
        elif target.isdigit():
            peers = self.node.discovery.all_peers()
            idx = int(target)
            if 0 <= idx < len(peers):
                peer_id = peers[idx]["peer_id"]
            else:
                _print("index out of range", prefix="[err]")
                return
        else:
            _print("peer not found in book or routing table", prefix="[err]")
            return

        self.active_peer = peer_id
        contact = self.book.get_by_peer_id(peer_id)
        label = contact.label if contact else peer_id[:16] + "…"
        _print(f"conversation with {label}", prefix="[chat]")
        self._print_conversation(peer_id)

    async def _cmd_panic(self) -> None:
        """
        Emergency wipe — no confirmation, speed is the point.
        Clears all in-memory state and exits immediately.
        The address book file on disk remains, but without the
        passphrase it is indistinguishable from random noise.
        """
        import sys, gc

        self.active_peer = None
        self.node.panic()
        self.book.wipe_memory()
        self._running = False

        gc.collect()

        _clear_line()
        print("  wiped.")

        sys.exit(0)

    async def _cmd_wipe(self) -> None:
        confirm = input("  wipe all messages? [y/N] ").strip().lower()
        if confirm == "y":
            self.node.store.wipe()
            _print("all messages wiped", prefix="[ok]")
        else:
            _print("cancelled", prefix="[—]")

    async def _cmd_send(self, text: str) -> None:
        if not self.active_peer:
            _print("no active conversation — use /chat <peer_id|label>", prefix="[err]")
            return
        ok = await self.node.send_message(self.active_peer, text)
        if ok:
            import time
            ts = time.strftime("%H:%M")
            _clear_line()
            print(f"  \033[90m[{ts}] you\033[0m  {text}")
        else:
            _print("send failed: peer unreachable or no circuit", prefix="[err]")

    async def _auto_connect(self) -> None:
        contacts = self.book.all()
        if not contacts:
            return
        _print(f"auto-connecting {len(contacts)} contact(s)…", prefix="[book]")
        for c in contacts:
            ok = await self.node.connect_to_peer(
                c.host, c.port, c.peer_id,
                bytes.fromhex(c.x25519_pub),
                bytes.fromhex(c.ed25519_pub),
            )
            if ok:
                _print(f"connected: {c.label}", prefix="[ok]")
            else:
                _print(f"unreachable: {c.label}", prefix="[—]")

    async def run(self) -> None:
        self.node.on_message(self._on_message)
        self.node.on_receipt(self._on_receipt)

        print()
        print(_hr())
        print("  malphas  —  privacy-first P2P messenger")
        print(f"  peer_id  {self.node.identity.peer_id}")
        print(f"  port     {self.node.port}")
        if len(self.book) > 0:
            print(f"  book     {len(self.book)} contact(s)")
        print()
        print("  /help for commands")
        print(_hr())
        print()

        if len(self.book) > 0:
            asyncio.create_task(self._auto_connect())

        loop = asyncio.get_running_loop()

        while self._running:
            try:
                _redraw_prompt()
                try:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                except asyncio.CancelledError:
                    break
                if not line:
                    break
                line = line.rstrip("\n").strip()
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
                            _print("no active conversation", prefix="[err]")
                    elif cmd == "wipe":
                        await self._cmd_wipe()
                    elif cmd == "panic":
                        await self._cmd_panic()
                    elif cmd == "help":
                        self._print_help()
                    else:
                        _print(f"unknown command: /{cmd}  (/help)", prefix="[err]")
                else:
                    await self._cmd_send(line)

            except (KeyboardInterrupt, EOFError):
                break
            except Exception:
                pass

        print("\n  shutting down…")
