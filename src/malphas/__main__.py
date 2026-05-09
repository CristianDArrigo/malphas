"""
Malphas entrypoint.

Modes:
  python -m malphas                    # CLI interactive (default)
  python -m malphas --mode web         # PWA + API server

Address book is stored encrypted at ~/.malphas/book (configurable via --book).
"""

import argparse
import asyncio
import getpass
import os
import signal
import sys
from pathlib import Path

from .addressbook import AddressBook
from .identity import create_identity_with_book_key
from .mnemonic import mnemonic_to_salt, salt_to_mnemonic
from .node import MalphasNode
from .pinstore import PinStore
from .salt_store import SALT_LEN, load_or_create_salt
from .splash import print_splash
from .transport import DirectTransport, TorTransport, tor_is_available

DEFAULT_BOOK_PATH = str(Path.home() / ".malphas" / "book")
DEFAULT_SALT_PATH = str(Path.home() / ".malphas" / "salt")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "showcase")


def _resolve_salt(args) -> bytes:
    """
    Decide where the per-user salt comes from, in priority order:
      1. `--from-mnemonic <words>` — restore from a 12-word BIP39
         backup. The salt is written to args.salt if absent;
         otherwise verified to match.
      2. `args.salt` file — read if present, generate if absent
         (the existing v0.7.0 flow).

    On a fresh generation (path didn't exist), prints the mnemonic
    once, big and visible, so the user can write it down. The
    same is shown by the `/backup` CLI command on demand.
    """
    salt_path = Path(args.salt)

    if args.from_mnemonic:
        try:
            salt = mnemonic_to_salt(args.from_mnemonic)
        except ValueError as e:
            print(f"  error: {e}", file=sys.stderr)
            sys.exit(2)

        if salt_path.exists():
            existing = salt_path.read_bytes()
            if existing != salt:
                print(
                    f"  error: {salt_path} already exists with a different "
                    "salt.\n  Refusing to overwrite — this would replace "
                    "your existing identity.",
                    file=sys.stderr,
                )
                sys.exit(2)
            print(f"  mnemonic matches existing salt at {salt_path}.")
        else:
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = salt_path.with_suffix(".salt-tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(salt)
            os.replace(str(tmp), str(salt_path))
            print(f"  salt restored from mnemonic into {salt_path}.")
        return salt

    # Standard flow — load_or_create. Detect "we just generated it"
    # by checking existence before the call.
    fresh = not salt_path.exists()
    salt = load_or_create_salt(salt_path)
    if fresh:
        words = salt_to_mnemonic(salt)
        print()
        print("  ┌─ first run on this machine ──────────────────────────────┐")
        print("  │ a per-user salt has been generated and saved.            │")
        print("  │ write down these 12 words — they are the ONLY way to     │")
        print(f"  │ recover this identity if {salt_path} is lost. │")
        print("  └──────────────────────────────────────────────────────────┘")
        print()
        for i, word in enumerate(words.split(), start=1):
            print(f"    {i:2d}. {word}")
        print()
        print("  to restore on another machine:  malphas --from-mnemonic \"...\"")
        print()
    return salt


def _open_book_with_migration(
    book_path: Path,
    passphrase: str,
    salt: bytes,
) -> tuple[AddressBook, bytes, "object"]:
    """
    Resolve identity + open the address book, with auto-migration from
    the pre-0.7.0 fixed-salt format.

    Pre-0.7.0 the Argon2 salt was the constant `b"malphas-kdf-salt"`.
    A user upgrading from <=0.6.x has a `~/.malphas/book` cipher
    file encrypted under a `book_key` derived from THAT salt; passing
    the new per-user random salt produces a different `book_key` and
    decryption fails. We detect the failure, retry with the legacy
    salt, and if that succeeds we re-emit the book under the new key
    so the next run is clean.

    Returns (book, book_key, identity).
    """
    identity, book_key = create_identity_with_book_key(passphrase, salt)
    book = AddressBook(str(book_path), book_key)

    if not book_path.exists() or book_path.stat().st_size == 0:
        # Fresh install — no migration needed.
        book.load()
        return book, book_key, identity

    try:
        book.load()
        return book, book_key, identity
    except ValueError:
        # Try legacy salt (pre-0.7.0).
        legacy_id, legacy_key = create_identity_with_book_key(passphrase, salt=None)
        legacy_book = AddressBook(str(book_path), legacy_key)
        try:
            legacy_book.load()
        except ValueError:
            # Genuinely the wrong passphrase or corrupted file.
            raise

        # Migration succeeded under the legacy key. Re-emit the contacts
        # under the new (per-user-salt-derived) key.
        print("  address book: migrating from pre-0.7.0 fixed-salt format…")
        for c in legacy_book.all():
            book.add(c)
        legacy_book.wipe_memory()
        print(f"  address book migrated ({len(book)} contact(s)). "
              "consider running /book to verify, then /backup to save "
              "the 12-word recovery mnemonic.")
        return book, book_key, identity


def _get_passphrase() -> str:
    print("  your identity is derived deterministically from this passphrase.")
    print("  it is never stored. the same passphrase always produces the same identity.")
    print()
    print("  weak passphrases (e.g. 'admin', 'password') make your peer_id")
    print("  precalculable by anyone who knows the algorithm. use at least")
    print("  4 random words or a long unpredictable phrase.")
    print("  example: corvo-vetro-martello-1987-luna")
    print()
    passphrase = getpass.getpass("  passphrase: ")
    if not passphrase:
        print("  passphrase cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return passphrase


async def _run_cli(args) -> None:
    from .cli_ui import MalphasCLI

    print_splash()
    passphrase = _get_passphrase()
    salt = _resolve_salt(args)

    # Ensure book directory exists
    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        book, book_key, identity = _open_book_with_migration(
            book_path, passphrase, salt
        )
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        print("  wrong passphrase or corrupted address book.", file=sys.stderr)
        sys.exit(1)
    passphrase = ""
    del passphrase
    if len(book) > 0:
        print(f"  address book loaded ({len(book)} contact(s))")

    transport = DirectTransport()
    if args.tor:
        available = await tor_is_available(socks_port=args.socks_port)
        if not available:
            print(f"  error: Tor SOCKS5 not found on port {args.socks_port}", file=sys.stderr)
            print("  make sure Tor is running: sudo systemctl start tor", file=sys.stderr)
            sys.exit(1)
        transport = TorTransport(
            socks_port=args.socks_port,
            control_port=args.control_port,
        )

    # Pin store — same directory as address book, encrypted with same key
    pin_path = str(book_path.parent / "pins")
    pins = PinStore(pin_path, book_key)
    pins.load()

    node = MalphasNode(
        identity=identity,
        host=args.host,
        port=args.port,
        message_ttl=args.ttl,
        transport=transport,
        pin_store=pins,
    )
    await node.start()

    if args.tor:
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
            )
            priv_bytes = identity.ed25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            onion = await transport.start_hidden_service(
                identity.ed25519_pub_bytes, priv_bytes, args.port
            )
            print(f"  onion    {onion}")
        except Exception as e:
            print(f"  warning: hidden service registration failed: {e}", file=sys.stderr)
            print("  continuing without hidden service (outbound Tor only)", file=sys.stderr)

    loop = asyncio.get_running_loop()
    cli = MalphasCLI(node, book, salt_path=Path(args.salt))

    def _shutdown():
        cli._running = False

    if sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)

    try:
        await cli.run()
    except KeyboardInterrupt:
        _shutdown()
    finally:
        await node.stop()
        book.wipe_memory()


async def _run_web(args) -> None:
    import uvicorn

    from .api import create_app

    passphrase = _get_passphrase()
    salt = _resolve_salt(args)

    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        book, book_key, identity = _open_book_with_migration(
            book_path, passphrase, salt
        )
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        sys.exit(1)
    passphrase = ""
    del passphrase

    print(f"  peer_id  {identity.peer_id}")
    print(f"  p2p      {args.host}:{args.port}")
    print(f"  api      http://127.0.0.1:{args.api_port}")

    node = MalphasNode(
        identity=identity,
        host=args.host,
        port=args.port,
        message_ttl=args.ttl,
    )
    await node.start()

    # Auto-connect from address book
    for c in book.all():
        await node.connect_to_peer(
            c.host, c.port, c.peer_id,
            bytes.fromhex(c.x25519_pub),
            bytes.fromhex(c.ed25519_pub),
        )

    app = create_app(node, STATIC_DIR)
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=args.api_port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)

    loop = asyncio.get_running_loop()

    def _shutdown():
        loop.create_task(node.stop())
        server.should_exit = True

    if sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)

    await server.serve()
    await node.stop()
    book.wipe_memory()


def _run_gui(args) -> None:
    """Synchronous entry: prompt passphrase + salt on the terminal,
    spin a node + asyncio bridge, then enter the Tk mainloop."""
    from .gui import AsyncBridge, launch_gui

    print_splash()
    passphrase = _get_passphrase()
    salt = _resolve_salt(args)

    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        book, book_key, identity = _open_book_with_migration(
            book_path, passphrase, salt
        )
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        sys.exit(1)
    passphrase = ""  # noqa: S105 — overwriting the local for hygiene
    del passphrase
    if len(book) > 0:
        print(f"  address book loaded ({len(book)} contact(s))")

    pin_path = str(book_path.parent / "pins")
    pins = PinStore(pin_path, book_key)
    pins.load()

    transport = DirectTransport()
    if args.tor:
        # Same async availability check as _run_cli but called sync.
        import asyncio as _asyncio
        if not _asyncio.run(tor_is_available(socks_port=args.socks_port)):
            print(f"  error: Tor SOCKS5 not found on port {args.socks_port}",
                  file=sys.stderr)
            sys.exit(1)
        transport = TorTransport(
            socks_port=args.socks_port,
            control_port=args.control_port,
        )

    node = MalphasNode(
        identity=identity,
        host=args.host,
        port=args.port,
        message_ttl=args.ttl,
        transport=transport,
        pin_store=pins,
    )

    bridge = AsyncBridge()
    # node.start has to run on the asyncio thread so its background
    # tasks live there.
    bridge.submit_coro(node.start()).result(timeout=10.0)
    node.set_reconnect_book(book)

    print(f"  peer_id  {identity.peer_id}")
    print(f"  port     {args.port}")
    print("  launching GUI...")

    try:
        launch_gui(node, book, bridge, salt_path=Path(args.salt))
    finally:
        # mainloop returned — make sure the background loop is down.
        try:
            bridge.submit_coro(node.stop()).result(timeout=3.0)
        except Exception:
            pass
        bridge.stop(timeout=2.0)
        book.wipe_memory()


def main():
    from . import __version__

    parser = argparse.ArgumentParser(description="Malphas P2P messenger")
    parser.add_argument(
        "--version",
        action="version",
        version=f"malphas {__version__}",
    )
    parser.add_argument("--mode", choices=["cli", "web", "gui"], default="cli")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--api-port", type=int, default=8080)
    parser.add_argument("--ttl", type=int, default=3600)
    parser.add_argument(
        "--tor", action="store_true",
        help="Route all connections through Tor (requires Tor running)"
    )
    parser.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS5 port")
    parser.add_argument("--control-port", type=int, default=9051, help="Tor control port")
    parser.add_argument(
        "--book", default=DEFAULT_BOOK_PATH,
        help=f"Address book file path (default: {DEFAULT_BOOK_PATH})"
    )
    parser.add_argument(
        "--salt", default=DEFAULT_SALT_PATH,
        help=(
            f"Per-user Argon2 salt file (default: {DEFAULT_SALT_PATH}). "
            "Generated on first run, mode 0600. Lose it = lose the identity."
        ),
    )
    parser.add_argument(
        "--from-mnemonic",
        default=None,
        metavar='"WORD WORD ... WORD"',
        help=(
            "Restore the per-user salt from a 12-word BIP39 mnemonic "
            "(printed on first run). The salt file is written if absent; "
            "if it exists, it is verified to match — startup aborts on "
            "mismatch."
        ),
    )
    args = parser.parse_args()

    if args.mode == "web":
        asyncio.run(_run_web(args))
    elif args.mode == "gui":
        _run_gui(args)
    else:
        asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
