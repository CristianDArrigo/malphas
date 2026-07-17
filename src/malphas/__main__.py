"""
Malphas entrypoint.

Modes:
  python -m malphas                    # CLI interactive (default)
  python -m malphas --mode gui-qt      # desktop GUI (PySide6)

Address book is stored encrypted at ~/.malphas/book (configurable via --book).
"""

import argparse
import asyncio
import getpass
import logging
import os
import signal
import sys
from pathlib import Path

from . import identity_store
from .addressbook import AddressBook
from .identity import Identity
from .mnemonic import mnemonic_to_root, root_to_mnemonic
from .node import MalphasNode
from .pinstore import PinStore, PinStoreCorruptError
from .splash import print_splash
from .transport import DirectTransport, TorTransport, tor_is_available

DEFAULT_BOOK_PATH = str(Path.home() / ".malphas" / "book")
DEFAULT_IDENTITY_PATH = str(Path.home() / ".malphas" / "identity")


def _print_first_run_mnemonic(mnemonic: str, identity_path: Path) -> None:
    words = mnemonic.split()
    print()
    print("  +-- first run on this machine ------------------------------+")
    print("  | a random identity has been generated and encrypted under  |")
    print("  | your passphrase. write down these 24 words: they are the  |")
    print("  | ONLY way to recover this identity if the file is lost.    |")
    print("  +-----------------------------------------------------------+")
    print()
    for i, word in enumerate(words, start=1):
        print(f"    {i:2d}. {word}")
    print()
    print("  to restore on another machine:  malphas --from-mnemonic")
    print("  to change your passphrase:      /passwd  (in the app)")
    print()


def _open_book(book_path: Path, book_key: bytes, fresh: bool) -> AddressBook:
    """Open the encrypted address book under `book_key`.

    On a freshly-created/restored identity, a pre-existing book that cannot be
    decrypted under the new key is expected (it belonged to a different
    identity); start empty rather than crash. Otherwise a decryption failure is
    a real error and propagates.
    """
    book = AddressBook(str(book_path), book_key)
    try:
        book.load()
    except ValueError:
        if fresh:
            print("  note: an existing address book could not be read under "
                  "this identity; starting with an empty book.")
            book.init_empty()
        else:
            raise
    return book


def _setup_identity_and_book(
    args,
) -> tuple[Identity, AddressBook, bytes, str, Path]:
    """
    Resolve the identity (random root wrapped under a passphrase-KEK) and open
    the address book. Handles first run, restore-from-mnemonic, and normal
    unlock. Returns (identity, book, book_key, recovery_mnemonic, identity_path).
    """
    identity_path = Path(args.identity)
    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)

    exists = identity_store.identity_file_exists(str(identity_path))

    if args.from_mnemonic:
        if exists:
            print(f"  error: {identity_path} already exists.\n"
                  "  Refusing to overwrite an existing identity. Remove it "
                  "deliberately first if you really mean to restore over it.",
                  file=sys.stderr)
            sys.exit(2)
        words = getpass.getpass("  recovery mnemonic (24 words): ").strip()
        try:
            restored = mnemonic_to_root(words)
        except ValueError as e:
            print(f"  error: {e}", file=sys.stderr)
            sys.exit(2)
        passphrase = _get_passphrase()
        root, identity, book_key = identity_store.create_and_store_identity(
            str(identity_path), passphrase, root=restored)
        print(f"  identity restored from mnemonic into {identity_path}.")
        fresh = True
    elif exists:
        passphrase = _get_passphrase()
        try:
            root, identity, book_key = identity_store.load_identity(
                str(identity_path), passphrase)
        except ValueError:
            print("\n  error: wrong passphrase (could not unwrap the identity).",
                  file=sys.stderr)
            sys.exit(1)
        fresh = False
    else:
        passphrase = _get_passphrase()
        root, identity, book_key = identity_store.create_and_store_identity(
            str(identity_path), passphrase)
        _print_first_run_mnemonic(root_to_mnemonic(root), identity_path)
        fresh = True

    recovery_mnemonic = root_to_mnemonic(root)
    passphrase = ""  # drop the passphrase reference
    del passphrase

    book = _open_book(book_path, book_key, fresh)
    return identity, book, book_key, recovery_mnemonic, identity_path


def _get_passphrase() -> str:
    print("  this passphrase encrypts your identity at rest (it does NOT derive")
    print("  it; the identity is a random key you can back up as 24 words).")
    print("  it is never stored. you can change it later with /passwd.")
    print()
    print("  use a strong passphrase: at least 4 random words or a long")
    print("  unpredictable phrase. example: corvo-vetro-martello-1987-luna")
    print()
    passphrase = getpass.getpass("  passphrase: ")
    if not passphrase:
        print("  passphrase cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return passphrase


async def _run_cli(args) -> None:
    from .cli_ui import MalphasCLI

    print_splash()
    identity, book, book_key, recovery_mnemonic, identity_path = (
        _setup_identity_and_book(args)
    )
    book_path = Path(args.book)
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
    try:
        pins.load()
    except PinStoreCorruptError as e:
        print(f"\n  FATAL: {e}")
        print("  If you legitimately changed your passphrase/salt, remove the")
        print(f"  pin file ({pin_path}) deliberately and restart.\n")
        raise SystemExit(1)

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
            tor_pub, tor_priv = identity.tor_service_key()
            onion = await transport.start_hidden_service(
                tor_pub, tor_priv, args.port
            )
            print(f"  onion    {onion}")
        except Exception as e:
            print(f"  warning: hidden service registration failed: {e}", file=sys.stderr)
            print("  continuing without hidden service (outbound Tor only)", file=sys.stderr)

    loop = asyncio.get_running_loop()
    cli = MalphasCLI(node, book, recovery_mnemonic=recovery_mnemonic,
                     identity_path=identity_path)

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


def _run_gui(args) -> None:
    """Synchronous entry: prompt passphrase + salt on the terminal,
    spin a node + asyncio bridge, then enter the Tk mainloop."""
    from .gui import AsyncBridge, launch_gui

    print_splash()
    identity, book, book_key, recovery_mnemonic, identity_path = (
        _setup_identity_and_book(args)
    )
    book_path = Path(args.book)
    if len(book) > 0:
        print(f"  address book loaded ({len(book)} contact(s))")

    pin_path = str(book_path.parent / "pins")
    pins = PinStore(pin_path, book_key)
    try:
        pins.load()
    except PinStoreCorruptError as e:
        print(f"\n  FATAL: {e}")
        print(f"  Remove the pin file ({pin_path}) deliberately to reset.\n")
        raise SystemExit(1)

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

    if args.tor:
        # Register the v3 hidden service so other peers can reach us
        # via .onion (mirrors the _run_cli flow).
        try:
            tor_pub, tor_priv = identity.tor_service_key()
            onion = bridge.submit_coro(
                transport.start_hidden_service(
                    tor_pub, tor_priv, args.port
                )
            ).result(timeout=30.0)
            print(f"  onion    {onion}")
        except Exception as e:
            print(f"  warning: hidden service registration failed: {e}",
                  file=sys.stderr)
            print("  continuing without hidden service (outbound Tor only)",
                  file=sys.stderr)

    print(f"  peer_id  {identity.peer_id}")
    print(f"  port     {args.port}")
    print("  launching GUI...")

    try:
        launch_gui(node, book, bridge, recovery_mnemonic=recovery_mnemonic)
    finally:
        # mainloop returned — make sure the background loop is down.
        try:
            bridge.submit_coro(node.stop()).result(timeout=3.0)
        except Exception:
            pass
        bridge.stop(timeout=2.0)
        book.wipe_memory()


def _run_gui_qt(args) -> None:
    """Synchronous entry: prompt passphrase + salt on the terminal,
    spin a node + asyncio bridge, then enter the Qt event loop.

    Mirrors `_run_gui` exactly except for the toolkit. The Qt GUI
    is currently in skeleton form; node/bridge are passed through
    so wiring can land iter-by-iter without touching this entry."""
    try:
        from .gui import AsyncBridge
        from .gui_qt import launch_qt_gui
    except ImportError as e:
        print(f"\n  error: PySide6 not installed — {e}", file=sys.stderr)
        print("  install with: pip install -e \".[gui-qt]\"",
              file=sys.stderr)
        sys.exit(1)

    print_splash()
    identity, book, book_key, recovery_mnemonic, identity_path = (
        _setup_identity_and_book(args)
    )
    book_path = Path(args.book)
    if len(book) > 0:
        print(f"  address book loaded ({len(book)} contact(s))")

    pin_path = str(book_path.parent / "pins")
    pins = PinStore(pin_path, book_key)
    try:
        pins.load()
    except PinStoreCorruptError as e:
        print(f"\n  FATAL: {e}")
        print(f"  Remove the pin file ({pin_path}) deliberately to reset.\n")
        raise SystemExit(1)

    transport = DirectTransport()
    if args.tor:
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
    bridge.submit_coro(node.start()).result(timeout=10.0)
    node.set_reconnect_book(book)

    if args.tor:
        # Register the v3 hidden service so other peers can reach us via
        # .onion and our invites carry an onion address (mirrors _run_cli /
        # _run_gui — the Qt path previously skipped this, so a Qt node was
        # only ever reachable outbound, and its invites had no onion).
        try:
            tor_pub, tor_priv = identity.tor_service_key()
            onion = bridge.submit_coro(
                transport.start_hidden_service(
                    tor_pub, tor_priv, args.port
                )
            ).result(timeout=30.0)
            print(f"  onion    {onion}")
        except Exception as e:
            print(f"  warning: hidden service registration failed: {e}",
                  file=sys.stderr)
            print("  continuing without hidden service (outbound Tor only)",
                  file=sys.stderr)

    print(f"  peer_id  {identity.peer_id}")
    print(f"  port     {args.port}")
    print("  launching Qt GUI...")

    try:
        launch_qt_gui(node, book, bridge, recovery_mnemonic=recovery_mnemonic)
    finally:
        try:
            bridge.submit_coro(node.stop()).result(timeout=3.0)
        except Exception:
            pass
        bridge.stop(timeout=2.0)
        book.wipe_memory()


def _setup_debug_logging(debug: bool) -> None:
    """Wire the package logger to STDERR at DEBUG when --debug is set.

    Logging is OFF by default and goes ONLY to stderr (never to disk),
    preserving the no-persistence privacy stance: nothing is written
    anywhere unless the user explicitly opts in for a troubleshooting run.
    """
    if not debug:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"))
    pkg = logging.getLogger("malphas")
    pkg.setLevel(logging.DEBUG)
    pkg.addHandler(handler)
    pkg.propagate = False


def main():
    from . import __version__

    parser = argparse.ArgumentParser(description="Malphas P2P messenger")
    parser.add_argument(
        "--version",
        action="version",
        version=f"malphas {__version__}",
    )
    parser.add_argument("--mode", choices=["cli", "gui", "gui-qt"],
                         default="cli")
    parser.add_argument(
        "--host", default="127.0.0.1",
        help=("P2P listen address in DIRECT mode (default: 127.0.0.1, "
              "loopback-only). Pass 0.0.0.0 to accept connections from other "
              "machines. Ignored under --tor (Tor always binds loopback and "
              "exposes the node only as a v3 onion service)."),
    )
    parser.add_argument("--port", type=int, default=7777)
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
        "--identity", default=DEFAULT_IDENTITY_PATH,
        help=(
            f"Identity file (default: {DEFAULT_IDENTITY_PATH}). Holds your "
            "random identity root, encrypted under your passphrase (mode 0600). "
            "Back it up as 24 words; lose it and the backup = lose the identity."
        ),
    )
    parser.add_argument(
        "--from-mnemonic",
        action="store_true",
        help=(
            "Restore the identity root from a 24-word BIP39 mnemonic. The "
            "words are prompted interactively (never passed on the command "
            "line, which would leak them via the process list). The salt "
            "file is written if absent; if it exists it is verified to "
            "match — startup aborts on mismatch."
        ),
    )
    parser.add_argument(
        "--debug", action="store_true",
        help=("Verbose diagnostic logging to STDERR (never to disk). Surfaces "
              "fail-closed drops — dropped frames, auth failures, queued-not-"
              "sent messages, hidden-service setup. Off by default."),
    )
    args = parser.parse_args()
    _setup_debug_logging(args.debug)

    if args.mode == "gui":
        _run_gui(args)
    elif args.mode == "gui-qt":
        _run_gui_qt(args)
    else:
        asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
