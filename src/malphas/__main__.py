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

from .identity import create_identity_with_book_key
from .node import MalphasNode
from .addressbook import AddressBook
from .transport import DirectTransport, TorTransport, tor_is_available
from .splash import print_splash

DEFAULT_BOOK_PATH = str(Path.home() / ".malphas" / "book")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "pwa")


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
    identity, book_key = create_identity_with_book_key(passphrase)
    passphrase = ""
    del passphrase

    # Ensure book directory exists
    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)

    book = AddressBook(str(book_path), book_key)
    try:
        loaded = book.load()
        if loaded:
            print(f"  address book loaded ({len(book)} contact(s))")
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        print("  wrong passphrase or corrupted address book.", file=sys.stderr)
        sys.exit(1)

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

    node = MalphasNode(
        identity=identity,
        host=args.host,
        port=args.port,
        message_ttl=args.ttl,
        transport=transport,
    )
    await node.start()

    if args.tor:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            priv_bytes = identity.ed25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            onion = await transport.start_hidden_service(
                identity.ed25519_pub_bytes, priv_bytes, args.port
            )
            print(f"  onion    {onion}")
        except Exception as e:
            print(f"  warning: hidden service registration failed: {e}", file=sys.stderr)
            print("  continuing without hidden service (outbound Tor only)", file=sys.stderr)

    loop = asyncio.get_running_loop()
    cli = MalphasCLI(node, book)

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
    identity, book_key = create_identity_with_book_key(passphrase)
    passphrase = ""
    del passphrase

    book_path = Path(args.book)
    book_path.parent.mkdir(parents=True, exist_ok=True)
    book = AddressBook(str(book_path), book_key)
    try:
        book.load()
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        sys.exit(1)

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


def main():
    parser = argparse.ArgumentParser(description="Malphas P2P messenger")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli")
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
    args = parser.parse_args()

    if args.mode == "web":
        asyncio.run(_run_web(args))
    else:
        asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
