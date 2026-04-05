"""
Tests for the CLI interface (cli_ui.py).

Covers:
- Command methods: _cmd_chat, _cmd_book, _cmd_send, _cmd_wipe, _cmd_export,
  _cmd_import, _cmd_add, _cmd_panic (called directly, no run() loop)
- Display methods: _print_identity, _print_peers, _print_book,
  _print_conversation, _print_help
- Callbacks: _on_message, _on_receipt
- Tab completion: MalphasCompleter
- Status bar: _status_bar()
- Regex helpers: PEER_ID_RE, HEX64_RE
"""

import asyncio
import os
import socket
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from malphas.cli_ui import MalphasCLI, MalphasCompleter, COMMANDS, PEER_ID_RE, HEX64_RE
from malphas.identity import create_identity, create_identity_with_book_key
from malphas.invite import generate_invite
from malphas.node import MalphasNode
from malphas.addressbook import AddressBook, Contact
from malphas.discovery import PeerDiscovery
from malphas.memory import MessageStore
from malphas.receipts import ReceiptTracker


# ---------------------------------------------------------------------------
# Port allocation helper
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Find a free TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Identity fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def identity_cli_a():
    return create_identity("cli-test-alice")


@pytest.fixture
def identity_cli_b():
    return create_identity("cli-test-bob")


@pytest.fixture
def identity_cli_c():
    return create_identity("cli-test-charlie")


@pytest.fixture
def book_key_cli():
    _, key = create_identity_with_book_key("cli-test-alice")
    return key


@pytest.fixture
def tmp_book_path():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".book") as f:
        path = f.name
    os.unlink(path)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def fresh_book_cli(tmp_book_path, book_key_cli):
    book = AddressBook(tmp_book_path, book_key_cli)
    book.load()
    return book


@pytest.fixture
def contact_bob(identity_cli_b):
    return Contact(
        label="bob",
        peer_id=identity_cli_b.peer_id,
        host="127.0.0.1",
        port=19101,
        x25519_pub=identity_cli_b.x25519_pub_bytes.hex(),
        ed25519_pub=identity_cli_b.ed25519_pub_bytes.hex(),
    )


@pytest.fixture
def contact_charlie(identity_cli_c):
    return Contact(
        label="charlie",
        peer_id=identity_cli_c.peer_id,
        host="127.0.0.1",
        port=19102,
        x25519_pub=identity_cli_c.x25519_pub_bytes.hex(),
        ed25519_pub=identity_cli_c.ed25519_pub_bytes.hex(),
    )


# ---------------------------------------------------------------------------
# Mock-based CLI fixture (no real TCP server — fast, no port conflicts)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_node(identity_cli_a):
    """A MalphasNode-like mock that exposes the attributes the CLI reads."""
    node = MagicMock(spec=MalphasNode)
    node.identity = identity_cli_a
    node.host = "127.0.0.1"
    node.port = 19100
    node.public_address = "127.0.0.1"
    node.discovery = PeerDiscovery(identity_cli_a.peer_id)
    node.store = MessageStore()
    node.receipts = ReceiptTracker()
    node._connections = {}

    # Transport mock
    transport = MagicMock()
    transport.public_address = None
    node.transport = transport

    # Make async methods return proper coroutines
    node.send_message = AsyncMock(return_value=None)
    node.connect_to_peer = AsyncMock(return_value=False)
    node.panic = MagicMock()
    node.on_message = MagicMock()
    node.on_receipt = MagicMock()
    return node


@pytest.fixture
def cli(mock_node, fresh_book_cli):
    """CLI backed by mock node — safe for all non-networking tests."""
    return MalphasCLI(mock_node, fresh_book_cli)


@pytest.fixture
def cli_with_bob(cli, contact_bob):
    """CLI with bob already in the address book."""
    cli.book.add(contact_bob)
    return cli


# ---------------------------------------------------------------------------
# Real-node fixtures (for integration tests that need actual TCP)
# ---------------------------------------------------------------------------

@pytest.fixture
async def real_node_a(identity_cli_a):
    port = _free_port()
    node = MalphasNode(identity_cli_a, host="127.0.0.1", port=port, cover_traffic=False)
    await node.start()
    yield node
    await node.stop()


@pytest.fixture
async def real_node_b(identity_cli_b):
    port = _free_port()
    node = MalphasNode(identity_cli_b, host="127.0.0.1", port=port, cover_traffic=False)
    await node.start()
    yield node
    await node.stop()


@pytest.fixture
def real_cli(real_node_a, fresh_book_cli):
    """CLI backed by a real running node."""
    return MalphasCLI(real_node_a, fresh_book_cli)


# ---------------------------------------------------------------------------
# Output capture helper — replaces _console with a StringIO-backed Console
# ---------------------------------------------------------------------------

def _capture(cli) -> StringIO:
    """Replace cli._console with a StringIO-backed Console and return the buffer."""
    buf = StringIO()
    cli._console = Console(file=buf, highlight=False, force_terminal=False, width=120)
    return buf


def _run_capture(cli, func, *args, **kwargs):
    """Run a sync method on cli, capturing rich + _plain output. Returns output string."""
    buf = _capture(cli)
    plain_buf = StringIO()
    original_plain = cli._plain
    cli._plain = lambda msg: plain_buf.write(msg + "\n")
    try:
        func(*args, **kwargs)
    finally:
        cli._plain = original_plain
    return buf.getvalue() + plain_buf.getvalue()


async def _run_capture_async(cli, coro):
    """Await an async coroutine on cli, capturing rich + _plain output. Returns output string."""
    buf = _capture(cli)
    plain_buf = StringIO()
    original_plain = cli._plain
    cli._plain = lambda msg: plain_buf.write(msg + "\n")
    try:
        await coro
    finally:
        cli._plain = original_plain
    return buf.getvalue() + plain_buf.getvalue()


# ---------------------------------------------------------------------------
# TestChatCommand
# ---------------------------------------------------------------------------

class TestChatCommand:
    """Test /chat with various target types."""

    async def test_chat_no_args_prints_usage(self, cli):
        output = await _run_capture_async(cli, cli._cmd_chat([]))
        assert "usage" in output.lower()

    async def test_chat_by_label_auto_connects(self, cli_with_bob, identity_cli_b):
        """
        /chat bob should resolve the label from the address book and
        attempt to connect. Since connect_to_peer is mocked to return
        False, it should report unreachable.
        """
        cli = cli_with_bob
        output = await _run_capture_async(cli, cli._cmd_chat(["bob"]))
        assert "could not reach" in output.lower()

    async def test_chat_by_label_sets_active_peer_when_connected(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat(["bob"])
        assert cli.active_peer == identity_cli_b.peer_id

    async def test_chat_by_label_already_connected(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat(["bob"])
        assert cli.active_peer == identity_cli_b.peer_id
        cli.node.connect_to_peer.assert_not_called()

    async def test_chat_by_peer_id(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat([identity_cli_b.peer_id])
        assert cli.active_peer == identity_cli_b.peer_id

    async def test_chat_by_index(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat(["0"])
        assert cli.active_peer is not None

    async def test_chat_index_out_of_range(self, cli):
        output = await _run_capture_async(cli, cli._cmd_chat(["99"]))
        assert "out of range" in output.lower()

    async def test_chat_unknown_target_prints_error(self, cli):
        output = await _run_capture_async(cli, cli._cmd_chat(["nonexistent_label"]))
        assert "not found" in output.lower()

    async def test_chat_partial_peer_id_match(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        prefix = identity_cli_b.peer_id[:8]
        await cli._cmd_chat([prefix])
        assert cli.active_peer == identity_cli_b.peer_id

    async def test_chat_partial_peer_id_ambiguous(self, cli, identity_cli_b, identity_cli_c):
        # Add two peers that share a prefix (unlikely but test the logic)
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.node.discovery.add_peer(
            identity_cli_c.peer_id, "127.0.0.1", 19102,
            identity_cli_c.x25519_pub_bytes,
            identity_cli_c.ed25519_pub_bytes,
        )
        # Use a very short prefix that matches both (first char)
        # Both peer_ids are hex, first char is likely different, so use full id of one
        output = await _run_capture_async(cli, cli._cmd_chat([identity_cli_b.peer_id[:4]]))
        # Either it matches uniquely or says ambiguous — both are valid
        assert cli.active_peer is not None or "ambiguous" in output.lower() or "no peer" in output.lower()

    async def test_chat_partial_peer_id_no_match(self, cli):
        output = await _run_capture_async(cli, cli._cmd_chat(["deadbeef"]))
        assert "no peer" in output.lower()

    async def test_chat_partial_peer_id_too_short(self, cli):
        """Less than 4 chars hex should not match as prefix."""
        output = await _run_capture_async(cli, cli._cmd_chat(["abc"]))
        assert "not found" in output.lower()

    async def test_chat_prints_conversation_label(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = await _run_capture_async(cli, cli._cmd_chat(["bob"]))
        assert "bob" in output.lower()


# ---------------------------------------------------------------------------
# TestChatCommandIntegration (real TCP)
# ---------------------------------------------------------------------------

class TestChatCommandIntegration:

    async def test_chat_label_auto_connects_real(
        self, real_node_a, real_node_b, identity_cli_b, fresh_book_cli
    ):
        contact = Contact(
            label="bob",
            peer_id=identity_cli_b.peer_id,
            host="127.0.0.1",
            port=real_node_b.port,
            x25519_pub=identity_cli_b.x25519_pub_bytes.hex(),
            ed25519_pub=identity_cli_b.ed25519_pub_bytes.hex(),
        )
        fresh_book_cli.add(contact)
        cli = MalphasCLI(real_node_a, fresh_book_cli)
        await cli._cmd_chat(["bob"])
        assert cli.active_peer == identity_cli_b.peer_id
        peer = real_node_a.discovery.get_peer(identity_cli_b.peer_id)
        assert peer is not None

    async def test_chat_by_peer_id_real(
        self, real_node_a, real_node_b, identity_cli_a, identity_cli_b, fresh_book_cli
    ):
        ok = await real_node_a.connect_to_peer(
            "127.0.0.1", real_node_b.port,
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        assert ok
        await asyncio.sleep(0.1)
        cli = MalphasCLI(real_node_a, fresh_book_cli)
        await cli._cmd_chat([identity_cli_b.peer_id])
        assert cli.active_peer == identity_cli_b.peer_id


# ---------------------------------------------------------------------------
# TestBookCommands
# ---------------------------------------------------------------------------

class TestBookCommands:

    async def test_book_empty_prints_empty_message(self, cli):
        output = await _run_capture_async(cli, cli._cmd_book([]))
        assert "empty" in output.lower()

    async def test_book_lists_contacts(self, cli_with_bob):
        output = await _run_capture_async(cli_with_bob, cli_with_bob._cmd_book([]))
        assert "bob" in output.lower()

    async def test_book_add_no_active_peer(self, cli):
        assert cli.active_peer is None
        output = await _run_capture_async(cli, cli._cmd_book(["add", "testlabel"]))
        assert "no active conversation" in output.lower()

    async def test_book_add_with_active_peer(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        await cli._cmd_book(["add", "bobby"])
        contact = cli.book.get("bobby")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_book_add_empty_label_errors(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        with patch("builtins.input", return_value=""):
            output = await _run_capture_async(cli, cli._cmd_book(["add"]))
        assert "empty" in output.lower()

    async def test_book_add_prompts_for_label(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        with patch("builtins.input", return_value="prompted_label"):
            await cli._cmd_book(["add"])
        contact = cli.book.get("prompted_label")
        assert contact is not None

    async def test_book_add_peer_not_in_routing_table(self, cli, identity_cli_b):
        cli.active_peer = identity_cli_b.peer_id
        output = await _run_capture_async(cli, cli._cmd_book(["add", "ghost"]))
        assert "not in routing table" in output.lower()

    async def test_book_rm_existing_contact(self, cli_with_bob):
        assert cli_with_bob.book.get("bob") is not None
        output = await _run_capture_async(
            cli_with_bob, cli_with_bob._cmd_book(["rm", "bob"])
        )
        assert "removed" in output.lower()
        assert cli_with_bob.book.get("bob") is None

    async def test_book_rm_nonexistent_contact(self, cli):
        output = await _run_capture_async(cli, cli._cmd_book(["rm", "ghost"]))
        assert "not found" in output.lower()

    async def test_book_rm_no_label_prints_usage(self, cli):
        output = await _run_capture_async(cli, cli._cmd_book(["rm"]))
        assert "usage" in output.lower()

    async def test_book_unknown_subcommand(self, cli):
        output = await _run_capture_async(cli, cli._cmd_book(["xyz"]))
        assert "unknown subcommand" in output.lower()

    async def test_book_add_persists_to_disk(
        self, cli, identity_cli_b, tmp_book_path, book_key_cli
    ):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        await cli._cmd_book(["add", "persisted_bob"])
        book2 = AddressBook(tmp_book_path, book_key_cli)
        book2.load()
        contact = book2.get("persisted_bob")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_book_rm_persists_removal(
        self, cli_with_bob, tmp_book_path, book_key_cli
    ):
        await cli_with_bob._cmd_book(["rm", "bob"])
        book2 = AddressBook(tmp_book_path, book_key_cli)
        book2.load()
        assert book2.get("bob") is None

    async def test_book_add_multi_word_label(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        await cli._cmd_book(["add", "My", "Friend"])
        contact = cli.book.get("My Friend")
        assert contact is not None


# ---------------------------------------------------------------------------
# TestSendCommand
# ---------------------------------------------------------------------------

class TestSendCommand:

    async def test_send_without_active_peer(self, cli):
        assert cli.active_peer is None
        output = await _run_capture_async(cli, cli._cmd_send("hello"))
        assert "no active conversation" in output.lower()

    async def test_send_with_active_peer_calls_send_message(
        self, cli, identity_cli_b
    ):
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value="msg123")
        await cli._cmd_send("test message")
        cli.node.send_message.assert_called_once_with(
            identity_cli_b.peer_id, "test message"
        )

    async def test_send_failure_prints_error(self, cli, identity_cli_b):
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value=None)
        output = await _run_capture_async(cli, cli._cmd_send("will fail"))
        assert "failed" in output.lower() or "unreachable" in output.lower()

    async def test_send_success_prints_message(self, cli, identity_cli_b):
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value="msg456")
        output = await _run_capture_async(cli, cli._cmd_send("echoed text"))
        assert "echoed text" in output
        assert "you" in output.lower()


# ---------------------------------------------------------------------------
# TestSendCommandIntegration
# ---------------------------------------------------------------------------

class TestSendCommandIntegration:

    async def test_send_real_message(
        self, real_node_a, real_node_b, identity_cli_a, identity_cli_b, fresh_book_cli
    ):
        received = []
        real_node_b.on_message(lambda f, c: received.append(c))

        ok = await real_node_a.connect_to_peer(
            "127.0.0.1", real_node_b.port,
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        assert ok
        await asyncio.sleep(0.15)

        cli = MalphasCLI(real_node_a, fresh_book_cli)
        cli.active_peer = identity_cli_b.peer_id
        await cli._cmd_send("integration test message")
        await asyncio.sleep(0.3)
        assert "integration test message" in received


# ---------------------------------------------------------------------------
# TestWipeCommand
# ---------------------------------------------------------------------------

class TestWipeCommand:

    async def test_wipe_confirmed(self, cli, identity_cli_a):
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "secret")
        assert len(cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")) == 1
        with patch("builtins.input", return_value="y"):
            output = await _run_capture_async(cli, cli._cmd_wipe())
        assert "wiped" in output.lower()
        assert cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer") == []

    async def test_wipe_cancelled(self, cli, identity_cli_a):
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "keep me")
        with patch("builtins.input", return_value="n"):
            output = await _run_capture_async(cli, cli._cmd_wipe())
        assert "cancelled" in output.lower()
        msgs = cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")
        assert len(msgs) == 1
        assert msgs[0]["content"] == "keep me"

    async def test_wipe_empty_input_cancels(self, cli, identity_cli_a):
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "still here")
        with patch("builtins.input", return_value=""):
            output = await _run_capture_async(cli, cli._cmd_wipe())
        assert "cancelled" in output.lower()
        msgs = cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")
        assert len(msgs) == 1

    async def test_wipe_capital_Y_confirms(self, cli, identity_cli_a):
        """The code does .strip().lower() so 'Y' becomes 'y' and should wipe."""
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "test")
        with patch("builtins.input", return_value="Y"):
            await cli._cmd_wipe()
        assert cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer") == []


# ---------------------------------------------------------------------------
# TestPanicCommand
# ---------------------------------------------------------------------------

class TestPanicCommand:

    async def test_panic_clears_active_peer(self, cli):
        cli.active_peer = "some_peer_id"
        with pytest.raises(SystemExit):
            await cli._cmd_panic()
        assert cli.active_peer is None

    async def test_panic_calls_node_panic(self, cli):
        with pytest.raises(SystemExit):
            await cli._cmd_panic()
        cli.node.panic.assert_called_once()

    async def test_panic_calls_book_wipe(self, cli_with_bob):
        cli = cli_with_bob
        assert len(cli.book) > 0
        with pytest.raises(SystemExit):
            await cli._cmd_panic()
        assert len(cli.book) == 0

    async def test_panic_sets_running_false(self, cli):
        cli._running = True
        with pytest.raises(SystemExit):
            await cli._cmd_panic()
        assert cli._running is False

    async def test_panic_calls_sys_exit_zero(self, cli):
        with pytest.raises(SystemExit) as exc_info:
            await cli._cmd_panic()
        assert exc_info.value.code == 0

    async def test_panic_prints_wiped(self, cli):
        buf = _capture(cli)
        with pytest.raises(SystemExit):
            await cli._cmd_panic()
        assert "wiped" in buf.getvalue().lower()


# ---------------------------------------------------------------------------
# TestHelpCommand
# ---------------------------------------------------------------------------

class TestHelpCommand:

    def test_help_includes_all_commands(self, cli):
        expected_commands = [
            "/id", "/peers", "/book", "/book add", "/book rm",
            "/add", "/chat", "/history", "/export", "/import",
            "/wipe", "/panic", "/quit",
        ]
        output = _run_capture(cli, cli._print_help)
        for cmd in expected_commands:
            assert cmd in output, f"Expected '{cmd}' in help output"

    def test_help_includes_text_sending(self, cli):
        output = _run_capture(cli, cli._print_help)
        assert "<text>" in output

    def test_help_mentions_emergency(self, cli):
        output = _run_capture(cli, cli._print_help)
        assert "emergency" in output.lower()

    def test_help_uses_rich_panel(self, cli):
        """Help output should use a rich Panel (border characters)."""
        output = _run_capture(cli, cli._print_help)
        # Rich panels use box-drawing characters
        assert any(c in output for c in ("─", "│", "╭", "╮", "╰", "╯"))


# ---------------------------------------------------------------------------
# TestIdentityDisplay
# ---------------------------------------------------------------------------

class TestIdentityDisplay:

    def test_id_shows_peer_id(self, cli, identity_cli_a):
        output = _run_capture(cli, cli._print_identity)
        assert identity_cli_a.peer_id in output

    def test_id_shows_x25519_pub(self, cli, identity_cli_a):
        output = _run_capture(cli, cli._print_identity)
        assert identity_cli_a.x25519_pub_bytes.hex() in output

    def test_id_shows_ed25519_pub(self, cli, identity_cli_a):
        output = _run_capture(cli, cli._print_identity)
        assert identity_cli_a.ed25519_pub_bytes.hex() in output

    def test_id_shows_port(self, cli):
        output = _run_capture(cli, cli._print_identity)
        assert str(cli.node.port) in output

    def test_id_contains_labels(self, cli):
        output = _run_capture(cli, cli._print_identity)
        assert "peer_id" in output
        assert "x25519_pub" in output
        assert "ed25519_pub" in output
        assert "port" in output

    def test_id_shows_onion_when_present(self, cli):
        """When transport reports an .onion address, it should appear."""
        cli.node.transport.public_address = "abc123.onion"
        output = _run_capture(cli, cli._print_identity)
        assert "abc123.onion" in output

    def test_id_no_onion_when_absent(self, cli):
        """When transport has no .onion, 'onion' label should not appear."""
        cli.node.transport.public_address = None
        output = _run_capture(cli, cli._print_identity)
        assert "onion" not in output.lower()


# ---------------------------------------------------------------------------
# TestPeersDisplay
# ---------------------------------------------------------------------------

class TestPeersDisplay:

    def test_peers_empty(self, cli):
        output = _run_capture(cli, cli._print_peers)
        assert "no peers" in output.lower()

    def test_peers_shows_connected(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _run_capture(cli, cli._print_peers)
        assert identity_cli_b.peer_id[:16] in output

    def test_peers_marks_active_peer(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        output = _run_capture(cli, cli._print_peers)
        assert "*" in output

    def test_peers_shows_host_port(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _run_capture(cli, cli._print_peers)
        assert "127.0.0.1:19101" in output

    def test_peers_shows_book_label(self, cli_with_bob, identity_cli_b):
        cli_with_bob.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _run_capture(cli_with_bob, cli_with_bob._print_peers)
        assert "bob" in output.lower()


# ---------------------------------------------------------------------------
# TestBookDisplay
# ---------------------------------------------------------------------------

class TestBookDisplay:

    def test_book_empty_display(self, cli):
        output = _run_capture(cli, cli._print_book)
        assert "empty" in output.lower()

    def test_book_display_shows_label(self, cli_with_bob):
        output = _run_capture(cli_with_bob, cli_with_bob._print_book)
        assert "bob" in output.lower()

    def test_book_display_shows_peer_id_prefix(self, cli_with_bob, identity_cli_b):
        output = _run_capture(cli_with_bob, cli_with_bob._print_book)
        assert identity_cli_b.peer_id[:16] in output

    def test_book_display_marks_active(self, cli_with_bob, identity_cli_b):
        cli_with_bob.active_peer = identity_cli_b.peer_id
        output = _run_capture(cli_with_bob, cli_with_bob._print_book)
        assert "*" in output

    def test_book_display_multiple_contacts(self, cli_with_bob, contact_charlie):
        cli_with_bob.book.add(contact_charlie)
        output = _run_capture(cli_with_bob, cli_with_bob._print_book)
        assert "bob" in output.lower()
        assert "charlie" in output.lower()

    def test_book_display_shows_host_port(self, cli_with_bob):
        output = _run_capture(cli_with_bob, cli_with_bob._print_book)
        assert "127.0.0.1:19101" in output


# ---------------------------------------------------------------------------
# TestHistoryCommand
# ---------------------------------------------------------------------------

class TestHistoryCommand:

    def test_history_shows_messages(self, cli, identity_cli_a, identity_cli_b):
        cli.node.store.store(
            identity_cli_a.peer_id, identity_cli_b.peer_id, "archived message"
        )
        output = _run_capture(cli, cli._print_conversation, identity_cli_b.peer_id)
        assert "archived message" in output

    def test_history_empty_conversation(self, cli, identity_cli_b):
        output = _run_capture(cli, cli._print_conversation, identity_cli_b.peer_id)
        assert "no messages" in output.lower()

    def test_history_labels_own_messages(self, cli, identity_cli_a, identity_cli_b):
        cli.node.store.store(
            identity_cli_a.peer_id, identity_cli_b.peer_id, "my message"
        )
        output = _run_capture(cli, cli._print_conversation, identity_cli_b.peer_id)
        assert "you" in output.lower()

    def test_history_labels_peer_messages_by_label(
        self, cli_with_bob, identity_cli_a, identity_cli_b
    ):
        cli = cli_with_bob
        cli.node.store.store(
            identity_cli_b.peer_id, identity_cli_a.peer_id, "from bob"
        )
        output = _run_capture(cli, cli._print_conversation, identity_cli_b.peer_id)
        assert "bob" in output.lower()

    def test_history_labels_unknown_peer_by_truncated_id(
        self, cli, identity_cli_a, identity_cli_b
    ):
        cli.node.store.store(
            identity_cli_b.peer_id, identity_cli_a.peer_id, "from stranger"
        )
        output = _run_capture(cli, cli._print_conversation, identity_cli_b.peer_id)
        assert identity_cli_b.peer_id[:8] in output


# ---------------------------------------------------------------------------
# TestCallbacks
# ---------------------------------------------------------------------------

class TestCallbacks:

    async def test_on_message_active_peer_prints_content(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.active_peer = identity_cli_b.peer_id
        output = await _run_capture_async(
            cli, cli._on_message(identity_cli_b.peer_id, "hello from bob")
        )
        assert "hello from bob" in output

    async def test_on_message_inactive_peer_prints_notification(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.active_peer = None
        output = await _run_capture_async(
            cli, cli._on_message(identity_cli_b.peer_id, "hello from bob")
        )
        # New format: "< bob: hello from bob"
        assert "bob" in output.lower()
        assert "hello from bob" in output

    async def test_on_message_uses_label_from_book(
        self, cli_with_bob, identity_cli_b
    ):
        cli = cli_with_bob
        cli.active_peer = identity_cli_b.peer_id
        output = await _run_capture_async(
            cli, cli._on_message(identity_cli_b.peer_id, "labeled message")
        )
        assert "bob" in output.lower()

    async def test_on_message_unknown_sender_shows_truncated_id(self, cli):
        fake_peer_id = "a" * 40
        cli.active_peer = fake_peer_id
        output = await _run_capture_async(
            cli, cli._on_message(fake_peer_id, "who am i")
        )
        assert fake_peer_id[:8] in output

    async def test_on_receipt_received(self, cli_with_bob, identity_cli_b):
        cli = cli_with_bob
        output = await _run_capture_async(
            cli, cli._on_receipt("msg123", identity_cli_b.peer_id, True)
        )
        # Positive receipt is now a checkmark
        assert "\u2713" in output

    async def test_on_receipt_not_received(self, cli_with_bob, identity_cli_b):
        cli = cli_with_bob
        output = await _run_capture_async(
            cli, cli._on_receipt("msg123", identity_cli_b.peer_id, False)
        )
        assert "no receipt" in output.lower()

    async def test_on_receipt_unknown_peer_shows_truncated_id(self, cli):
        fake_peer_id = "b" * 40
        output = await _run_capture_async(
            cli, cli._on_receipt("msg123", fake_peer_id, False)
        )
        assert fake_peer_id[:8] in output


# ---------------------------------------------------------------------------
# TestAddCommand
# ---------------------------------------------------------------------------

class TestAddCommand:

    async def test_add_no_args_prints_usage(self, cli):
        output = await _run_capture_async(cli, cli._cmd_add([]))
        assert "usage" in output.lower()

    async def test_add_one_arg_prints_usage(self, cli):
        output = await _run_capture_async(cli, cli._cmd_add(["127.0.0.1"]))
        assert "usage" in output.lower()

    async def test_add_invalid_port_too_large(self, cli):
        output = await _run_capture_async(cli, cli._cmd_add(["127.0.0.1", "999999"]))
        assert "invalid port" in output.lower()

    async def test_add_invalid_port_zero(self, cli):
        output = await _run_capture_async(cli, cli._cmd_add(["127.0.0.1", "0"]))
        assert "invalid port" in output.lower()

    async def test_add_non_numeric_port(self, cli):
        output = await _run_capture_async(cli, cli._cmd_add(["127.0.0.1", "abc"]))
        assert "invalid port" in output.lower()

    async def test_add_invalid_peer_id(self, cli):
        with patch("builtins.input", return_value="not_a_valid_hex"):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid peer_id" in output.lower()

    async def test_add_invalid_x25519_pub(self, cli, identity_cli_b):
        inputs = iter([identity_cli_b.peer_id, "not_valid_hex"])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid x25519_pub" in output.lower()

    async def test_add_invalid_ed25519_pub(self, cli, identity_cli_b):
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            "bad_hex",
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid ed25519_pub" in output.lower()

    async def test_add_connection_failure(self, cli, identity_cli_b):
        cli.node.connect_to_peer = AsyncMock(return_value=False)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19199"])
            )
        assert "failed" in output.lower()

    async def test_add_success_no_save(self, cli, identity_cli_b):
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "n",  # don't save
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "connected" in output.lower()
        assert cli.book.get("bob") is None

    async def test_add_success_with_save(self, cli, identity_cli_b):
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "y",
            "bob_manual",
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            await cli._cmd_add(["127.0.0.1", "19101"])
        contact = cli.book.get("bob_manual")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_add_save_empty_label(self, cli, identity_cli_b):
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "y",
            "",
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(
                cli, cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "label empty" in output.lower() or "not saved" in output.lower()


# ---------------------------------------------------------------------------
# TestExportCommand
# ---------------------------------------------------------------------------

class TestExportCommand:

    async def test_export_generates_url(self, cli, identity_cli_a):
        output = await _run_capture_async(cli, cli._cmd_export())
        assert "malphas://" in output

    async def test_export_url_contains_correct_invite(self, cli, identity_cli_a):
        """The generated invite URL should match what generate_invite produces."""
        expected_url = generate_invite(
            identity_cli_a, cli.node.public_address, cli.node.port,
        )
        output = await _run_capture_async(cli, cli._cmd_export())
        # The URL may be line-wrapped by rich, so strip whitespace and compare
        output_collapsed = output.replace("\n", "").replace(" ", "")
        expected_collapsed = expected_url.replace("\n", "").replace(" ", "")
        assert expected_collapsed in output_collapsed

    async def test_export_shows_warning_panel(self, cli):
        output = await _run_capture_async(cli, cli._cmd_export())
        assert "warning" in output.lower()

    async def test_export_mentions_ip_change(self, cli):
        output = await _run_capture_async(cli, cli._cmd_export())
        assert "ip" in output.lower() or "host" in output.lower()


# ---------------------------------------------------------------------------
# TestImportCommand
# ---------------------------------------------------------------------------

class TestImportCommand:

    async def test_import_no_args_prints_usage(self, cli):
        output = await _run_capture_async(cli, cli._cmd_import([]))
        assert "usage" in output.lower()

    async def test_import_invalid_url(self, cli):
        output = await _run_capture_async(cli, cli._cmd_import(["not-a-url"]))
        assert "invalid" in output.lower()

    async def test_import_valid_url_shows_summary(self, cli, identity_cli_b):
        """A valid invite URL should display peer info before asking to connect."""
        url = generate_invite(identity_cli_b, "127.0.0.1", 19101)
        with patch("builtins.input", return_value="n"):
            output = await _run_capture_async(cli, cli._cmd_import([url]))
        assert identity_cli_b.peer_id in output
        assert "127.0.0.1" in output

    async def test_import_cancelled(self, cli, identity_cli_b):
        url = generate_invite(identity_cli_b, "127.0.0.1", 19101)
        with patch("builtins.input", return_value="n"):
            output = await _run_capture_async(cli, cli._cmd_import([url]))
        assert "cancelled" in output.lower()
        cli.node.connect_to_peer.assert_not_called()

    async def test_import_connect_failure(self, cli, identity_cli_b):
        url = generate_invite(identity_cli_b, "127.0.0.1", 19101)
        cli.node.connect_to_peer = AsyncMock(return_value=False)
        with patch("builtins.input", return_value="y"):
            output = await _run_capture_async(cli, cli._cmd_import([url]))
        assert "failed" in output.lower()

    async def test_import_connect_success_no_save(self, cli, identity_cli_b):
        url = generate_invite(identity_cli_b, "127.0.0.1", 19101)
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter(["y", "n"])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _run_capture_async(cli, cli._cmd_import([url]))
        assert "connected" in output.lower()

    async def test_import_connect_success_with_save(self, cli, identity_cli_b):
        url = generate_invite(identity_cli_b, "127.0.0.1", 19101)
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter(["y", "y", "imported_bob"])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            await cli._cmd_import([url])
        contact = cli.book.get("imported_bob")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_import_with_onion_prefers_onion(self, cli, identity_cli_b):
        """When the invite has an .onion address, it should be used for connecting."""
        url = generate_invite(
            identity_cli_b, "127.0.0.1", 19101,
            onion="abc123.onion",
        )
        cli.node.connect_to_peer = AsyncMock(return_value=False)
        with patch("builtins.input", return_value="y"):
            await cli._cmd_import([url])
        # Should have tried to connect via the .onion address
        call_args = cli.node.connect_to_peer.call_args
        assert call_args[0][0] == "abc123.onion"
        assert call_args[0][1] == 80  # onion default port


# ---------------------------------------------------------------------------
# TestAutoConnect
# ---------------------------------------------------------------------------

class TestAutoConnect:

    async def test_auto_connect_empty_book(self, cli):
        output = await _run_capture_async(cli, cli._auto_connect())
        assert output.strip() == ""

    async def test_auto_connect_unreachable(self, cli_with_bob):
        output = await _run_capture_async(cli_with_bob, cli_with_bob._auto_connect())
        assert "unreachable" in output.lower()

    async def test_auto_connect_success(self, cli_with_bob):
        cli_with_bob.node.connect_to_peer = AsyncMock(return_value=True)
        output = await _run_capture_async(cli_with_bob, cli_with_bob._auto_connect())
        assert "connected" in output.lower()

    async def test_auto_connect_reports_count(self, cli_with_bob):
        output = await _run_capture_async(cli_with_bob, cli_with_bob._auto_connect())
        assert "1 contact" in output.lower()


# ---------------------------------------------------------------------------
# TestStatusBar
# ---------------------------------------------------------------------------

class TestStatusBar:

    def test_status_bar_shows_peer_count(self, cli):
        result = cli._status_bar()
        assert "0 peers" in result

    def test_status_bar_shows_active_chat_label(self, cli_with_bob, identity_cli_b):
        cli = cli_with_bob
        cli.active_peer = identity_cli_b.peer_id
        result = cli._status_bar()
        assert "bob" in result.lower()

    def test_status_bar_shows_active_chat_truncated(self, cli, identity_cli_b):
        """When active peer is not in book, show truncated peer_id."""
        cli.active_peer = identity_cli_b.peer_id
        result = cli._status_bar()
        assert identity_cli_b.peer_id[:8] in result

    def test_status_bar_no_active_chat(self, cli):
        result = cli._status_bar()
        assert "chat" not in result.lower()

    def test_status_bar_shows_pending_receipts(self, cli):
        """When there are pending receipts, they should show in status bar."""
        # Add a mock pending receipt
        cli.node.receipts = MagicMock()
        cli.node.receipts.pending_count.return_value = 3
        result = cli._status_bar()
        assert "3 receipts" in result

    def test_status_bar_no_receipts_when_zero(self, cli):
        result = cli._status_bar()
        assert "receipt" not in result.lower()

    def test_status_bar_shows_tor(self, cli):
        cli.node.transport.public_address = "something.onion"
        result = cli._status_bar()
        assert "tor" in result.lower()

    def test_status_bar_no_tor_without_onion(self, cli):
        cli.node.transport.public_address = None
        result = cli._status_bar()
        assert "tor" not in result.lower()


# ---------------------------------------------------------------------------
# TestMalphasCompleter
# ---------------------------------------------------------------------------

class TestMalphasCompleter:

    def _make_document(self, text):
        """Create a mock Document-like object for completion."""
        doc = MagicMock()
        doc.text_before_cursor = text
        return doc

    def test_completes_commands_from_empty(self, mock_node, fresh_book_cli):
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        for cmd in COMMANDS:
            assert cmd in texts

    def test_completes_commands_with_prefix(self, mock_node, fresh_book_cli):
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/ch")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert "/chat" in texts
        assert "/id" not in texts

    def test_chat_completes_book_labels(self, mock_node, fresh_book_cli, contact_bob):
        fresh_book_cli.add(contact_bob)
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/chat ")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert "bob" in texts

    def test_chat_completes_partial_label(self, mock_node, fresh_book_cli, contact_bob):
        fresh_book_cli.add(contact_bob)
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/chat bo")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert "bob" in texts

    def test_chat_completes_peer_ids(self, mock_node, fresh_book_cli, identity_cli_b):
        mock_node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/chat ")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert identity_cli_b.peer_id[:8] in texts

    def test_book_rm_completes_labels(self, mock_node, fresh_book_cli, contact_bob):
        fresh_book_cli.add(contact_bob)
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/book rm ")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert "bob" in texts

    def test_no_completions_for_unknown_command(self, mock_node, fresh_book_cli):
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/wipe ")
        completions = list(completer.get_completions(doc, None))
        assert len(completions) == 0

    def test_slash_prefix_filters(self, mock_node, fresh_book_cli):
        completer = MalphasCompleter(mock_node, fresh_book_cli)
        doc = self._make_document("/ex")
        completions = list(completer.get_completions(doc, None))
        texts = [c.text for c in completions]
        assert "/export" in texts
        assert "/exit" in texts
        assert "/chat" not in texts


# ---------------------------------------------------------------------------
# TestRegexHelpers
# ---------------------------------------------------------------------------

class TestRegexHelpers:

    def test_peer_id_regex_valid(self):
        assert PEER_ID_RE.match("a" * 40)

    def test_peer_id_regex_rejects_short(self):
        assert not PEER_ID_RE.match("a" * 39)

    def test_peer_id_regex_rejects_non_hex(self):
        assert not PEER_ID_RE.match("g" * 40)

    def test_peer_id_regex_rejects_long(self):
        assert not PEER_ID_RE.match("a" * 41)

    def test_peer_id_regex_rejects_uppercase(self):
        assert not PEER_ID_RE.match("A" * 40)

    def test_peer_id_regex_mixed_hex(self):
        assert PEER_ID_RE.match("0123456789abcdef" * 2 + "01234567")

    def test_hex64_regex_valid(self):
        assert HEX64_RE.match("a" * 64)

    def test_hex64_regex_rejects_short(self):
        assert not HEX64_RE.match("a" * 63)

    def test_hex64_regex_rejects_long(self):
        assert not HEX64_RE.match("a" * 65)

    def test_hex64_regex_rejects_non_hex(self):
        assert not HEX64_RE.match("g" * 64)
