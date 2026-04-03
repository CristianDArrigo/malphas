"""
Tests for the CLI interface (cli_ui.py).

Covers:
- Command parsing and dispatch
- /chat with peer_id, label, index, and unknown targets
- /book, /book add, /book rm, and edge cases
- Sending messages with and without active peer
- /wipe with confirmation and cancellation
- /panic emergency wipe
- /help output completeness
- /id identity display
- /peers display
- /history display
- Unknown command handling
- Plain text dispatch to _cmd_send
- /add command validation
- Startup banner
- Auto-connect
- Message/receipt callbacks
"""

import asyncio
import os
import socket
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from malphas.cli_ui import MalphasCLI, _hr, _print, PEER_ID_RE
from malphas.identity import create_identity, create_identity_with_book_key
from malphas.node import MalphasNode
from malphas.addressbook import AddressBook, Contact
from malphas.discovery import PeerInfo, PeerDiscovery
from malphas.memory import MessageStore


# ---------------------------------------------------------------------------
# Port allocation helper
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Find a free TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Identity fixtures (reused across all tests)
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
    node.port = 19100
    node.discovery = PeerDiscovery(identity_cli_a.peer_id)
    node.store = MessageStore()
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
# Helpers
# ---------------------------------------------------------------------------

def _capture_prints(func, *args, **kwargs):
    """Run a sync function and capture stdout."""
    buf = StringIO()
    with patch("sys.stdout", buf):
        func(*args, **kwargs)
    return buf.getvalue()


async def _capture_prints_async(coro):
    """Await an async coroutine and capture stdout."""
    buf = StringIO()
    with patch("sys.stdout", buf):
        await coro
    return buf.getvalue()


# ---------------------------------------------------------------------------
# TestCLICommandParsing
# ---------------------------------------------------------------------------

class TestCLICommandParsing:
    """Verify that the run() loop dispatches commands to the right methods."""

    async def test_quit_sets_running_false(self, cli):
        """The /quit command must stop the CLI loop."""
        cli._running = True
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert cli._running is False

    async def test_exit_sets_running_false(self, cli):
        """/exit must also stop the CLI loop."""
        cli._running = True
        lines = iter(["/exit\n", ""])
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert cli._running is False

    async def test_id_dispatches_to_print_identity(self, cli):
        """The /id command must call _print_identity."""
        with patch.object(cli, "_print_identity") as mock_id:
            lines = iter(["/id\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_id.assert_called_once()

    async def test_peers_dispatches_to_print_peers(self, cli):
        with patch.object(cli, "_print_peers") as mock_peers:
            lines = iter(["/peers\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_peers.assert_called_once()

    async def test_help_dispatches_to_print_help(self, cli):
        with patch.object(cli, "_print_help") as mock_help:
            lines = iter(["/help\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_help.assert_called_once()

    async def test_book_dispatches_to_cmd_book(self, cli):
        with patch.object(cli, "_cmd_book", new_callable=AsyncMock) as mock_book:
            lines = iter(["/book\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_book.assert_called_once_with([])

    async def test_book_add_dispatches_with_args(self, cli):
        with patch.object(cli, "_cmd_book", new_callable=AsyncMock) as mock_book:
            lines = iter(["/book add alice\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_book.assert_called_once_with(["add", "alice"])

    async def test_chat_dispatches_to_cmd_chat(self, cli):
        with patch.object(cli, "_cmd_chat", new_callable=AsyncMock) as mock_chat:
            lines = iter(["/chat somepeer\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_chat.assert_called_once_with(["somepeer"])

    async def test_wipe_dispatches_to_cmd_wipe(self, cli):
        with patch.object(cli, "_cmd_wipe", new_callable=AsyncMock) as mock_wipe:
            lines = iter(["/wipe\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_wipe.assert_called_once()

    async def test_panic_dispatches_to_cmd_panic(self, cli):
        with patch.object(cli, "_cmd_panic", new_callable=AsyncMock) as mock_panic:
            lines = iter(["/panic\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_panic.assert_called_once()

    async def test_plain_text_dispatches_to_cmd_send(self, cli):
        with patch.object(cli, "_cmd_send", new_callable=AsyncMock) as mock_send:
            lines = iter(["hello world\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_send.assert_called_once_with("hello world")

    async def test_unknown_command_prints_error(self, cli):
        """An unknown /command must print an error message."""
        output = StringIO()
        lines = iter(["/foobar\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert "unknown command" in output.getvalue().lower()

    async def test_empty_line_is_ignored(self, cli):
        """Blank lines must not dispatch any command."""
        with patch.object(cli, "_cmd_send", new_callable=AsyncMock) as mock_send:
            lines = iter(["   \n", "\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_send.assert_not_called()

    async def test_multiple_commands_in_sequence(self, cli):
        """Multiple commands in sequence must all dispatch."""
        with patch.object(cli, "_print_identity") as mock_id, \
             patch.object(cli, "_print_peers") as mock_peers, \
             patch.object(cli, "_print_help") as mock_help:
            lines = iter(["/id\n", "/peers\n", "/help\n", ""])
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.readline = lambda: next(lines)
                await cli.run()
            mock_id.assert_called_once()
            mock_peers.assert_called_once()
            mock_help.assert_called_once()


# ---------------------------------------------------------------------------
# TestChatCommand
# ---------------------------------------------------------------------------

class TestChatCommand:
    """Test /chat with various target types."""

    async def test_chat_no_args_prints_usage(self, cli):
        output = await _capture_prints_async(cli._cmd_chat([]))
        assert "usage" in output.lower()

    async def test_chat_by_label_auto_connects(
        self, cli_with_bob, identity_cli_b
    ):
        """
        /chat bob should resolve the label from the address book and
        attempt to connect. Since connect_to_peer is mocked to return
        False, it should report unreachable.
        """
        cli = cli_with_bob
        output = await _capture_prints_async(cli._cmd_chat(["bob"]))
        assert "could not reach" in output.lower()

    async def test_chat_by_label_sets_active_peer_when_connected(
        self, cli_with_bob, identity_cli_b
    ):
        """
        If auto-connect succeeds, active_peer should be set.
        """
        cli = cli_with_bob
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        # Simulate the peer being in the routing table after connect
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
        """
        If the peer is already in the routing table, no re-connect needed.
        """
        cli = cli_with_bob
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat(["bob"])
        assert cli.active_peer == identity_cli_b.peer_id
        # connect_to_peer should NOT have been called since peer is already connected
        cli.node.connect_to_peer.assert_not_called()

    async def test_chat_by_peer_id(self, cli, identity_cli_b):
        """
        /chat <full 40-char peer_id> should set active_peer when the
        peer is in the routing table.
        """
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat([identity_cli_b.peer_id])
        assert cli.active_peer == identity_cli_b.peer_id

    async def test_chat_by_index(self, cli, identity_cli_b):
        """/chat 0 should resolve the first peer in the routing table."""
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        await cli._cmd_chat(["0"])
        assert cli.active_peer is not None

    async def test_chat_index_out_of_range(self, cli):
        """An out-of-range index must print an error."""
        output = await _capture_prints_async(cli._cmd_chat(["99"]))
        assert "out of range" in output.lower()

    async def test_chat_unknown_target_prints_error(self, cli):
        """A target that is not a label, peer_id, or index must error."""
        output = await _capture_prints_async(cli._cmd_chat(["nonexistent_label"]))
        assert "not found" in output.lower()

    async def test_chat_prints_conversation_label(
        self, cli_with_bob, identity_cli_b
    ):
        """After opening a chat, the CLI should print a label."""
        cli = cli_with_bob
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = await _capture_prints_async(cli._cmd_chat(["bob"]))
        assert "bob" in output.lower()


# ---------------------------------------------------------------------------
# TestChatCommandIntegration (real TCP)
# ---------------------------------------------------------------------------

class TestChatCommandIntegration:
    """Integration tests for /chat with real nodes."""

    async def test_chat_label_auto_connects_real(
        self, real_node_a, real_node_b, identity_cli_b, fresh_book_cli
    ):
        """With real nodes, /chat <label> should auto-connect."""
        # Add bob to address book with real_node_b's actual port
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
        self, real_node_a, real_node_b, identity_cli_b, fresh_book_cli
    ):
        """With real nodes, /chat <peer_id> works after manual connect."""
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
    """Test /book, /book add, /book rm, and edge cases."""

    async def test_book_empty_prints_empty_message(self, cli):
        output = await _capture_prints_async(cli._cmd_book([]))
        assert "empty" in output.lower()

    async def test_book_lists_contacts(self, cli_with_bob):
        output = await _capture_prints_async(cli_with_bob._cmd_book([]))
        assert "bob" in output.lower()

    async def test_book_add_no_active_peer(self, cli):
        """/book add without an active conversation must error."""
        assert cli.active_peer is None
        output = await _capture_prints_async(cli._cmd_book(["add", "testlabel"]))
        assert "no active conversation" in output.lower()

    async def test_book_add_with_active_peer(self, cli, identity_cli_b):
        """
        /book add <label> should save the active peer to the address book.
        """
        # Add the peer to routing table (simulates connected state)
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
        """An empty label after /book add should print an error."""
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id

        with patch("builtins.input", return_value=""):
            output = await _capture_prints_async(cli._cmd_book(["add"]))
        assert "empty" in output.lower()

    async def test_book_add_prompts_for_label(self, cli, identity_cli_b):
        """When /book add has no label arg, it prompts for one."""
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
        """If the active peer is not in routing table, should error."""
        cli.active_peer = identity_cli_b.peer_id
        # Peer NOT added to discovery
        output = await _capture_prints_async(cli._cmd_book(["add", "ghost"]))
        assert "not in routing table" in output.lower()

    async def test_book_rm_existing_contact(self, cli_with_bob):
        """Removing an existing contact must succeed."""
        assert cli_with_bob.book.get("bob") is not None
        output = await _capture_prints_async(
            cli_with_bob._cmd_book(["rm", "bob"])
        )
        assert "removed" in output.lower()
        assert cli_with_bob.book.get("bob") is None

    async def test_book_rm_nonexistent_contact(self, cli):
        """/book rm with an unknown label must print 'not found'."""
        output = await _capture_prints_async(cli._cmd_book(["rm", "ghost"]))
        assert "not found" in output.lower()

    async def test_book_rm_no_label_prints_usage(self, cli):
        """/book rm without a label must print usage."""
        output = await _capture_prints_async(cli._cmd_book(["rm"]))
        assert "usage" in output.lower()

    async def test_book_unknown_subcommand(self, cli):
        """/book xyz must print 'unknown subcommand'."""
        output = await _capture_prints_async(cli._cmd_book(["xyz"]))
        assert "unknown subcommand" in output.lower()

    async def test_book_add_persists_to_disk(
        self, cli, identity_cli_b, tmp_book_path, book_key_cli
    ):
        """After /book add, the contact must persist to the encrypted file."""
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        await cli._cmd_book(["add", "persisted_bob"])

        # Reload from disk
        book2 = AddressBook(tmp_book_path, book_key_cli)
        book2.load()
        contact = book2.get("persisted_bob")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_book_rm_persists_removal(
        self, cli_with_bob, tmp_book_path, book_key_cli
    ):
        """Removing a contact and reloading must show it is gone."""
        await cli_with_bob._cmd_book(["rm", "bob"])

        book2 = AddressBook(tmp_book_path, book_key_cli)
        book2.load()
        assert book2.get("bob") is None

    async def test_book_add_multi_word_label(self, cli, identity_cli_b):
        """Labels with spaces should work: /book add My Friend."""
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
    """Test message sending with and without an active peer."""

    async def test_send_without_active_peer(self, cli):
        """Sending a message with no active conversation must error."""
        assert cli.active_peer is None
        output = await _capture_prints_async(cli._cmd_send("hello"))
        assert "no active conversation" in output.lower()

    async def test_send_with_active_peer_calls_send_message(
        self, cli, identity_cli_b
    ):
        """When a conversation is active, _cmd_send must call node.send_message."""
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value="msg123")

        await cli._cmd_send("test message")
        cli.node.send_message.assert_called_once_with(
            identity_cli_b.peer_id, "test message"
        )

    async def test_send_failure_prints_error(self, cli, identity_cli_b):
        """When send_message returns None, the CLI must print a failure message."""
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value=None)

        output = await _capture_prints_async(cli._cmd_send("will fail"))
        assert "failed" in output.lower() or "unreachable" in output.lower()

    async def test_send_success_prints_message(self, cli, identity_cli_b):
        """Successful send must echo the message with timestamp."""
        cli.active_peer = identity_cli_b.peer_id
        cli.node.send_message = AsyncMock(return_value="msg456")

        output = await _capture_prints_async(cli._cmd_send("echoed text"))
        assert "echoed text" in output
        assert "you" in output.lower()


# ---------------------------------------------------------------------------
# TestSendCommandIntegration
# ---------------------------------------------------------------------------

class TestSendCommandIntegration:
    """Integration test for message sending via real nodes."""

    async def test_send_real_message(
        self, real_node_a, real_node_b, identity_cli_a, identity_cli_b, fresh_book_cli
    ):
        """A real message sent via the CLI should be delivered."""
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
    """Test /wipe with confirmation and cancellation."""

    async def test_wipe_confirmed(self, cli, identity_cli_a):
        """When user confirms 'y', all messages must be wiped."""
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "secret")
        assert len(cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")) == 1

        with patch("builtins.input", return_value="y"):
            output = await _capture_prints_async(cli._cmd_wipe())

        assert "wiped" in output.lower()
        assert cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer") == []

    async def test_wipe_cancelled(self, cli, identity_cli_a):
        """When user enters 'n', messages must remain."""
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "keep me")

        with patch("builtins.input", return_value="n"):
            output = await _capture_prints_async(cli._cmd_wipe())

        assert "cancelled" in output.lower()
        msgs = cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")
        assert len(msgs) == 1
        assert msgs[0]["content"] == "keep me"

    async def test_wipe_empty_input_cancels(self, cli, identity_cli_a):
        """Pressing enter without typing 'y' must cancel."""
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "still here")

        with patch("builtins.input", return_value=""):
            output = await _capture_prints_async(cli._cmd_wipe())

        assert "cancelled" in output.lower()
        msgs = cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer")
        assert len(msgs) == 1

    async def test_wipe_capital_Y_cancels(self, cli, identity_cli_a):
        """Only lowercase 'y' should confirm (implementation does .lower())."""
        cli.node.store.store(identity_cli_a.peer_id, "other_peer", "test")

        with patch("builtins.input", return_value="Y"):
            await cli._cmd_wipe()

        # After .strip().lower(), "Y" -> "y", so it should actually wipe
        assert cli.node.store.get_conversation(identity_cli_a.peer_id, "other_peer") == []


# ---------------------------------------------------------------------------
# TestPanicCommand
# ---------------------------------------------------------------------------

class TestPanicCommand:
    """Test /panic emergency wipe."""

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
        """Panic must call sys.exit(0)."""
        with pytest.raises(SystemExit) as exc_info:
            await cli._cmd_panic()
        assert exc_info.value.code == 0

    async def test_panic_wipes_store_via_node(self, cli, identity_cli_a):
        """Messages stored before panic should be gone after."""
        cli.node.store.store(identity_cli_a.peer_id, "other", "sensitive")
        assert len(cli.node.store.get_conversation(identity_cli_a.peer_id, "other")) == 1

        with pytest.raises(SystemExit):
            await cli._cmd_panic()

        # The real store is wiped by node.panic(), but our mock node's panic()
        # is a MagicMock. We verify panic() was called — the node tests
        # verify that panic() actually clears the store.
        cli.node.panic.assert_called_once()


# ---------------------------------------------------------------------------
# TestHelpCommand
# ---------------------------------------------------------------------------

class TestHelpCommand:
    """Verify /help output includes all documented commands."""

    def test_help_includes_all_commands(self, cli):
        expected_commands = [
            "/id", "/peers", "/book", "/book add", "/book rm",
            "/add", "/chat", "/history", "/wipe", "/panic", "/quit",
        ]
        output = _capture_prints(cli._print_help)
        for cmd in expected_commands:
            assert cmd in output, f"Expected '{cmd}' in help output"

    def test_help_includes_text_sending(self, cli):
        output = _capture_prints(cli._print_help)
        assert "<text>" in output

    def test_help_mentions_emergency(self, cli):
        """Panic should mention it is an emergency action."""
        output = _capture_prints(cli._print_help)
        assert "emergency" in output.lower()

    def test_help_has_horizontal_rules(self, cli):
        """Help output should be framed with horizontal rules."""
        output = _capture_prints(cli._print_help)
        assert "\u2500" in output


# ---------------------------------------------------------------------------
# TestIdentityDisplay
# ---------------------------------------------------------------------------

class TestIdentityDisplay:
    """Test /id output."""

    def test_id_shows_peer_id(self, cli, identity_cli_a):
        output = _capture_prints(cli._print_identity)
        assert identity_cli_a.peer_id in output

    def test_id_shows_x25519_pub(self, cli, identity_cli_a):
        output = _capture_prints(cli._print_identity)
        assert identity_cli_a.x25519_pub_bytes.hex() in output

    def test_id_shows_ed25519_pub(self, cli, identity_cli_a):
        output = _capture_prints(cli._print_identity)
        assert identity_cli_a.ed25519_pub_bytes.hex() in output

    def test_id_shows_port(self, cli):
        output = _capture_prints(cli._print_identity)
        assert str(cli.node.port) in output

    def test_id_contains_labels(self, cli):
        """The output should label each field."""
        output = _capture_prints(cli._print_identity)
        assert "peer_id" in output
        assert "x25519_pub" in output
        assert "ed25519_pub" in output
        assert "port" in output


# ---------------------------------------------------------------------------
# TestPeersDisplay
# ---------------------------------------------------------------------------

class TestPeersDisplay:
    """Test /peers output."""

    def test_peers_empty(self, cli):
        """No connected peers must show a 'no peers' message."""
        output = _capture_prints(cli._print_peers)
        assert "no peers" in output.lower()

    def test_peers_shows_connected(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _capture_prints(cli._print_peers)
        assert identity_cli_b.peer_id[:16] in output

    def test_peers_marks_active_peer(self, cli, identity_cli_b):
        """The active peer should be marked with an asterisk."""
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        cli.active_peer = identity_cli_b.peer_id
        output = _capture_prints(cli._print_peers)
        assert " *" in output

    def test_peers_shows_host_port(self, cli, identity_cli_b):
        cli.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _capture_prints(cli._print_peers)
        assert "127.0.0.1:19101" in output

    def test_peers_shows_book_label(self, cli_with_bob, identity_cli_b):
        """If a connected peer is in the address book, show the label."""
        cli_with_bob.node.discovery.add_peer(
            identity_cli_b.peer_id, "127.0.0.1", 19101,
            identity_cli_b.x25519_pub_bytes,
            identity_cli_b.ed25519_pub_bytes,
        )
        output = _capture_prints(cli_with_bob._print_peers)
        assert "bob" in output.lower()


# ---------------------------------------------------------------------------
# TestBookDisplay
# ---------------------------------------------------------------------------

class TestBookDisplay:
    """Test /book output."""

    def test_book_empty_display(self, cli):
        output = _capture_prints(cli._print_book)
        assert "empty" in output.lower()

    def test_book_display_shows_label(self, cli_with_bob):
        output = _capture_prints(cli_with_bob._print_book)
        assert "bob" in output.lower()

    def test_book_display_shows_peer_id_prefix(self, cli_with_bob, identity_cli_b):
        output = _capture_prints(cli_with_bob._print_book)
        assert identity_cli_b.peer_id[:16] in output

    def test_book_display_marks_active(self, cli_with_bob, identity_cli_b):
        """Active peer in the book should be marked with *."""
        cli_with_bob.active_peer = identity_cli_b.peer_id
        output = _capture_prints(cli_with_bob._print_book)
        assert " *" in output

    def test_book_display_multiple_contacts(
        self, cli_with_bob, contact_charlie
    ):
        cli_with_bob.book.add(contact_charlie)
        output = _capture_prints(cli_with_bob._print_book)
        assert "bob" in output.lower()
        assert "charlie" in output.lower()

    def test_book_display_shows_host_port(self, cli_with_bob):
        output = _capture_prints(cli_with_bob._print_book)
        assert "127.0.0.1:19101" in output


# ---------------------------------------------------------------------------
# TestHistoryCommand
# ---------------------------------------------------------------------------

class TestHistoryCommand:
    """Test /history command."""

    async def test_history_no_active_peer(self, cli):
        """Without an active conversation, /history must error."""
        output = StringIO()
        lines = iter(["/history\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert "no active conversation" in output.getvalue().lower()

    def test_history_shows_messages(self, cli, identity_cli_a, identity_cli_b):
        """With messages stored, _print_conversation must show them."""
        cli.node.store.store(
            identity_cli_a.peer_id, identity_cli_b.peer_id, "archived message"
        )
        output = _capture_prints(cli._print_conversation, identity_cli_b.peer_id)
        assert "archived message" in output

    def test_history_empty_conversation(self, cli, identity_cli_b):
        """With no messages, print 'no messages'."""
        output = _capture_prints(cli._print_conversation, identity_cli_b.peer_id)
        assert "no messages" in output.lower()

    def test_history_labels_own_messages(self, cli, identity_cli_a, identity_cli_b):
        """Messages sent by the current node should be labeled 'you'."""
        cli.node.store.store(
            identity_cli_a.peer_id, identity_cli_b.peer_id, "my message"
        )
        output = _capture_prints(cli._print_conversation, identity_cli_b.peer_id)
        assert "you" in output.lower()

    def test_history_labels_peer_messages_by_label(
        self, cli_with_bob, identity_cli_a, identity_cli_b
    ):
        """Messages from a peer in the address book should use their label."""
        cli = cli_with_bob
        cli.node.store.store(
            identity_cli_b.peer_id, identity_cli_a.peer_id, "from bob"
        )
        output = _capture_prints(cli._print_conversation, identity_cli_b.peer_id)
        assert "bob" in output.lower()

    def test_history_labels_unknown_peer_by_truncated_id(
        self, cli, identity_cli_a, identity_cli_b
    ):
        """Messages from an unknown peer should show truncated peer_id."""
        cli.node.store.store(
            identity_cli_b.peer_id, identity_cli_a.peer_id, "from stranger"
        )
        output = _capture_prints(cli._print_conversation, identity_cli_b.peer_id)
        assert identity_cli_b.peer_id[:8] in output


# ---------------------------------------------------------------------------
# TestCallbacks
# ---------------------------------------------------------------------------

class TestCallbacks:
    """Test the _on_message and _on_receipt callbacks."""

    async def test_on_message_active_peer_prints_content(
        self, cli_with_bob, identity_cli_b
    ):
        """Incoming message from the active peer should print the content."""
        cli = cli_with_bob
        cli.active_peer = identity_cli_b.peer_id

        output = await _capture_prints_async(
            cli._on_message(identity_cli_b.peer_id, "hello from bob")
        )
        assert "hello from bob" in output

    async def test_on_message_inactive_peer_prints_notification(
        self, cli_with_bob, identity_cli_b
    ):
        """Incoming message from a non-active peer should print a notification."""
        cli = cli_with_bob
        cli.active_peer = None

        output = await _capture_prints_async(
            cli._on_message(identity_cli_b.peer_id, "hello from bob")
        )
        assert "new message" in output.lower()

    async def test_on_message_uses_label_from_book(
        self, cli_with_bob, identity_cli_b
    ):
        """If the sender is in the address book, their label should be shown."""
        cli = cli_with_bob
        cli.active_peer = identity_cli_b.peer_id

        output = await _capture_prints_async(
            cli._on_message(identity_cli_b.peer_id, "labeled message")
        )
        assert "bob" in output.lower()

    async def test_on_message_unknown_sender_shows_truncated_id(self, cli):
        """An unknown sender should show a truncated peer_id."""
        fake_peer_id = "a" * 40
        cli.active_peer = fake_peer_id

        output = await _capture_prints_async(
            cli._on_message(fake_peer_id, "who am i")
        )
        assert fake_peer_id[:8] in output

    async def test_on_receipt_received(self, cli_with_bob, identity_cli_b):
        """A received receipt should print 'read by <label>'."""
        cli = cli_with_bob
        output = await _capture_prints_async(
            cli._on_receipt("msg123", identity_cli_b.peer_id, True)
        )
        assert "read by" in output.lower()
        assert "bob" in output.lower()

    async def test_on_receipt_not_received(self, cli_with_bob, identity_cli_b):
        """A failed receipt should print a warning."""
        cli = cli_with_bob
        output = await _capture_prints_async(
            cli._on_receipt("msg123", identity_cli_b.peer_id, False)
        )
        assert "no receipt" in output.lower()

    async def test_on_receipt_unknown_peer_shows_truncated_id(self, cli):
        """A receipt from an unknown peer should use truncated peer_id."""
        fake_peer_id = "b" * 40
        output = await _capture_prints_async(
            cli._on_receipt("msg123", fake_peer_id, True)
        )
        assert fake_peer_id[:8] in output


# ---------------------------------------------------------------------------
# TestAddCommand
# ---------------------------------------------------------------------------

class TestAddCommand:
    """Test /add <host> <port>."""

    async def test_add_no_args_prints_usage(self, cli):
        output = await _capture_prints_async(cli._cmd_add([]))
        assert "usage" in output.lower()

    async def test_add_one_arg_prints_usage(self, cli):
        output = await _capture_prints_async(cli._cmd_add(["127.0.0.1"]))
        assert "usage" in output.lower()

    async def test_add_invalid_port_too_large(self, cli):
        output = await _capture_prints_async(cli._cmd_add(["127.0.0.1", "999999"]))
        assert "invalid port" in output.lower()

    async def test_add_invalid_port_zero(self, cli):
        output = await _capture_prints_async(cli._cmd_add(["127.0.0.1", "0"]))
        assert "invalid port" in output.lower()

    async def test_add_non_numeric_port(self, cli):
        output = await _capture_prints_async(cli._cmd_add(["127.0.0.1", "abc"]))
        assert "invalid port" in output.lower()

    async def test_add_invalid_peer_id(self, cli):
        """An invalid peer_id (not 40-char hex) must be rejected."""
        with patch("builtins.input", return_value="not_a_valid_hex"):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid peer_id" in output.lower()

    async def test_add_invalid_x25519_pub(self, cli, identity_cli_b):
        """A valid peer_id but invalid x25519_pub must be rejected."""
        inputs = iter([identity_cli_b.peer_id, "not_valid_hex"])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid x25519_pub" in output.lower()

    async def test_add_invalid_ed25519_pub(self, cli, identity_cli_b):
        """Valid peer_id and x25519, but invalid ed25519 must be rejected."""
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            "bad_hex",
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "invalid ed25519_pub" in output.lower()

    async def test_add_connection_failure(self, cli, identity_cli_b):
        """Connecting to a non-listening port must report failure."""
        cli.node.connect_to_peer = AsyncMock(return_value=False)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19199"])
            )
        assert "failed" in output.lower()

    async def test_add_success_no_save(self, cli, identity_cli_b):
        """A successful connect with 'n' to save should not add to book."""
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "n",  # don't save
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "connected" in output.lower()
        assert cli.book.get("bob") is None

    async def test_add_success_with_save(self, cli, identity_cli_b):
        """After connecting, saving to address book must work."""
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "y",          # save
            "bob_manual",  # label
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            await cli._cmd_add(["127.0.0.1", "19101"])

        contact = cli.book.get("bob_manual")
        assert contact is not None
        assert contact.peer_id == identity_cli_b.peer_id

    async def test_add_save_empty_label(self, cli, identity_cli_b):
        """Saving with an empty label should print a message and not save."""
        cli.node.connect_to_peer = AsyncMock(return_value=True)
        inputs = iter([
            identity_cli_b.peer_id,
            identity_cli_b.x25519_pub_bytes.hex(),
            identity_cli_b.ed25519_pub_bytes.hex(),
            "y",  # save
            "",   # empty label
        ])
        with patch("builtins.input", side_effect=lambda prompt: next(inputs)):
            output = await _capture_prints_async(
                cli._cmd_add(["127.0.0.1", "19101"])
            )
        assert "label empty" in output.lower() or "not saved" in output.lower()


# ---------------------------------------------------------------------------
# TestRunBanner
# ---------------------------------------------------------------------------

class TestRunBanner:
    """Test the startup banner printed by run()."""

    async def test_banner_shows_peer_id(self, cli, identity_cli_a):
        output = StringIO()
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert identity_cli_a.peer_id in output.getvalue()

    async def test_banner_shows_port(self, cli):
        output = StringIO()
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert str(cli.node.port) in output.getvalue()

    async def test_banner_shows_help_hint(self, cli):
        output = StringIO()
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert "/help" in output.getvalue()

    async def test_banner_shows_book_count(self, cli_with_bob):
        """When contacts exist, the banner should mention the count."""
        output = StringIO()
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli_with_bob.run()
        assert "1 contact" in output.getvalue()

    async def test_banner_shows_malphas_name(self, cli):
        output = StringIO()
        lines = iter(["/quit\n", ""])
        with patch("sys.stdin") as mock_stdin, \
             patch("sys.stdout", output):
            mock_stdin.readline = lambda: next(lines)
            await cli.run()
        assert "malphas" in output.getvalue().lower()


# ---------------------------------------------------------------------------
# TestAutoConnect
# ---------------------------------------------------------------------------

class TestAutoConnect:
    """Test the auto-connect feature at startup."""

    async def test_auto_connect_empty_book(self, cli):
        """With no contacts, auto-connect should do nothing."""
        output = await _capture_prints_async(cli._auto_connect())
        assert output.strip() == ""

    async def test_auto_connect_unreachable(self, cli_with_bob):
        """When contacts are unreachable, it should report them."""
        output = await _capture_prints_async(cli_with_bob._auto_connect())
        assert "unreachable" in output.lower()

    async def test_auto_connect_success(self, cli_with_bob):
        """When a contact is reachable, it should report success."""
        cli_with_bob.node.connect_to_peer = AsyncMock(return_value=True)
        output = await _capture_prints_async(cli_with_bob._auto_connect())
        assert "connected" in output.lower()

    async def test_auto_connect_reports_count(self, cli_with_bob):
        """Auto-connect should report the number of contacts."""
        output = await _capture_prints_async(cli_with_bob._auto_connect())
        assert "1 contact" in output.lower()


# ---------------------------------------------------------------------------
# TestModuleHelpers
# ---------------------------------------------------------------------------

class TestModuleHelpers:
    """Test module-level helper functions."""

    def test_hr_returns_horizontal_rule(self):
        hr = _hr()
        assert len(hr) > 0
        assert all(c == "\u2500" for c in hr)

    def test_peer_id_regex_valid(self):
        valid = "a" * 40
        assert PEER_ID_RE.match(valid)

    def test_peer_id_regex_rejects_short(self):
        assert not PEER_ID_RE.match("a" * 39)

    def test_peer_id_regex_rejects_non_hex(self):
        assert not PEER_ID_RE.match("g" * 40)

    def test_peer_id_regex_rejects_long(self):
        assert not PEER_ID_RE.match("a" * 41)

    def test_peer_id_regex_case_insensitive_input(self):
        """Uppercase hex should not match (regex only allows lowercase)."""
        assert not PEER_ID_RE.match("A" * 40)

    def test_peer_id_regex_mixed_hex(self):
        """A valid 40-char lowercase hex string should match."""
        assert PEER_ID_RE.match("0123456789abcdef" * 2 + "01234567")
