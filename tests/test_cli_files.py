"""
CLI command tests for file transfer (iter-012).

These tests don't drive prompt_toolkit; they invoke the `_cmd_*` methods
directly on a `MalphasCLI` whose node is mocked so we can assert what
the commands ask of it.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from malphas.addressbook import AddressBook
from malphas.cli_ui import MalphasCLI
from malphas.files import FileOffer, FileTransferManager, OutgoingFile


def _temp_path(content: bytes = b"hello world\n") -> str:
    fd, path = tempfile.mkstemp(prefix="malphas-cli-")
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


def _mock_book() -> AddressBook:
    book = MagicMock(spec=AddressBook)
    book.get_by_peer_id.return_value = None
    book.get.return_value = None
    book.all.return_value = []
    book.__len__ = MagicMock(return_value=0)
    return book


def _mock_node() -> MagicMock:
    node = MagicMock()
    node.identity.peer_id = "a" * 40
    node.discovery.get_peer.return_value = MagicMock()
    node.discovery.all_peers.return_value = []
    node._files = FileTransferManager()
    node.send_file = AsyncMock(return_value="abc123def456" * 2 + "0000")
    node.accept_file_offer = MagicMock(return_value=True)
    node.send_file_resume = AsyncMock()
    return node


# ── /sendfile ────────────────────────────────────────────────────────────────

class TestSendfile:
    async def test_no_args_errors(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._err = MagicMock()
        await cli._cmd_sendfile([])
        cli._err.assert_called()
        node.send_file.assert_not_called()

    async def test_calls_node_send_file_with_resolved_peer(self):
        node = _mock_node()
        book = _mock_book()
        # /sendfile <peer_id_hex> <path>
        peer_id = "b" * 40
        node.discovery.get_peer.return_value = MagicMock()
        cli = MalphasCLI(node, book)
        cli._err = MagicMock()
        cli._ok = MagicMock()
        path = _temp_path(b"data")
        try:
            await cli._cmd_sendfile([peer_id, path])
        finally:
            os.unlink(path)
        node.send_file.assert_awaited_once()
        called_dest, called_path = node.send_file.await_args.args
        assert called_dest == peer_id
        assert called_path == path

    async def test_unknown_target_errors(self):
        node = _mock_node()
        node.discovery.get_peer.return_value = None
        book = _mock_book()
        book.get.return_value = None
        cli = MalphasCLI(node, book)
        cli._err = MagicMock()
        path = _temp_path(b"data")
        try:
            await cli._cmd_sendfile(["unknown-label", path])
        finally:
            os.unlink(path)
        cli._err.assert_called()
        node.send_file.assert_not_called()

    async def test_missing_file_errors(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._err = MagicMock()
        await cli._cmd_sendfile(["b" * 40, "/no/such/path"])
        cli._err.assert_called()
        node.send_file.assert_not_called()


# ── /accept and /reject ──────────────────────────────────────────────────────

class TestAcceptReject:
    async def test_accept_unknown_id_errors(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._err = MagicMock()
        await cli._cmd_accept(["nonexistent"])
        cli._err.assert_called()

    async def test_accept_registers_offer(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()

        offer_dict = {
            "file_id": "deadbeef" * 4,
            "name": "photo.jpg",
            "size": 1234,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        cli._pending_offers[offer_dict["file_id"]] = ("alice", offer_dict)

        await cli._cmd_accept([offer_dict["file_id"]])
        node.accept_file_offer.assert_called_once_with(offer_dict)
        cli._ok.assert_called()
        # After accept, the offer is no longer pending
        assert offer_dict["file_id"] not in cli._pending_offers

    async def test_accept_with_truncated_id(self):
        # Regression: offers are DISPLAYED with a 16-char prefix
        # (/accept {fid[:16]}), so accepting with that prefix must resolve
        # to the full key. Previously it errored "no pending offer".
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()
        full = "d2fb0a66202e8051" + "abcdef01" * 2   # 32 hex chars
        offer = {"file_id": full, "name": "codes.txt", "size": 135,
                 "sha256": "0" * 64, "chunk_size": 32768, "chunk_count": 1}
        cli._pending_offers[full] = ("alice", offer)

        await cli._cmd_accept([full[:16]])   # the displayed, truncated id
        node.accept_file_offer.assert_called_once_with(offer)
        assert full not in cli._pending_offers

    async def test_reject_drops_pending_offer(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()

        fid = "feedface" * 4
        cli._pending_offers[fid] = ("alice", {"file_id": fid, "size": 0,
                                              "name": "x", "sha256": "0" * 64,
                                              "chunk_size": 32768, "chunk_count": 0})

        await cli._cmd_reject([fid])
        cli._ok.assert_called()
        assert fid not in cli._pending_offers


# ── /savefile ────────────────────────────────────────────────────────────────

class TestSavefile:
    async def test_savefile_writes_bytes(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()

        fid = "cafebabe" * 4
        payload = b"contents on disk"
        cli._completed_files[fid] = ("alice", "thing.bin", payload)

        out_dir = tempfile.mkdtemp(prefix="malphas-savefile-")
        out_path = os.path.join(out_dir, "out.bin")
        try:
            await cli._cmd_savefile([fid, out_path])
            with open(out_path, "rb") as f:
                assert f.read() == payload
            cli._ok.assert_called()
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)
            os.rmdir(out_dir)

    async def test_savefile_unknown_id_errors(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._err = MagicMock()
        await cli._cmd_savefile(["nope", "/tmp/whatever"])
        cli._err.assert_called()

    async def test_savefile_to_directory_uses_original_name(self, tmp_path):
        # Regression: /savefile <id> <dir> writes to <dir>/<original name>.
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()
        fid = "abad1dea" * 4
        cli._completed_files[fid] = ("alice", "report.pdf", b"PDFDATA")
        await cli._cmd_savefile([fid, str(tmp_path)])
        assert (tmp_path / "report.pdf").read_bytes() == b"PDFDATA"

    async def test_savefile_expands_tilde(self, monkeypatch, tmp_path):
        # Regression: ~ must be expanded (open() does not do it).
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._ok = MagicMock()
        monkeypatch.setenv("HOME", str(tmp_path))
        fid = "0badf00d" * 4
        cli._completed_files[fid] = ("alice", "x.bin", b"hi")
        await cli._cmd_savefile([fid, "~/out.bin"])
        assert (tmp_path / "out.bin").read_bytes() == b"hi"

    async def test_on_file_complete_recovers_accepted_name(self):
        # Regression: the received file kept the real name, not "file.bin"
        # (the accepted offer was dropped from _pending_offers on /accept).
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._plain = MagicMock()
        fid = "feedbeef" * 4
        cli._accepted_offers[fid] = (
            "alice", {"file_id": fid, "name": "secret.txt"})
        await cli._on_file_complete(fid, b"data")
        from_id, name, _ = cli._completed_files[fid]
        assert name == "secret.txt"
        assert from_id == "alice"


# ── /files ───────────────────────────────────────────────────────────────────

class TestFilesList:
    async def test_files_lists_pending_and_completed(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._print = MagicMock()

        fid_pending = "1" * 32
        fid_done = "2" * 32
        cli._pending_offers[fid_pending] = ("alice", {
            "file_id": fid_pending,
            "name": "incoming.bin",
            "size": 1024,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        })
        cli._completed_files[fid_done] = ("bob", "done.bin", b"x" * 64)

        await cli._cmd_files([])
        # _print is called at least once for the table panel
        assert cli._print.called


# ── Notifications ─────────────────────────────────────────────────────────────

class TestFileNotifications:
    async def test_on_file_offer_callback_records_pending(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._plain = MagicMock()

        offer = {
            "file_id": "abc" * 8 + "00",
            "name": "photo.jpg",
            "size": 4096,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        await cli._on_file_offer("alice-id", offer)
        assert offer["file_id"] in cli._pending_offers
        cli._plain.assert_called()

    async def test_on_file_complete_records_payload(self):
        node = _mock_node()
        cli = MalphasCLI(node, _mock_book())
        cli._plain = MagicMock()

        # Pre-register the offer so the CLI knows the filename
        fid = "1234" * 8
        offer = {
            "file_id": fid,
            "name": "file.bin",
            "size": 5,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        cli._pending_offers[fid] = ("alice", offer)

        await cli._on_file_complete(fid, b"hello")
        # Once complete, it should move from pending to completed
        assert fid in cli._completed_files
        from_id, name, data = cli._completed_files[fid]
        assert name == "file.bin"
        assert data == b"hello"
        cli._plain.assert_called()
