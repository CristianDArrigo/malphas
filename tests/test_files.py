"""
File transfer tests (iter-010 — red phase).

Unit: chunkify, dedup, out-of-order, SHA256 mismatch, cap enforcement, cancel.
Integration: end-to-end transfer via two real nodes.
"""

import asyncio
import hashlib
import os
import tempfile

import pytest

# This will fail at collection time until iter-010-green lands.
from malphas.files import (  # noqa: E402
    CHUNK_SIZE,
    MAX_FILE_BYTES,
    FileOffer,
    FileTransferManager,
    IncomingFile,
    OutgoingFile,
)
from malphas.identity import create_identity
from malphas.node import MalphasNode

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_temp_file(size: int) -> str:
    fd, path = tempfile.mkstemp(prefix="malphas-ftest-")
    with os.fdopen(fd, "wb") as f:
        # Deterministic non-trivial content for stable hashes
        f.write(os.urandom(size))
    return path


# ── Unit ──────────────────────────────────────────────────────────────────────

class TestOutgoingFile:
    def test_chunkify_count_matches_size(self):
        path = _make_temp_file(CHUNK_SIZE * 4 + 1234)
        try:
            of = OutgoingFile(path)
            offer = of.offer()
            chunks = list(of.chunkify())
            assert offer.chunk_count == len(chunks) == 5
        finally:
            os.unlink(path)

    def test_offer_sha256_correct(self):
        path = _make_temp_file(2048)
        try:
            with open(path, "rb") as f:
                expected = hashlib.sha256(f.read()).hexdigest()
            of = OutgoingFile(path)
            assert of.offer().sha256 == expected
        finally:
            os.unlink(path)

    def test_max_file_size_enforced(self, monkeypatch):
        # Pretend a 200 MB file via stat
        path = _make_temp_file(1)
        try:
            # Force the size attribute (avoid actually creating 200 MB)
            monkeypatch.setattr(os.path, "getsize", lambda _p: MAX_FILE_BYTES + 1)
            with pytest.raises(ValueError):
                OutgoingFile(path)
        finally:
            os.unlink(path)


class TestIncomingFile:
    def test_assemble_byte_perfect(self):
        path = _make_temp_file(CHUNK_SIZE * 3)
        try:
            with open(path, "rb") as f:
                original = f.read()
            of = OutgoingFile(path)
            offer = of.offer()
            ic = IncomingFile(offer)
            for idx, data in of.chunkify():
                ic.add_chunk(idx, data)
            assert ic.is_complete()
            assert ic.assemble() == original
        finally:
            os.unlink(path)

    def test_chunk_dedup(self):
        path = _make_temp_file(CHUNK_SIZE * 2)
        try:
            of = OutgoingFile(path)
            ic = IncomingFile(of.offer())
            chunks = list(of.chunkify())
            ic.add_chunk(*chunks[0])
            # Same idx, same data: must remain consistent
            ic.add_chunk(*chunks[0])
            ic.add_chunk(*chunks[1])
            assert ic.is_complete()
        finally:
            os.unlink(path)

    def test_chunk_out_of_order(self):
        path = _make_temp_file(CHUNK_SIZE * 4)
        try:
            with open(path, "rb") as f:
                original = f.read()
            of = OutgoingFile(path)
            ic = IncomingFile(of.offer())
            chunks = list(of.chunkify())
            for idx, data in reversed(chunks):
                ic.add_chunk(idx, data)
            assert ic.assemble() == original
        finally:
            os.unlink(path)

    def test_sha256_mismatch_raises(self):
        path = _make_temp_file(CHUNK_SIZE)
        try:
            of = OutgoingFile(path)
            offer = of.offer()
            # Tamper offer hash
            tampered = FileOffer(
                file_id=offer.file_id,
                name=offer.name,
                size=offer.size,
                sha256="0" * 64,
                chunk_size=offer.chunk_size,
                chunk_count=offer.chunk_count,
            )
            ic = IncomingFile(tampered)
            for idx, data in of.chunkify():
                ic.add_chunk(idx, data)
            with pytest.raises(ValueError):
                ic.assemble()
        finally:
            os.unlink(path)

    def test_progress_reports_fraction(self):
        path = _make_temp_file(CHUNK_SIZE * 4)
        try:
            of = OutgoingFile(path)
            ic = IncomingFile(of.offer())
            chunks = list(of.chunkify())
            assert ic.progress() == 0.0
            ic.add_chunk(*chunks[0])
            assert ic.progress() == pytest.approx(0.25)
            ic.add_chunk(*chunks[1])
            assert ic.progress() == pytest.approx(0.5)
        finally:
            os.unlink(path)

    def test_cancel_frees_memory(self):
        path = _make_temp_file(CHUNK_SIZE)
        try:
            of = OutgoingFile(path)
            ic = IncomingFile(of.offer())
            for idx, data in of.chunkify():
                ic.add_chunk(idx, data)
            ic.cancel()
            # After cancel, calling assemble must error
            with pytest.raises(Exception):
                ic.assemble()
        finally:
            os.unlink(path)


class TestFileTransferManager:
    def test_register_outgoing_returns_file_id(self):
        mgr = FileTransferManager()
        path = _make_temp_file(64)
        try:
            of = OutgoingFile(path)
            file_id = mgr.register_outgoing(of)
            assert isinstance(file_id, str) and len(file_id) >= 16
        finally:
            os.unlink(path)

    def test_get_incoming_returns_registered(self):
        mgr = FileTransferManager()
        path = _make_temp_file(64)
        try:
            of = OutgoingFile(path)
            offer = of.offer()
            ic = mgr.register_incoming(offer)
            assert mgr.get_incoming(offer.file_id) is ic
        finally:
            os.unlink(path)

    def test_wipe_clears_all(self):
        mgr = FileTransferManager()
        path = _make_temp_file(64)
        try:
            of = OutgoingFile(path)
            mgr.register_incoming(of.offer())
            mgr.wipe()
            assert mgr.get_incoming(of.offer().file_id) is None
        finally:
            os.unlink(path)


# ── Integration: E2E ─────────────────────────────────────────────────────────

@pytest.fixture
async def file_pair():
    id_a = create_identity("file-alice")
    id_b = create_identity("file-bob")
    a = MalphasNode(id_a, "127.0.0.1", 18301, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18302, cover_traffic=False)
    await a.start()
    await b.start()
    ok = await a.connect_to_peer(
        "127.0.0.1", b.port, id_b.peer_id,
        id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
    )
    assert ok
    await asyncio.sleep(0.15)
    yield a, b, id_a, id_b
    await a.stop()
    await b.stop()


class TestFileTransferIntegration:
    async def test_small_file_arrives_intact(self, file_pair):
        a, b, id_a, id_b = file_pair
        path = _make_temp_file(1024)
        try:
            with open(path, "rb") as f:
                expected = f.read()
            received: list[bytes] = []

            async def on_complete(file_id, data):
                received.append(data)

            b.on_file_complete(on_complete)
            # Auto-accept BEFORE sending so the offer is accepted in time
            # for the chunks that follow.
            b.auto_accept_files = True

            file_id = await a.send_file(id_b.peer_id, path)
            assert file_id is not None

            await asyncio.sleep(2.0)
            assert any(d == expected for d in received), \
                f"file not delivered intact ({len(received)} payloads)"
        finally:
            os.unlink(path)

    async def test_panic_wipes_files(self, file_pair):
        a, b, id_a, id_b = file_pair
        path = _make_temp_file(1024)
        try:
            b.auto_accept_files = True
            await a.send_file(id_b.peer_id, path)
            await asyncio.sleep(0.5)
            # b's file manager has at least one entry
            b.panic()
            assert len(b._files._incoming) == 0
        finally:
            os.unlink(path)
