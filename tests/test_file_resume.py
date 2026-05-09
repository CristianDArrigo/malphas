"""
Tests for file transfer resume (v0.8.0).

Verifies:
- IncomingFile.received_indices() correctness (unit).
- E2E: receiver with a partial buffer triggers a file_resume from the
  sender's offer, sender skips the indices, transfer completes.
- E2E: fresh file_id on the receiver side → no resume signal, sender
  proceeds normally.
- panic() unblocks in-flight resume waiters.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from malphas.files import FileOffer, IncomingFile, OutgoingFile
from malphas.identity import create_identity
from malphas.node import MalphasNode


def _make_temp_file(size: int) -> str:
    fd, path = tempfile.mkstemp(prefix="malphas-resume-")
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(size))
    return path


# ── Unit ──────────────────────────────────────────────────────────────────────


def test_received_indices_empty():
    of = OutgoingFile(_make_temp_file(64))
    try:
        ic = IncomingFile(of.offer())
        assert ic.received_indices() == []
    finally:
        os.unlink(of._path)  # type: ignore[attr-defined]


def test_received_indices_after_partial_fill():
    path = _make_temp_file(32 * 1024 * 4)  # 4 chunks of 32 KB
    try:
        of = OutgoingFile(path)
        ic = IncomingFile(of.offer())
        chunks = list(of.chunkify())
        ic.add_chunk(*chunks[0])
        ic.add_chunk(*chunks[2])
        assert ic.received_indices() == [0, 2]
    finally:
        os.unlink(path)


# ── E2E ───────────────────────────────────────────────────────────────────────


async def _connect(a: MalphasNode, b: MalphasNode, id_b) -> bool:
    ok = await a.connect_to_peer(
        "127.0.0.1", b.port,
        id_b.peer_id,
        id_b.x25519_pub_bytes,
        id_b.ed25519_pub_bytes,
    )
    await asyncio.sleep(0.15)
    return ok


@pytest.fixture
async def resume_pair():
    id_a = create_identity("resume-alice")
    id_b = create_identity("resume-bob")
    a = MalphasNode(id_a, "127.0.0.1", 18401, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18402, cover_traffic=False)
    await a.start()
    await b.start()
    assert await _connect(a, b, id_b)
    yield a, b, id_a, id_b
    await a.stop()
    await b.stop()


class TestResumeIntegration:
    async def test_resume_after_partial_buffer(self, resume_pair):
        a, b, id_a, id_b = resume_pair
        path = _make_temp_file(32 * 1024 * 4)  # 4 chunks
        try:
            with open(path, "rb") as f:
                expected = f.read()

            received: list[bytes] = []
            b.on_file_complete(lambda fid, data: received.append(data))
            b.auto_accept_files = True

            # Step 1: register an OutgoingFile on Alice and pre-populate
            # 2 chunks on Bob's side as if from a previous attempt.
            of = OutgoingFile(path)
            file_id = a._files.register_outgoing(of)
            offer = of.offer()
            b._files.register_incoming(offer)
            ic = b._files.get_incoming(file_id)
            assert ic is not None
            chunks_list = list(of.chunkify())
            ic.add_chunk(*chunks_list[0])
            ic.add_chunk(*chunks_list[2])
            assert ic.received_indices() == [0, 2]

            # Step 2: trigger resume.
            result = await a.resume_file(id_b.peer_id, file_id)
            assert result == file_id

            await asyncio.sleep(2.0)

            # The receiver must have completed and the assembled data
            # equals the original.
            assert any(d == expected for d in received), \
                f"resume did not produce a complete file (got {len(received)} payloads)"
        finally:
            os.unlink(path)

    async def test_resume_unknown_id_returns_none(self, resume_pair):
        a, b, id_a, id_b = resume_pair
        result = await a.resume_file(id_b.peer_id, "deadbeef" * 4)
        assert result is None

    async def test_panic_unblocks_resume_wait(self, resume_pair):
        a, b, id_a, id_b = resume_pair
        path = _make_temp_file(64)
        try:
            of = OutgoingFile(path)
            file_id = a._files.register_outgoing(of)

            # Disconnect b so a's send won't get a file_resume.
            await b.stop()
            await asyncio.sleep(0.1)

            # Kick off a send and immediately panic from another task.
            send_task = asyncio.create_task(
                a.send_file(id_b.peer_id, path, file_id=file_id)
            )
            await asyncio.sleep(0.05)
            a.panic()

            # The panic should set every pending resume Event so the
            # send completes (it'll likely return file_id-or-None
            # quickly without hanging).
            try:
                await asyncio.wait_for(send_task, timeout=2.0)
            except asyncio.TimeoutError:
                pytest.fail("send_file did not complete after panic()")
        finally:
            os.unlink(path)
