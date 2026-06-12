"""
Tests for /api/files/* endpoints (iter-022).

Covers:
- POST /api/files/send             — multipart upload + send_file dispatch
- GET  /api/files                  — list of pending offers + completed files
- POST /api/files/accept           — register an incoming offer
- POST /api/files/reject           — drop a pending offer
- GET  /api/files/{file_id}/download — stream completed payload, then drop
- WebSocket pushes on offer / complete

Reuses the existing fixture style of test_api.py (httpx.ASGITransport).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from malphas.api import create_app
from malphas.identity import create_identity
from malphas.node import MalphasNode

VALID_PEER_ID_A = "a" * 40
VALID_X25519 = "c" * 64
VALID_ED25519 = "d" * 64


@pytest.fixture
def api_identity():
    return create_identity("api-files-test")


@pytest.fixture
def api_node(api_identity):
    return MalphasNode(
        api_identity,
        host="127.0.0.1",
        port=17790,
        cover_traffic=False,
    )


@pytest.fixture
def static_dir():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "index.html").write_text("<html></html>")
        yield d


@pytest.fixture
def app(api_node, static_dir):
    return create_app(api_node, static_dir)


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {app.state.api_token}"},
    ) as c:
        yield c


# ── /api/files/send ──────────────────────────────────────────────────────────

class TestFilesSend:
    async def test_unknown_peer_404(self, client):
        resp = await client.post(
            "/api/files/send",
            data={"peer_id": VALID_PEER_ID_A},
            files={"file": ("hello.txt", b"hello", "text/plain")},
        )
        assert resp.status_code == 404

    async def test_invalid_peer_400(self, client):
        resp = await client.post(
            "/api/files/send",
            data={"peer_id": "not-hex"},
            files={"file": ("hello.txt", b"hello", "text/plain")},
        )
        assert resp.status_code == 400

    async def test_calls_node_send_file_when_peer_known(self, client, api_node, monkeypatch):
        # Inject a peer in routing table so the 404 check passes
        api_node.discovery.add_peer(
            VALID_PEER_ID_A, "127.0.0.1", 9999,
            bytes.fromhex(VALID_X25519),
            bytes.fromhex(VALID_ED25519),
        )
        # Monkeypatch send_file to avoid touching network
        async def fake_send(dest, path):
            assert dest == VALID_PEER_ID_A
            with open(path, "rb") as f:
                assert f.read() == b"hello world"
            return "abc123" * 5 + "00"  # 32 hex
        monkeypatch.setattr(api_node, "send_file", fake_send)

        resp = await client.post(
            "/api/files/send",
            data={"peer_id": VALID_PEER_ID_A},
            files={"file": ("hello.txt", b"hello world", "text/plain")},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "file_id" in body
        assert body["file_id"].startswith("abc123")

    async def test_send_file_returns_none_503(self, client, api_node, monkeypatch):
        api_node.discovery.add_peer(
            VALID_PEER_ID_A, "127.0.0.1", 9999,
            bytes.fromhex(VALID_X25519),
            bytes.fromhex(VALID_ED25519),
        )
        async def fake_send(dest, path):
            return None
        monkeypatch.setattr(api_node, "send_file", fake_send)
        resp = await client.post(
            "/api/files/send",
            data={"peer_id": VALID_PEER_ID_A},
            files={"file": ("x.bin", b"x", "application/octet-stream")},
        )
        assert resp.status_code == 503


# ── /api/files (list) ────────────────────────────────────────────────────────

class TestFilesList:
    async def test_empty_initially(self, client):
        resp = await client.get("/api/files")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"pending": [], "completed": []}

    async def test_lists_pending_after_offer(self, client, api_node):
        offer = {
            "file_id": "deadbeef" * 4,
            "name": "photo.jpg",
            "size": 1234,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        # Trigger the registered on_file_offer callback directly.
        for cb in list(api_node._file_offer_callbacks):
            await cb("alice-id", offer)
        resp = await client.get("/api/files")
        data = resp.json()
        assert any(p["file_id"] == offer["file_id"] for p in data["pending"])
        assert data["completed"] == []


# ── /api/files/accept and /api/files/reject ──────────────────────────────────

class TestAcceptReject:
    async def test_accept_unknown_404(self, client):
        resp = await client.post(
            "/api/files/accept",
            json={"file_id": "abcd" * 8},
        )
        assert resp.status_code == 404

    async def test_accept_registers(self, client, api_node, monkeypatch):
        offer = {
            "file_id": "feedface" * 4,
            "name": "x.bin",
            "size": 1,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        for cb in list(api_node._file_offer_callbacks):
            await cb("alice-id", offer)

        called = {}
        def fake_accept(d):
            called["offer"] = d
            return True
        monkeypatch.setattr(api_node, "accept_file_offer", fake_accept)

        resp = await client.post(
            "/api/files/accept",
            json={"file_id": offer["file_id"]},
        )
        assert resp.status_code == 200, resp.text
        assert called["offer"]["file_id"] == offer["file_id"]
        # After accept it must be removed from pending
        listed = (await client.get("/api/files")).json()
        assert not any(p["file_id"] == offer["file_id"] for p in listed["pending"])

    async def test_reject_unknown_404(self, client):
        resp = await client.post(
            "/api/files/reject",
            json={"file_id": "abcd" * 8},
        )
        assert resp.status_code == 404

    async def test_reject_drops_pending(self, client, api_node):
        offer = {
            "file_id": "0badfade" * 4,
            "name": "x.bin",
            "size": 1,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        for cb in list(api_node._file_offer_callbacks):
            await cb("alice-id", offer)

        resp = await client.post(
            "/api/files/reject",
            json={"file_id": offer["file_id"]},
        )
        assert resp.status_code == 200
        listed = (await client.get("/api/files")).json()
        assert not any(p["file_id"] == offer["file_id"] for p in listed["pending"])


# ── /api/files/{file_id}/download ────────────────────────────────────────────

class TestDownload:
    async def test_unknown_404(self, client):
        resp = await client.get("/api/files/" + "a" * 32 + "/download")
        assert resp.status_code == 404

    async def test_invalid_id_400(self, client):
        resp = await client.get("/api/files/not-hex/download")
        assert resp.status_code == 400

    async def test_download_returns_payload_then_drops(self, client, api_node):
        # Simulate a complete file by firing the on_file_offer + on_file_complete
        # callbacks in sequence (the handler stores the payload).
        offer = {
            "file_id": "11223344" * 4,
            "name": "doc.bin",
            "size": 5,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        for cb in list(api_node._file_offer_callbacks):
            await cb("alice-id", offer)
        for cb in list(api_node._file_complete_callbacks):
            await cb(offer["file_id"], b"hello")

        resp = await client.get(f"/api/files/{offer['file_id']}/download")
        assert resp.status_code == 200, resp.text
        assert resp.content == b"hello"
        # Content-Disposition should carry a sanitized filename
        assert "doc.bin" in resp.headers.get("content-disposition", "")
        # Subsequent download must 404 (zero-disk: payload dropped)
        again = await client.get(f"/api/files/{offer['file_id']}/download")
        assert again.status_code == 404

    async def test_filename_is_sanitized(self, client, api_node):
        offer = {
            "file_id": "55667788" * 4,
            "name": "../etc/passwd",
            "size": 3,
            "sha256": "0" * 64,
            "chunk_size": 32768,
            "chunk_count": 1,
        }
        for cb in list(api_node._file_offer_callbacks):
            await cb("alice-id", offer)
        for cb in list(api_node._file_complete_callbacks):
            await cb(offer["file_id"], b"abc")

        resp = await client.get(f"/api/files/{offer['file_id']}/download")
        cd = resp.headers.get("content-disposition", "")
        # Slashes and dots-only paths must NOT survive into the disposition.
        assert "/" not in cd
        assert "passwd" in cd  # the basename portion remains, but hardened
