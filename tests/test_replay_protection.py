"""
Replay protection tests.

Covers:
- Unit tests on ReplayCache (insert, seen, expiry, cap, wipe).
- Integration tests on MalphasNode end-to-end:
  * Same (from_id, msg_id) delivered twice → callback called once.
  * Distinct msg_ids both delivered.
  * After cache TTL, the same key can pass again.
  * Path coverage: ratchet (default), HMAC fallback, Ed25519 fallback.
  * panic() wipes the replay cache.
"""

import asyncio
import time

import pytest

from malphas.identity import create_identity
from malphas.node import MalphasNode
from malphas.replay import ReplayCache  # noqa: F401 — must exist

# ── Unit tests ────────────────────────────────────────────────────────────────

class TestReplayCacheUnit:
    def test_first_insert_returns_false(self):
        cache = ReplayCache(ttl=60, max_entries=100)
        assert cache.seen("alice", "msg-1") is False

    def test_second_insert_returns_true(self):
        cache = ReplayCache(ttl=60, max_entries=100)
        cache.seen("alice", "msg-1")
        assert cache.seen("alice", "msg-1") is True

    def test_distinct_msg_ids_independent(self):
        cache = ReplayCache(ttl=60, max_entries=100)
        cache.seen("alice", "msg-1")
        assert cache.seen("alice", "msg-2") is False
        assert cache.seen("alice", "msg-2") is True

    def test_distinct_senders_independent(self):
        cache = ReplayCache(ttl=60, max_entries=100)
        cache.seen("alice", "msg-1")
        assert cache.seen("bob", "msg-1") is False

    def test_ttl_expiry(self):
        cache = ReplayCache(ttl=0.05, max_entries=100)  # 50 ms
        cache.seen("alice", "msg-1")
        assert cache.seen("alice", "msg-1") is True
        time.sleep(0.07)
        cache.purge_expired()
        # After purge, the entry is gone — same key passes again
        assert cache.seen("alice", "msg-1") is False

    def test_cap_evicts_oldest(self):
        cache = ReplayCache(ttl=3600, max_entries=3)
        cache.seen("a", "1")
        cache.seen("a", "2")
        cache.seen("a", "3")
        # This insertion must evict ("a", "1")
        cache.seen("a", "4")
        assert len(cache) == 3
        # ("a", "1") is gone — appears as new
        assert cache.seen("a", "1") is False

    def test_wipe_clears_everything(self):
        cache = ReplayCache(ttl=3600, max_entries=100)
        cache.seen("a", "1")
        cache.seen("a", "2")
        assert len(cache) == 2
        cache.wipe()
        assert len(cache) == 0
        assert cache.seen("a", "1") is False

    def test_purge_expired_returns_count(self):
        cache = ReplayCache(ttl=0.05, max_entries=100)
        cache.seen("a", "1")
        cache.seen("a", "2")
        time.sleep(0.07)
        # Add one fresh entry that should NOT be purged
        cache.seen("a", "3")
        purged = cache.purge_expired()
        assert purged == 2
        assert len(cache) == 1


# ── Integration helpers ──────────────────────────────────────────────────────

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
async def pair_replay():
    id_a = create_identity("replay-alice")
    id_b = create_identity("replay-bob")
    a = MalphasNode(id_a, "127.0.0.1", 18101, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18102, cover_traffic=False)
    await a.start()
    await b.start()
    assert await _connect(a, b, id_b)
    yield a, b, id_a, id_b
    await a.stop()
    await b.stop()


# ── Integration: replay protection ────────────────────────────────────────────

class TestReplayIntegration:
    async def test_ratchet_path_replay_is_dropped(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        received: list[tuple[str, str]] = []
        b.on_message(lambda f, c: received.append((f, c)))

        # Send the same msg_id twice via internal _try_send
        sent1 = await a._try_send(id_b.peer_id, "ratchet-replay", "fixed-rid-1")
        await asyncio.sleep(0.3)
        sent2 = await a._try_send(id_b.peer_id, "ratchet-replay", "fixed-rid-1")
        await asyncio.sleep(0.5)

        assert sent1 is True
        assert sent2 is True
        # Replay must be dropped — only ONE callback fires
        matched = [m for m in received if m[1] == "ratchet-replay"]
        assert len(matched) == 1, f"expected 1 delivery, got {len(matched)}: {received}"

    async def test_hmac_path_replay_is_dropped(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        received: list[tuple[str, str]] = []
        b.on_message(lambda f, c: received.append((f, c)))

        # Force HMAC path by disabling ratchet on the sender side
        conn_to_b = a._connections[id_b.peer_id]
        conn_to_b.ratchet = None

        # And on the receiver, make the inbound conn use HMAC fallback too
        for conn in b._connections.values():
            conn.ratchet = None

        await a._try_send(id_b.peer_id, "hmac-replay", "fixed-hid-1")
        await asyncio.sleep(0.3)
        await a._try_send(id_b.peer_id, "hmac-replay", "fixed-hid-1")
        await asyncio.sleep(0.5)

        matched = [m for m in received if m[1] == "hmac-replay"]
        assert len(matched) == 1

    async def test_ed25519_path_replay_is_dropped(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        received: list[tuple[str, str]] = []
        b.on_message(lambda f, c: received.append((f, c)))

        # Force Ed25519 fallback by disabling both ratchet and hmac_key
        conn_to_b = a._connections[id_b.peer_id]
        conn_to_b.ratchet = None
        conn_to_b.hmac_key = None
        for conn in b._connections.values():
            conn.ratchet = None
            conn.hmac_key = None

        await a._try_send(id_b.peer_id, "ed-replay", "fixed-eid-1")
        await asyncio.sleep(0.3)
        await a._try_send(id_b.peer_id, "ed-replay", "fixed-eid-1")
        await asyncio.sleep(0.5)

        matched = [m for m in received if m[1] == "ed-replay"]
        assert len(matched) == 1

    async def test_distinct_msg_ids_both_delivered(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        received: list[tuple[str, str]] = []
        b.on_message(lambda f, c: received.append((f, c)))

        await a._try_send(id_b.peer_id, "msg-A", "rid-A")
        await asyncio.sleep(0.2)
        await a._try_send(id_b.peer_id, "msg-B", "rid-B")
        await asyncio.sleep(0.5)

        contents = [m[1] for m in received]
        assert "msg-A" in contents
        assert "msg-B" in contents

    async def test_panic_wipes_replay_cache(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        received: list[tuple[str, str]] = []

        # First, deliver a message to populate B's replay cache
        b.on_message(lambda f, c: received.append((f, c)))
        await a._try_send(id_b.peer_id, "pre-panic", "fixed-pid-1")
        await asyncio.sleep(0.3)
        # Cache must contain the entry
        assert len(b._replay) >= 1

        # Panic wipes everything
        b.panic()
        assert len(b._replay) == 0

    async def test_message_store_no_double_entry(self, pair_replay):
        a, b, id_a, id_b = pair_replay
        await a._try_send(id_b.peer_id, "store-once", "fixed-sid-1")
        await asyncio.sleep(0.3)
        await a._try_send(id_b.peer_id, "store-once", "fixed-sid-1")
        await asyncio.sleep(0.3)

        msgs = b.store.get_conversation(id_a.peer_id, id_b.peer_id)
        matching = [m for m in msgs if m["content"] == "store-once"]
        assert len(matching) == 1
