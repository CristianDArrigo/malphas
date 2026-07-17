"""
Regression tests for the post-audit fixes (GitHub issues #5, #8, #11,
#13, #14, #15, #16, #17, #18, #19).

Each test pins a specific behaviour that was broken or missing before the
security-audit follow-up.
"""
import asyncio
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from malphas.receipts import ReceiptTracker, sign_receipt


# ── #16: resolved receipts must not leak in _pending ─────────────────────────
def test_resolved_receipt_removed_from_pending():
    tracker = ReceiptTracker()
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    nonce = b"\x11" * 16
    tracker.track("msg1", nonce, "peerX", "a secret message preview")
    assert "msg1" in tracker._pending

    sig = sign_receipt("msg1", nonce, priv)
    ok = tracker.resolve("msg1", sig, pub, from_peer_id="peerX")

    assert ok is True
    # The resolved receipt (and its 40-char plaintext preview) must be gone.
    assert "msg1" not in tracker._pending


# ── #8: node WIRE_VERSION must match the package/spec constant ────────────────
def test_wire_version_matches_package():
    import malphas
    import malphas.node as node
    assert node.WIRE_VERSION == malphas.WIRE_VERSION == 2


# ── #14: legacy-salt migration must not crash and must keep contacts ──────────
def test_legacy_salt_migration_preserves_contacts(tmp_path):
    from malphas.__main__ import _open_book_with_migration
    from malphas.addressbook import AddressBook, Contact
    from malphas.identity import create_identity, create_identity_with_book_key

    passphrase = "legacy-migrate-pass"
    book_path = tmp_path / "book"

    # Simulate a pre-0.7.0 book encrypted under the legacy fixed salt.
    _, legacy_key = create_identity_with_book_key(passphrase, salt=None)
    legacy = AddressBook(str(book_path), legacy_key)
    legacy.load()
    idb = create_identity("migrate-bob")
    legacy.add(Contact(
        label="bob", peer_id=idb.peer_id, host="127.0.0.1", port=17778,
        x25519_pub=idb.x25519_pub_bytes.hex(),
        ed25519_pub=idb.ed25519_pub_bytes.hex(),
    ))

    # New per-user random salt -> new key -> load() fails -> migration path.
    new_salt = os.urandom(16)
    book, book_key, identity = _open_book_with_migration(book_path, passphrase, new_salt)

    assert "bob" in [c.label for c in book.all()]


# ── #18: AddressBook._save must fsync (durability parity with PinStore) ───────
def test_addressbook_save_fsyncs(tmp_path, monkeypatch):
    import malphas.addressbook as ab
    from malphas.identity import create_identity, create_identity_with_book_key

    _, key = create_identity_with_book_key("durability-pass")
    book = ab.AddressBook(str(tmp_path / "book"), key)
    book.load()

    calls = []
    real_fsync = os.fsync
    monkeypatch.setattr(ab.os, "fsync", lambda fd: (calls.append(fd), real_fsync(fd))[1])

    idb = create_identity("durability-bob")
    book.add(ab.Contact(
        label="bob", peer_id=idb.peer_id, host="h", port=1,
        x25519_pub=idb.x25519_pub_bytes.hex(),
        ed25519_pub=idb.ed25519_pub_bytes.hex(),
    ))
    assert calls, "AddressBook._save must fsync for durability parity with PinStore"


# ── #5: handshake must reject an endpoint whose identity != the expected one ──
class TestHandshakeIdentity:
    async def test_rejects_mismatched_expected_identity(
        self, node_a, node_b, identity_b, identity_c
    ):
        # Dial B's real endpoint (port 17778) but claim to expect C's identity.
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_c.peer_id,               # expected = C (wrong; endpoint is B)
            identity_c.x25519_pub_bytes,
            identity_c.ed25519_pub_bytes,
        )
        assert ok is False
        # Neither the impostor (B, under its real id) nor the expected id (C)
        # may end up pinned/connected.
        assert node_a._connections.get(identity_b.peer_id) is None
        assert node_a._connections.get(identity_c.peer_id) is None

    async def test_matching_identity_still_connects(
        self, node_a, node_b, identity_b
    ):
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        assert ok is True
        assert node_a._connections.get(identity_b.peer_id) is not None


# ── #15: a stale read-loop must not evict a newer connection for the peer ─────
def test_stale_readloop_does_not_evict_newer_connection(identity_a):
    import types as _types

    from malphas.node import MalphasNode

    node = MalphasNode(identity_a, "127.0.0.1", 17781, cover_traffic=False)
    c1 = _types.SimpleNamespace(peer_info=_types.SimpleNamespace(peer_id="peerZ"))
    c2 = _types.SimpleNamespace(peer_info=_types.SimpleNamespace(peer_id="peerZ"))

    node._connections["peerZ"] = c1
    node._connections["peerZ"] = c2  # reconnect: c2 replaces c1

    # c1's read loop ends *after* c2 took over — it must not remove c2.
    pid = node._forget_connection_if_current(c1)
    assert pid == "peerZ"
    assert node._connections.get("peerZ") is c2

    # c2's own cleanup does remove it.
    node._forget_connection_if_current(c2)
    assert node._connections.get("peerZ") is None


# ── #17: _flush_queue must re-enqueue messages whose send fails ───────────────
async def test_flush_requeues_failed_sends(identity_a, monkeypatch):
    from malphas.node import MalphasNode

    node = MalphasNode(identity_a, "127.0.0.1", 17782, cover_traffic=False)
    node._enqueue("peerQ", "m1", "id1")
    node._enqueue("peerQ", "m2", "id2")

    async def always_fail(dest, content, msg_id):
        return False

    monkeypatch.setattr(node, "_try_send", always_fail)
    await node._flush_queue("peerQ")

    remaining = node._message_queue.get("peerQ", [])
    assert ("m1", "id1") in remaining
    assert ("m2", "id2") in remaining


# ── #11: handshake reads must honour a smaller frame cap ─────────────────────
class _FakeReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        if len(chunk) < n:
            raise asyncio.IncompleteReadError(chunk, n)
        self._pos += n
        return chunk


async def test_recv_raw_honours_smaller_handshake_cap():
    from malphas.node import (
        HANDSHAKE_MAX_FRAME_BYTES,
        MAX_FRAME_BYTES,
        PeerConnection,
        _pack_msg,
    )

    assert HANDSHAKE_MAX_FRAME_BYTES < MAX_FRAME_BYTES
    oversized = b"x" * (HANDSHAKE_MAX_FRAME_BYTES + 1)
    frame = _pack_msg(0x01, oversized)
    conn = PeerConnection(_FakeReader(frame), None)
    with pytest.raises(ConnectionError):
        await conn.recv_raw(max_bytes=HANDSHAKE_MAX_FRAME_BYTES)


async def test_recv_raw_allows_normal_handshake_frame():
    from malphas.node import HANDSHAKE_MAX_FRAME_BYTES, PeerConnection, _pack_msg

    payload = b"hello" * 4
    frame = _pack_msg(0x01, payload)
    conn = PeerConnection(_FakeReader(frame), None)
    msg_type, got = await conn.recv_raw(max_bytes=HANDSHAKE_MAX_FRAME_BYTES)
    assert got == payload


# ── #13: panic must best-effort clear per-connection symmetric keys ───────────
def test_panic_clears_connection_symmetric_keys(identity_a):
    import types as _types

    from malphas.node import MalphasNode, PeerConnection

    node = MalphasNode(identity_a, "127.0.0.1", 17783, cover_traffic=False)
    conn = PeerConnection(_FakeReader(b""), None)
    conn.session_key = b"S" * 32
    conn.hmac_key = b"H" * 32
    conn.peer_info = _types.SimpleNamespace(peer_id="peerP")
    node._connections["peerP"] = conn

    node.panic()

    # The connection object outlives panic via this reference; its key bytes
    # must have been dropped, not left resident.
    assert conn.session_key is None
    assert conn.hmac_key is None


# ── #19: only the group creator may mutate membership locally ────────────────
async def test_non_creator_cannot_mutate_membership(
    identity_a, identity_b, identity_c
):
    from malphas.node import MalphasNode

    node = MalphasNode(identity_a, "127.0.0.1", 17784, cover_traffic=False)
    # Put C in discovery so the "member must be known" gate passes and only
    # the creator check can block the operation.
    node.discovery.add_peer(
        identity_c.peer_id, "127.0.0.1", 1,
        identity_c.x25519_pub_bytes, identity_c.ed25519_pub_bytes,
    )
    # Group created BY B; A is only a member, not the creator.
    group = node._groups.create(
        "team", identity_b.peer_id, [identity_b.peer_id, identity_a.peer_id]
    )

    assert await node.add_group_member(group.group_id, identity_c.peer_id) is False
    assert await node.remove_group_member(group.group_id, identity_b.peer_id) is False
    # Membership must be untouched (no local fork).
    assert identity_c.peer_id not in group.members
    assert identity_b.peer_id in group.members


# ── #21: cover traffic must use the same 3-hop circuit as real messages ───────
async def test_cover_traffic_uses_three_hop_circuit(identity_a, monkeypatch):
    from malphas.node import MalphasNode

    node = MalphasNode(identity_a, "127.0.0.1", 17785, cover_traffic=False)
    recorded = {}

    def fake_circuit(dest, hops=None, relay_pool=None):
        recorded["hops"] = hops
        raise ValueError("no relays")  # short-circuit; we only inspect hops

    monkeypatch.setattr(node.discovery, "select_relay_circuit", fake_circuit)
    await node._send_cover_packet("peerCover")

    # A 1-hop cover packet is distinguishable from a 3-hop real message by
    # size and hop count; cover must route like real traffic.
    assert recorded.get("hops") == 3


# ── #10: unknown inbound pins stay in-memory + capped; known ones persist ─────
def test_ephemeral_pins_not_persisted_and_capped(tmp_path):
    from malphas.pinstore import MAX_EPHEMERAL_PINS, PinStore

    key = os.urandom(32)
    path = tmp_path / "pins"
    store = PinStore(str(path), key)

    # Flood with unknown inbound peers (persist=False).
    for i in range(MAX_EPHEMERAL_PINS + 50):
        store.check_and_pin(
            f"peer{i}", os.urandom(32), os.urandom(32), persist=False
        )

    # Nothing persisted to disk, and the in-memory ephemeral set is capped.
    assert not path.exists() or path.stat().st_size == 0
    assert store._pins == {}
    assert len(store._ephemeral_pins) <= MAX_EPHEMERAL_PINS

    # A known/invited peer (persist=True) still pins durably.
    store.check_and_pin("known1", os.urandom(32), os.urandom(32), persist=True)
    assert path.exists() and path.stat().st_size > 0
    assert "known1" in store._pins


def test_ephemeral_pin_still_detects_mismatch_in_session(tmp_path):
    from malphas.pinstore import PinStore

    store = PinStore(str(tmp_path / "pins"), os.urandom(32))
    ed = os.urandom(32)
    x = os.urandom(32)
    ok, _ = store.check_and_pin("peerE", ed, x, persist=False)
    assert ok is True
    # Same peer_id, different Ed25519 key later in the same session = MITM.
    ok2, pinned = store.check_and_pin("peerE", os.urandom(32), x, persist=False)
    assert ok2 is False
    assert pinned == ed.hex()
