"""
End-to-end integration tests.
Verify actual message delivery between real nodes on loopback TCP.
These tests catch bugs invisible to unit tests (wire format, onion stripping,
session key usage, delivery pipeline).
"""

import asyncio
import pytest

from malphas.identity import create_identity
from malphas.node import MalphasNode


# ── Helpers ───────────────────────────────────────────────────────────────────

async def connect(a: MalphasNode, b: MalphasNode, id_b) -> bool:
    ok = await a.connect_to_peer(
        "127.0.0.1", b.port,
        id_b.peer_id,
        id_b.x25519_pub_bytes,
        id_b.ed25519_pub_bytes,
    )
    await asyncio.sleep(0.15)
    return ok


async def collect(node, timeout=0.6):
    """Collect all messages received by node within timeout."""
    msgs = []
    node.on_message(lambda f, c: msgs.append((f, c)))
    await asyncio.sleep(timeout)
    return msgs


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
async def pair():
    """Two connected nodes, A→B."""
    id_a = create_identity("e2e-alice")
    id_b = create_identity("e2e-bob")
    a = MalphasNode(id_a, "127.0.0.1", 18001, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18002, cover_traffic=False)
    await a.start()
    await b.start()
    assert await connect(a, b, id_b)
    yield a, b, id_a, id_b
    await a.stop()
    await b.stop()


@pytest.fixture
async def trio():
    """Three nodes: A connected to B, B connected to C."""
    id_a = create_identity("e2e-alice-3")
    id_b = create_identity("e2e-bob-3")
    id_c = create_identity("e2e-charlie-3")
    a = MalphasNode(id_a, "127.0.0.1", 18003, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18004, cover_traffic=False)
    c = MalphasNode(id_c, "127.0.0.1", 18005, cover_traffic=False)
    await a.start()
    await b.start()
    await c.start()
    assert await connect(a, b, id_b)
    assert await connect(b, c, id_c)
    # A also knows C via B's routing table (manual add for circuit)
    a.discovery.add_peer(id_c.peer_id, "127.0.0.1", 18005,
                         id_c.x25519_pub_bytes, id_c.ed25519_pub_bytes)
    yield a, b, c, id_a, id_b, id_c
    await a.stop()
    await b.stop()
    await c.stop()


# ── Direct delivery (1 hop) ───────────────────────────────────────────────────

class TestDirectDelivery:
    async def test_message_arrives_at_destination(self, pair):
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        msg_id = await a.send_message(id_b.peer_id, "hello world")
        assert msg_id is not None, "send_message returned None — peer not reachable"

        await asyncio.sleep(0.5)
        assert "hello world" in received, f"Message not received. Got: {received}"

    async def test_message_from_peer_id_correct(self, pair):
        a, b, id_a, id_b = pair
        froms = []
        b.on_message(lambda f, c: froms.append(f))

        await a.send_message(id_b.peer_id, "check sender")
        await asyncio.sleep(0.5)

        assert id_a.peer_id in froms

    async def test_sender_store_populated(self, pair):
        a, b, id_a, id_b = pair
        await a.send_message(id_b.peer_id, "store test")
        await asyncio.sleep(0.2)

        msgs = a.store.get_conversation(id_a.peer_id, id_b.peer_id)
        assert any(m["content"] == "store test" for m in msgs)

    async def test_recipient_store_populated(self, pair):
        a, b, id_a, id_b = pair
        await a.send_message(id_b.peer_id, "store at b")
        await asyncio.sleep(0.5)

        msgs = b.store.get_conversation(id_a.peer_id, id_b.peer_id)
        assert any(m["content"] == "store at b" for m in msgs)

    async def test_multiple_messages_all_arrive(self, pair):
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        for i in range(5):
            await a.send_message(id_b.peer_id, f"msg-{i}")
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.8)
        for i in range(5):
            assert f"msg-{i}" in received, f"msg-{i} not received. Got: {received}"

    async def test_bidirectional_delivery(self, pair):
        a, b, id_a, id_b = pair
        recv_b, recv_a = [], []
        b.on_message(lambda f, c: recv_b.append(c))
        a.on_message(lambda f, c: recv_a.append(c))

        await a.send_message(id_b.peer_id, "a→b")
        await asyncio.sleep(0.4)
        await b.send_message(id_a.peer_id, "b→a")
        await asyncio.sleep(0.4)

        assert "a→b" in recv_b, f"a→b not received by b. Got: {recv_b}"
        assert "b→a" in recv_a, f"b→a not received by a. Got: {recv_a}"

    async def test_large_message_delivered(self, pair):
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        large = "x" * 3000  # spans multiple padding blocks
        await a.send_message(id_b.peer_id, large)
        await asyncio.sleep(0.5)
        assert large in received

    async def test_unicode_message_delivered(self, pair):
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        msg = "ciao 🔒 — φάντομ — 幻影"
        await a.send_message(id_b.peer_id, msg)
        await asyncio.sleep(0.5)
        assert msg in received


# ── Read receipts ─────────────────────────────────────────────────────────────

class TestReadReceiptsE2E:
    async def test_receipt_arrives_after_delivery(self, pair):
        a, b, id_a, id_b = pair
        receipts = []
        a.on_receipt(lambda msg_id, dest, ok: receipts.append(ok))

        msg_id = await a.send_message(id_b.peer_id, "receipt check")
        assert msg_id is not None
        await asyncio.sleep(0.8)

        assert True in receipts, f"No positive receipt received. Got: {receipts}"

    async def test_receipt_msg_id_matches_sent(self, pair):
        a, b, id_a, id_b = pair
        receipt_ids = []
        a.on_receipt(lambda msg_id, dest, ok: receipt_ids.append((msg_id, ok)))

        msg_id = await a.send_message(id_b.peer_id, "id match test")
        await asyncio.sleep(0.8)

        matching = [(mid, ok) for mid, ok in receipt_ids if mid == msg_id]
        assert matching, f"No receipt for msg_id {msg_id}. Got: {receipt_ids}"
        assert matching[0][1] is True

    async def test_no_false_receipt_without_delivery(self, pair):
        """
        If we send to a peer not in routing table (unreachable),
        send_message returns None and no receipt should fire.
        """
        a, b, id_a, id_b = pair
        receipts = []
        a.on_receipt(lambda msg_id, dest, ok: receipts.append(ok))

        result = await a.send_message("a" * 40, "nobody home")
        assert result is None  # not sent
        await asyncio.sleep(0.5)
        assert receipts == []


# ── Cover traffic ─────────────────────────────────────────────────────────────

class TestCoverTrafficE2E:
    async def test_cover_not_delivered_as_message(self, pair):
        a, b, id_a, id_b = pair
        false_msgs = []
        b.on_message(lambda f, c: false_msgs.append(c))

        # Send 5 cover packets
        for _ in range(5):
            await a._send_cover_packet(id_b.peer_id)
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.3)
        assert false_msgs == [], f"Cover produced false messages: {false_msgs}"

    async def test_real_message_after_cover_arrives(self, pair):
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        # Send cover then real
        await a._send_cover_packet(id_b.peer_id)
        await asyncio.sleep(0.1)
        await a.send_message(id_b.peer_id, "real after cover")
        await asyncio.sleep(0.5)

        assert "real after cover" in received
        assert len(received) == 1


# ── Relay / multi-hop ─────────────────────────────────────────────────────────

class TestRelayE2E:
    async def test_message_through_relay(self, trio):
        """A sends to C through B as relay."""
        a, b, c, id_a, id_b, id_c = trio
        received = []
        c.on_message(lambda f, content: received.append(content))

        # A knows B and C; select_relay_circuit should pick B as relay for A→C
        msg_id = await a.send_message(id_c.peer_id, "through relay")
        assert msg_id is not None, "send_message returned None"

        await asyncio.sleep(0.8)
        assert "through relay" in received, f"Not received at C. Got: {received}"

    async def test_relay_does_not_receive_plaintext(self, trio):
        """B relays the message but must not see the plaintext content."""
        a, b, c, id_a, id_b, id_c = trio
        b_received = []
        b.on_message(lambda f, content: b_received.append(content))

        await a.send_message(id_c.peer_id, "secret for charlie")
        await asyncio.sleep(0.8)

        # B should not have received the plaintext
        assert "secret for charlie" not in b_received, \
            "Relay B received plaintext it should not have seen"

    async def test_relay_receipt_through_hop(self, trio):
        """Receipt from C routes back to A through B."""
        a, b, c, id_a, id_b, id_c = trio
        # C also needs to know how to route back to A
        c.discovery.add_peer(id_a.peer_id, "127.0.0.1", 18003,
                              id_a.x25519_pub_bytes, id_a.ed25519_pub_bytes)

        receipts = []
        a.on_receipt(lambda msg_id, dest, ok: receipts.append(ok))

        await a.send_message(id_c.peer_id, "receipt via relay")
        await asyncio.sleep(1.2)

        assert True in receipts, f"No receipt received. Got: {receipts}"


# ── Crypto integrity on wire ──────────────────────────────────────────────────

class TestWireCryptoIntegrity:
    async def test_tampered_packet_silently_dropped(self, pair):
        """
        If we intercept and tamper with a packet, it must be silently dropped
        — not delivered as garbage and not crashing the node.
        """
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        # Send a real message first to confirm delivery works
        await a.send_message(id_b.peer_id, "before tamper")
        await asyncio.sleep(0.5)
        assert "before tamper" in received

        # Now simulate a tampered packet by sending raw garbage as MSG_ONION
        conn = a._connections.get(id_b.peer_id)
        if conn and conn.session_key:
            from malphas.crypto import encrypt
            garbage = encrypt(conn.session_key, b"\xff" * 64)
            await conn.send(3, garbage)  # MSG_ONION = 0x03
            await asyncio.sleep(0.3)

        # Node B must still be alive and not have delivered garbage
        assert all(m in ["before tamper"] for m in received), \
            f"Garbage delivered: {received}"

        # Confirm B still works after receiving tampered packet
        await a.send_message(id_b.peer_id, "after tamper")
        await asyncio.sleep(0.5)
        assert "after tamper" in received

    async def test_two_nodes_derive_same_session_key(self, pair):
        """
        A and B must derive the same session key — tested implicitly
        by successful message delivery, but verified explicitly here.
        """
        a, b, id_a, id_b = pair
        conn_a = a._connections.get(id_b.peer_id)
        conn_b = b._connections.get(id_a.peer_id)

        assert conn_a is not None and conn_b is not None
        # Both session keys must be the same 32-byte value
        assert conn_a.session_key == conn_b.session_key
        assert len(conn_a.session_key) == 32
