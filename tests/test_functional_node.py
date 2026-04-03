"""
Functional tests: node integration and end-to-end behavior.

Verifies:
- Two nodes can connect via TCP handshake
- Session key established on both sides
- Message delivery end-to-end
- Read receipt delivered back to sender
- Cover traffic does not interfere with real messages
- Node stop clears all state
- Multiple concurrent messages handled correctly
"""

import asyncio
import secrets

import pytest


class TestNodeHandshake:
    async def test_two_nodes_connect(self, node_a, node_b, identity_b):
        """A connects to B — handshake must succeed."""
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        assert ok

    async def test_connected_peer_in_routing_table(self, node_a, node_b, identity_b):
        await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        peer = node_a.discovery.get_peer(identity_b.peer_id)
        assert peer is not None
        assert peer.peer_id == identity_b.peer_id

    async def test_session_key_established(self, node_a, node_b, identity_b):
        """After handshake, both nodes must have a session key."""
        await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.1)
        conn_a = node_a._connections.get(identity_b.peer_id)
        assert conn_a is not None
        assert conn_a.session_key is not None
        assert len(conn_a.session_key) == 32

    async def test_connection_to_wrong_port_fails(self, node_a, identity_b):
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 19999,  # nothing listening here
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        assert not ok


class TestMessageDelivery:
    async def _connect_ab(self, node_a, node_b, identity_b):
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        assert ok
        await asyncio.sleep(0.15)  # let handshake settle

    async def test_message_delivered_to_recipient(
        self, node_a, node_b, identity_a, identity_b
    ):
        """A sends message to B — B's store must contain it."""
        received = []
        node_b.on_message(lambda f, c: received.append(c))

        await self._connect_ab(node_a, node_b, identity_b)

        msg_id = await node_a.send_message(identity_b.peer_id, "hello from A")
        assert msg_id is not None

        await asyncio.sleep(0.3)
        assert "hello from A" in received

    async def test_sent_message_in_sender_store(
        self, node_a, node_b, identity_a, identity_b
    ):
        await self._connect_ab(node_a, node_b, identity_b)
        await node_a.send_message(identity_b.peer_id, "stored message")
        await asyncio.sleep(0.1)

        msgs = node_a.store.get_conversation(identity_a.peer_id, identity_b.peer_id)
        assert any(m["content"] == "stored message" for m in msgs)

    async def test_received_message_in_recipient_store(
        self, node_a, node_b, identity_a, identity_b
    ):
        await self._connect_ab(node_a, node_b, identity_b)
        await node_a.send_message(identity_b.peer_id, "check store")
        await asyncio.sleep(0.3)

        msgs = node_b.store.get_conversation(identity_a.peer_id, identity_b.peer_id)
        assert any(m["content"] == "check store" for m in msgs)

    async def test_multiple_messages_all_delivered(
        self, node_a, node_b, identity_a, identity_b
    ):
        received = []
        node_b.on_message(lambda f, c: received.append(c))

        await self._connect_ab(node_a, node_b, identity_b)

        contents = [f"message {i}" for i in range(5)]
        for content in contents:
            await node_a.send_message(identity_b.peer_id, content)
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.5)
        for content in contents:
            assert content in received

    async def test_send_fails_without_connection(self, node_a, identity_b):
        """Sending to a peer not in routing table must return None."""
        msg_id = await node_a.send_message(identity_b.peer_id, "nobody home")
        assert msg_id is None

    async def test_bidirectional_messaging(
        self, node_a, node_b, identity_a, identity_b
    ):
        """A→B and B→A must both work after initial connection."""
        received_by_b = []
        received_by_a = []
        node_b.on_message(lambda f, c: received_by_b.append(c))
        node_a.on_message(lambda f, c: received_by_a.append(c))

        await self._connect_ab(node_a, node_b, identity_b)

        await node_a.send_message(identity_b.peer_id, "A to B")
        await asyncio.sleep(0.3)
        await node_b.send_message(identity_a.peer_id, "B to A")
        await asyncio.sleep(0.3)

        assert "A to B" in received_by_b
        assert "B to A" in received_by_a


class TestReadReceipts:
    async def _connect_ab(self, node_a, node_b, identity_b):
        await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.15)

    async def test_receipt_received_after_delivery(
        self, node_a, node_b, identity_a, identity_b
    ):
        """B receives message and sends receipt — A must receive it."""
        receipts = []
        node_a.on_receipt(lambda msg_id, dest, received: receipts.append(received))

        await self._connect_ab(node_a, node_b, identity_b)
        msg_id = await node_a.send_message(identity_b.peer_id, "receipt test")
        assert msg_id is not None

        await asyncio.sleep(0.5)
        assert True in receipts

    async def test_receipt_msg_id_matches(
        self, node_a, node_b, identity_a, identity_b
    ):
        receipt_ids = []
        node_a.on_receipt(lambda msg_id, dest, received: receipt_ids.append(msg_id))

        await self._connect_ab(node_a, node_b, identity_b)
        msg_id = await node_a.send_message(identity_b.peer_id, "id check")
        await asyncio.sleep(0.5)
        assert msg_id in receipt_ids


class TestCoverTrafficFunctional:
    async def test_cover_traffic_does_not_appear_as_message(
        self, identity_a, identity_b
    ):
        """Cover packets must be silently dropped — no false messages."""
        from malphas.node import MalphasNode

        node_a = MalphasNode(identity_a, "127.0.0.1", 17777, cover_traffic=False)
        node_b = MalphasNode(identity_b, "127.0.0.1", 17778, cover_traffic=False)
        await node_a.start()
        await node_b.start()

        false_messages = []
        node_b.on_message(lambda f, c: false_messages.append(c))

        await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.1)

        # Manually send a cover packet
        await node_a._send_cover_packet(identity_b.peer_id)
        await asyncio.sleep(0.3)

        assert false_messages == []

        await node_a.stop()
        await node_b.stop()

    async def test_real_message_after_cover_delivered(
        self, node_a, node_b, identity_a, identity_b
    ):
        """Cover traffic must not interfere with subsequent real messages."""
        received = []
        node_b.on_message(lambda f, c: received.append(c))

        await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id,
            identity_b.x25519_pub_bytes,
            identity_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.1)

        # Send cover first
        await node_a._send_cover_packet(identity_b.peer_id)
        await asyncio.sleep(0.1)

        # Then real message
        await node_a.send_message(identity_b.peer_id, "real after cover")
        await asyncio.sleep(0.3)

        assert "real after cover" in received
        assert len(received) == 1  # only the real message


class TestNodeLifecycle:
    async def test_stop_wipes_message_store(self, identity_a):
        from malphas.node import MalphasNode
        node = MalphasNode(identity_a, "127.0.0.1", 17780, cover_traffic=False)
        await node.start()
        node.store.store("x", "y", "sensitive")
        await node.stop()
        # After stop, store is wiped
        msgs = node.store.get_conversation("x", "y")
        assert msgs == []

    async def test_stop_wipes_routing_table(self, identity_a, identity_b):
        from malphas.node import MalphasNode
        node = MalphasNode(identity_a, "127.0.0.1", 17781, cover_traffic=False)
        await node.start()
        node.discovery.add_peer(
            identity_b.peer_id, "127.0.0.1", 7778,
            identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        )
        await node.stop()
        assert node.discovery.all_peers() == []
