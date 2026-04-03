"""
Functional tests: peer discovery, routing table, message store.

Verifies correct operational behavior of non-crypto components.
"""

import time
import secrets

import pytest

from malphas.discovery import PeerDiscovery, PeerInfo, RoutingTable, xor_distance
from malphas.memory import MessageStore


class TestXORDistance:
    def test_distance_to_self_is_zero(self, identity_a):
        assert xor_distance(identity_a.peer_id, identity_a.peer_id) == 0

    def test_distance_is_symmetric(self, identity_a, identity_b):
        d1 = xor_distance(identity_a.peer_id, identity_b.peer_id)
        d2 = xor_distance(identity_b.peer_id, identity_a.peer_id)
        assert d1 == d2

    def test_different_peers_nonzero_distance(self, identity_a, identity_b):
        assert xor_distance(identity_a.peer_id, identity_b.peer_id) > 0


class TestRoutingTable:
    def test_add_peer(self, identity_a, identity_b):
        rt = RoutingTable(identity_a.peer_id)
        peer = PeerInfo(identity_b.peer_id, "127.0.0.1", 7778,
                        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        rt.add(peer)
        assert rt.size() == 1
        assert rt.get(identity_b.peer_id) is not None

    def test_self_not_added(self, identity_a):
        rt = RoutingTable(identity_a.peer_id)
        self_peer = PeerInfo(identity_a.peer_id, "127.0.0.1", 7777,
                             identity_a.x25519_pub_bytes, identity_a.ed25519_pub_bytes)
        rt.add(self_peer)
        assert rt.size() == 0

    def test_duplicate_peer_updates_info(self, identity_a, identity_b):
        rt = RoutingTable(identity_a.peer_id)
        peer = PeerInfo(identity_b.peer_id, "10.0.0.1", 7778,
                        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        rt.add(peer)
        # Update with new host
        peer2 = PeerInfo(identity_b.peer_id, "10.0.0.99", 7999,
                         identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        rt.add(peer2)
        assert rt.size() == 1
        assert rt.get(identity_b.peer_id).host == "10.0.0.99"
        assert rt.get(identity_b.peer_id).port == 7999

    def test_remove_peer(self, identity_a, identity_b):
        rt = RoutingTable(identity_a.peer_id)
        peer = PeerInfo(identity_b.peer_id, "127.0.0.1", 7778,
                        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        rt.add(peer)
        rt.remove(identity_b.peer_id)
        assert rt.size() == 0
        assert rt.get(identity_b.peer_id) is None

    def test_closest_returns_sorted_by_distance(self, identity_a, identity_b, identity_c):
        rt = RoutingTable(identity_a.peer_id)
        for ident in [identity_b, identity_c]:
            rt.add(PeerInfo(ident.peer_id, "127.0.0.1", 7778,
                            ident.x25519_pub_bytes, ident.ed25519_pub_bytes))

        closest = rt.closest(identity_a.peer_id, k=2)
        assert len(closest) == 2
        d1 = xor_distance(closest[0].peer_id, identity_a.peer_id)
        d2 = xor_distance(closest[1].peer_id, identity_a.peer_id)
        assert d1 <= d2

    def test_purge_stale_removes_old_peers(self, identity_a, identity_b):
        rt = RoutingTable(identity_a.peer_id)
        peer = PeerInfo(identity_b.peer_id, "127.0.0.1", 7778,
                        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        peer.last_seen = time.time() - 999  # artificially stale
        rt.add(peer)
        removed = rt.purge_stale(timeout=100.0)
        assert removed == 1
        assert rt.size() == 0

    def test_purge_leaves_fresh_peers(self, identity_a, identity_b):
        rt = RoutingTable(identity_a.peer_id)
        peer = PeerInfo(identity_b.peer_id, "127.0.0.1", 7778,
                        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        rt.add(peer)  # last_seen = now
        removed = rt.purge_stale(timeout=300.0)
        assert removed == 0
        assert rt.size() == 1


class TestPeerDiscovery:
    def test_add_and_get_peer(self, identity_a, identity_b):
        disc = PeerDiscovery(identity_a.peer_id)
        disc.add_peer(identity_b.peer_id, "127.0.0.1", 7778,
                      identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        peer = disc.get_peer(identity_b.peer_id)
        assert peer is not None
        assert peer.peer_id == identity_b.peer_id

    def test_circuit_selection_includes_destination(self, identity_a, identity_b, identity_c):
        disc = PeerDiscovery(identity_a.peer_id)
        for ident in [identity_b, identity_c]:
            disc.add_peer(ident.peer_id, "127.0.0.1", 7778,
                          ident.x25519_pub_bytes, ident.ed25519_pub_bytes)

        circuit = disc.select_relay_circuit(identity_c.peer_id, hops=2)
        # Last hop must be the destination
        assert circuit[-1][1] == identity_c.peer_id

    def test_circuit_excludes_self(self, identity_a, identity_b, identity_c):
        disc = PeerDiscovery(identity_a.peer_id)
        for ident in [identity_b, identity_c]:
            disc.add_peer(ident.peer_id, "127.0.0.1", 7778,
                          ident.x25519_pub_bytes, ident.ed25519_pub_bytes)
        circuit = disc.select_relay_circuit(identity_c.peer_id, hops=3)
        peer_ids_in_circuit = [p[1] for p in circuit]
        assert identity_a.peer_id not in peer_ids_in_circuit

    def test_circuit_excludes_destination_from_relays(self, identity_a, identity_b, identity_c):
        disc = PeerDiscovery(identity_a.peer_id)
        for ident in [identity_b, identity_c]:
            disc.add_peer(ident.peer_id, "127.0.0.1", 7778,
                          ident.x25519_pub_bytes, ident.ed25519_pub_bytes)
        circuit = disc.select_relay_circuit(identity_c.peer_id, hops=3)
        relay_ids = [p[1] for p in circuit[:-1]]
        assert identity_c.peer_id not in relay_ids

    def test_circuit_degrades_with_few_peers(self, identity_a, identity_b):
        """With only 1 peer available, circuit degrades to 1 hop (direct)."""
        disc = PeerDiscovery(identity_a.peer_id)
        disc.add_peer(identity_b.peer_id, "127.0.0.1", 7778,
                      identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        circuit = disc.select_relay_circuit(identity_b.peer_id, hops=3)
        assert len(circuit) == 1  # only destination
        assert circuit[0][1] == identity_b.peer_id

    def test_unknown_destination_raises(self, identity_a, identity_b):
        disc = PeerDiscovery(identity_a.peer_id)
        with pytest.raises(ValueError):
            disc.select_relay_circuit(identity_b.peer_id)

    def test_wipe_clears_all_peers(self, identity_a, identity_b):
        disc = PeerDiscovery(identity_a.peer_id)
        disc.add_peer(identity_b.peer_id, "127.0.0.1", 7778,
                      identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes)
        disc.wipe()
        assert disc.all_peers() == []


class TestMessageStore:
    def test_store_and_retrieve(self):
        store = MessageStore()
        store.store("alice", "bob", "hello")
        msgs = store.get_conversation("alice", "bob")
        assert len(msgs) == 1
        assert msgs[0]["content"] == "hello"

    def test_conversation_is_bidirectional(self):
        """Same conversation regardless of who queries."""
        store = MessageStore()
        store.store("alice", "bob", "from alice")
        store.store("bob", "alice", "from bob")
        msgs_ab = store.get_conversation("alice", "bob")
        msgs_ba = store.get_conversation("bob", "alice")
        assert len(msgs_ab) == 2
        assert msgs_ab == msgs_ba

    def test_conversations_are_isolated(self):
        """Messages between A↔B must not appear in A↔C conversation."""
        store = MessageStore()
        store.store("alice", "bob", "secret to bob")
        store.store("alice", "charlie", "different to charlie")
        msgs_ac = store.get_conversation("alice", "charlie")
        contents = [m["content"] for m in msgs_ac]
        assert "secret to bob" not in contents

    def test_expired_messages_not_returned(self):
        store = MessageStore(ttl_seconds=0)
        store.store("alice", "bob", "ephemeral")
        time.sleep(0.01)
        msgs = store.get_conversation("alice", "bob")
        assert msgs == []

    def test_purge_removes_expired(self):
        store = MessageStore(ttl_seconds=0)
        store.store("alice", "bob", "expired")
        time.sleep(0.01)
        removed = store.purge_expired()
        assert removed == 1

    def test_max_messages_enforced(self):
        store = MessageStore(max_messages=5)
        for i in range(10):
            store.store("alice", "bob", f"msg {i}")
        msgs = store.get_conversation("alice", "bob")
        assert len(msgs) <= 5

    def test_messages_ordered_oldest_first(self):
        store = MessageStore()
        for content in ["first", "second", "third"]:
            store.store("alice", "bob", content)
            time.sleep(0.001)
        msgs = store.get_conversation("alice", "bob")
        contents = [m["content"] for m in msgs]
        assert contents == ["first", "second", "third"]

    def test_wipe_removes_all_conversations(self):
        store = MessageStore()
        store.store("alice", "bob", "hello")
        store.store("alice", "charlie", "world")
        store.wipe()
        assert store.get_conversation("alice", "bob") == []
        assert store.get_conversation("alice", "charlie") == []

    def test_from_peer_field_correct(self):
        store = MessageStore()
        store.store("alice", "bob", "from alice")
        msgs = store.get_conversation("alice", "bob")
        assert msgs[0]["from_peer"] == "alice"
        assert msgs[0]["to_peer"] == "bob"

    def test_timestamp_is_recent(self):
        store = MessageStore()
        before = time.time()
        store.store("alice", "bob", "timed message")
        after = time.time()
        msgs = store.get_conversation("alice", "bob")
        assert before <= msgs[0]["timestamp"] <= after
