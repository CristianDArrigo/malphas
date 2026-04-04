"""
Tests for key pinning (TOFU) — pinstore.py.

Verifies:
- First contact pins the key
- Same key accepted on subsequent contacts
- Different key rejected (pin violation)
- /trust resets pin
- Persistence: save and load from encrypted file
- Wipe clears all pins
- Pin store works in handshake integration
"""

import os
import tempfile

import pytest

from malphas.identity import create_identity, create_identity_with_book_key
from malphas.pinstore import PinStore
from malphas.crypto import hkdf_derive


class TestPinBasic:
    def test_first_contact_pins(self, identity_a):
        ps = PinStore()
        ok, pinned = ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        assert ok is True
        assert pinned is None

    def test_same_key_accepted(self, identity_a):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        ok, pinned = ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        assert ok is True
        assert pinned is None

    def test_different_key_rejected(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        # Same peer_id but different key
        ok, pinned = ps.check_and_pin(identity_a.peer_id, identity_b.ed25519_pub_bytes)
        assert ok is False
        assert pinned == identity_a.ed25519_pub_bytes.hex()

    def test_different_peers_independent(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        ok, _ = ps.check_and_pin(identity_b.peer_id, identity_b.ed25519_pub_bytes)
        assert ok is True

    def test_get_pin(self, identity_a):
        ps = PinStore()
        assert ps.get_pin(identity_a.peer_id) is None
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        assert ps.get_pin(identity_a.peer_id) == identity_a.ed25519_pub_bytes.hex()

    def test_all_pins(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        ps.check_and_pin(identity_b.peer_id, identity_b.ed25519_pub_bytes)
        pins = ps.all_pins()
        assert len(pins) == 2
        assert identity_a.peer_id in pins
        assert identity_b.peer_id in pins


class TestPinTrust:
    def test_trust_resets_pin(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        # Reset pin
        ps.trust(identity_a.peer_id)
        # Now a different key should be accepted (re-pinned)
        ok, _ = ps.check_and_pin(identity_a.peer_id, identity_b.ed25519_pub_bytes)
        assert ok is True
        assert ps.get_pin(identity_a.peer_id) == identity_b.ed25519_pub_bytes.hex()

    def test_trust_with_specific_key(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        # Trust with B's key explicitly
        ps.trust(identity_a.peer_id, identity_b.ed25519_pub_bytes)
        assert ps.get_pin(identity_a.peer_id) == identity_b.ed25519_pub_bytes.hex()

    def test_trust_unknown_peer(self):
        ps = PinStore()
        ps.trust("a" * 40)  # should not crash
        assert ps.get_pin("a" * 40) is None


class TestPinWipe:
    def test_wipe_clears_all(self, identity_a, identity_b):
        ps = PinStore()
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        ps.check_and_pin(identity_b.peer_id, identity_b.ed25519_pub_bytes)
        ps.wipe()
        assert ps.all_pins() == {}
        assert ps.get_pin(identity_a.peer_id) is None


class TestPinPersistence:
    def test_save_and_load(self, identity_a):
        _, key = create_identity_with_book_key("pin-test")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pins") as f:
            path = f.name
        os.unlink(path)

        try:
            ps1 = PinStore(path, key)
            ps1.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)

            ps2 = PinStore(path, key)
            loaded = ps2.load()
            assert loaded is True
            assert ps2.get_pin(identity_a.peer_id) == identity_a.ed25519_pub_bytes.hex()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_wrong_key_fails_gracefully(self, identity_a):
        _, key1 = create_identity_with_book_key("pin-key-1")
        _, key2 = create_identity_with_book_key("pin-key-2")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pins") as f:
            path = f.name
        os.unlink(path)

        try:
            ps1 = PinStore(path, key1)
            ps1.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)

            ps2 = PinStore(path, key2)
            loaded = ps2.load()
            assert loaded is False  # wrong key — starts fresh
            assert ps2.all_pins() == {}
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_no_file_returns_false(self):
        ps = PinStore("/tmp/nonexistent_pin_file_12345", os.urandom(32))
        assert ps.load() is False

    def test_no_path_no_crash(self, identity_a):
        ps = PinStore()  # no path, no key
        ps.check_and_pin(identity_a.peer_id, identity_a.ed25519_pub_bytes)
        # _save should not crash
        assert ps.get_pin(identity_a.peer_id) is not None


class TestPinHandshakeIntegration:
    async def test_handshake_pins_on_first_connect(self, node_a, node_b, identity_b):
        ok = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id, identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        )
        assert ok
        assert node_a.pins.get_pin(identity_b.peer_id) == identity_b.ed25519_pub_bytes.hex()

    async def test_handshake_accepts_same_key(self, node_a, node_b, identity_b):
        """Connect twice — second handshake should succeed (same key)."""
        ok1 = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id, identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        )
        assert ok1

        # Disconnect
        conn = node_a._connections.pop(identity_b.peer_id, None)
        if conn:
            conn.close()
        import asyncio
        await asyncio.sleep(0.2)

        # Reconnect — same key, should be accepted
        ok2 = await node_a.connect_to_peer(
            "127.0.0.1", 17778,
            identity_b.peer_id, identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        )
        assert ok2

    async def test_panic_wipes_pins(self, node_a, identity_b):
        node_a.pins.check_and_pin(identity_b.peer_id, identity_b.ed25519_pub_bytes)
        assert node_a.pins.get_pin(identity_b.peer_id) is not None
        node_a.panic()
        assert node_a.pins.get_pin(identity_b.peer_id) is None
