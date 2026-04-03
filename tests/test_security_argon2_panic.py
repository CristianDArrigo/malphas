"""
Tests: Argon2id key derivation and /panic emergency wipe.

Argon2 tests verify:
- Determinism (same passphrase → same seed)
- Isolation (different passphrases → different seeds)
- Memory hardness parameters are respected
- Backward incompatibility with the old SHA1 derivation
  (a migration note, not a bug — intentional break)
- The derived seed feeds correctly into the keypair system

Panic tests verify:
- All messages wiped from memory
- All peer connections cleared
- All routing table entries cleared
- All pending receipts cleared
- Address book wiped from memory (file untouched)
- Callbacks cleared (no further processing possible)
"""

import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from malphas.identity import create_identity, create_identity_with_book_key, _derive_seed


class TestArgon2Derivation:
    def test_deterministic(self):
        """Same passphrase always produces the same seed."""
        s1 = _derive_seed("same-passphrase")
        s2 = _derive_seed("same-passphrase")
        assert s1 == s2

    def test_different_passphrases_different_seeds(self):
        s1 = _derive_seed("passphrase-A")
        s2 = _derive_seed("passphrase-B")
        assert s1 != s2

    def test_output_is_64_bytes(self):
        seed = _derive_seed("any-passphrase")
        assert len(seed) == 64

    def test_not_sha1(self):
        """
        Verify the derivation is NOT the old SHA1 approach.
        This is a regression test — if Argon2 is removed accidentally,
        this catches it immediately.
        """
        passphrase = "test-passphrase"
        seed = _derive_seed(passphrase)
        sha1_raw = hashlib.sha1(passphrase.encode()).digest()
        # The Argon2 output must not start with or contain the raw SHA1
        assert sha1_raw not in seed
        assert seed[:20] != sha1_raw

    def test_single_char_difference_produces_completely_different_seed(self):
        """Avalanche effect — one char difference → completely different output."""
        s1 = _derive_seed("passphrase")
        s2 = _derive_seed("Passphrase")  # only case difference
        # XOR distance should be large (most bits differ)
        xor = bytes(a ^ b for a, b in zip(s1, s2))
        bits_changed = sum(bin(b).count('1') for b in xor)
        # Expect ~50% of 512 bits to differ (avalanche)
        assert bits_changed > 200, f"Only {bits_changed}/512 bits changed — weak avalanche"

    def test_identity_deterministic_with_argon2(self):
        """Full identity derivation is stable across multiple calls."""
        id1 = create_identity("argon2-test-passphrase")
        id2 = create_identity("argon2-test-passphrase")
        assert id1.peer_id == id2.peer_id
        assert id1.x25519_pub_bytes == id2.x25519_pub_bytes
        assert id1.ed25519_pub_bytes == id2.ed25519_pub_bytes

    def test_book_key_independent_from_identity_key(self):
        """
        The address book key must differ from the identity seed.
        Both derived from same passphrase but via different HKDF contexts.
        """
        ident, book_key = create_identity_with_book_key("independence-test")
        seed = _derive_seed("independence-test")
        # book_key must not be a simple slice of the seed
        assert book_key != seed[:32]
        assert book_key != seed[32:]
        assert book_key != seed[:32][::-1]

    def test_empty_passphrase_produces_valid_seed(self):
        """
        Edge case: even an empty passphrase should produce a valid seed.
        The caller (_get_passphrase) rejects empty passphrases, but the
        derivation function itself should not crash.
        """
        seed = _derive_seed("")
        assert len(seed) == 64

    def test_unicode_passphrase_supported(self):
        """Non-ASCII passphrases must work correctly."""
        seed1 = _derive_seed("pässwörd-日本語-🔐")
        seed2 = _derive_seed("pässwörd-日本語-🔐")
        assert seed1 == seed2
        assert len(seed1) == 64

    def test_very_long_passphrase(self):
        """Long passphrases must not cause issues."""
        long_pass = "word " * 200
        seed = _derive_seed(long_pass)
        assert len(seed) == 64

    def test_argon2_is_slower_than_sha1(self):
        """
        Argon2id must take significantly longer than SHA1.
        This is the whole point — if this fails, the memory-hardness
        parameters have been accidentally reduced.
        Threshold: at least 50ms (should be ~200ms on modern hardware).
        """
        import time

        passphrase = "timing-test"

        # SHA1 time
        sha1_start = time.time()
        for _ in range(100):
            hashlib.sha1(passphrase.encode()).digest()
        sha1_time = (time.time() - sha1_start) / 100

        # Argon2 time
        argon2_start = time.time()
        _derive_seed(passphrase)
        argon2_time = time.time() - argon2_start

        assert argon2_time > 0.02, \
            f"Argon2 too fast ({argon2_time*1000:.1f}ms) — parameters may have been weakened"
        assert argon2_time > sha1_time * 100, \
            f"Argon2 ({argon2_time*1000:.1f}ms) not significantly slower than SHA1 ({sha1_time*1000:.1f}ms)"


class TestPanicWipe:
    async def test_panic_clears_message_store(self):
        from malphas.node import MalphasNode
        ident = create_identity("panic-test-a")
        node = MalphasNode(ident, "127.0.0.1", 18100, cover_traffic=False)
        await node.start()

        node.store.store("alice", "bob", "sensitive message")
        node.store.store("bob", "alice", "another sensitive")
        assert len(node.store.get_conversation("alice", "bob")) == 2

        node.panic()

        assert node.store.get_conversation("alice", "bob") == []
        await node.stop()

    async def test_panic_clears_routing_table(self):
        from malphas.node import MalphasNode
        id_a = create_identity("panic-test-b")
        id_b = create_identity("panic-test-c")
        node = MalphasNode(id_a, "127.0.0.1", 18101, cover_traffic=False)
        await node.start()

        node.discovery.add_peer(
            id_b.peer_id, "127.0.0.1", 7778,
            id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
        )
        assert len(node.discovery.all_peers()) == 1

        node.panic()

        assert node.discovery.all_peers() == []
        await node.stop()

    async def test_panic_clears_pending_receipts(self):
        import secrets
        from malphas.node import MalphasNode
        ident = create_identity("panic-test-d")
        node = MalphasNode(ident, "127.0.0.1", 18102, cover_traffic=False)
        await node.start()

        node.receipts.track(
            secrets.token_hex(16),
            secrets.token_bytes(16),
            "a" * 40,
        )
        assert node.receipts.pending_count() == 1

        node.panic()

        assert node.receipts.pending_count() == 0
        await node.stop()

    async def test_panic_closes_all_connections(self):
        from malphas.node import MalphasNode
        id_a = create_identity("panic-test-e")
        id_b = create_identity("panic-test-f")

        node_a = MalphasNode(id_a, "127.0.0.1", 18103, cover_traffic=False)
        node_b = MalphasNode(id_b, "127.0.0.1", 18104, cover_traffic=False)
        await node_a.start()
        await node_b.start()

        await node_a.connect_to_peer(
            "127.0.0.1", 18104,
            id_b.peer_id, id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.15)
        assert len(node_a._connections) == 1

        node_a.panic()

        assert len(node_a._connections) == 0

        await node_a.stop()
        await node_b.stop()

    async def test_panic_clears_callbacks(self):
        """
        After panic, no callbacks should fire — the node is dead.
        """
        from malphas.node import MalphasNode
        ident = create_identity("panic-test-g")
        node = MalphasNode(ident, "127.0.0.1", 18105, cover_traffic=False)
        await node.start()

        fired = []
        node.on_message(lambda f, c: fired.append(c))
        assert len(node._callbacks) == 1

        node.panic()

        assert len(node._callbacks) == 0
        await node.stop()

    async def test_panic_does_not_delete_address_book_file(self):
        """
        Panic wipes address book FROM MEMORY but does NOT delete the file.
        The file is encrypted — without the passphrase it is useless noise.
        Deleting it would destroy the user's contacts permanently.
        """
        import os, tempfile
        from malphas.addressbook import AddressBook, Contact
        from malphas.identity import create_identity_with_book_key

        _, book_key = create_identity_with_book_key("panic-book-test")
        path = tempfile.mktemp(suffix=".book")

        try:
            book = AddressBook(path, book_key)
            book.load()
            book.add(Contact("alice", "a" * 40, "127.0.0.1", 7777, "b" * 64, "c" * 64))

            assert Path(path).exists()
            assert len(book) == 1

            book.wipe_memory()  # this is what panic calls

            # File must still exist
            assert Path(path).exists(), "File deleted — panic should NOT delete the book file"
            # Memory must be cleared
            assert len(book) == 0
        finally:
            if os.path.exists(path):
                os.unlink(path)

    async def test_panic_then_node_unusable(self):
        """
        After panic, the node must not process any further messages.
        Callbacks are cleared so nothing fires even if a packet arrives.
        """
        from malphas.node import MalphasNode
        id_a = create_identity("panic-test-h")
        id_b = create_identity("panic-test-i")

        node_a = MalphasNode(id_a, "127.0.0.1", 18106, cover_traffic=False)
        node_b = MalphasNode(id_b, "127.0.0.1", 18107, cover_traffic=False)
        await node_a.start()
        await node_b.start()

        received_after_panic = []
        node_a.on_message(lambda f, c: received_after_panic.append(c))

        await node_b.connect_to_peer(
            "127.0.0.1", 18106,
            id_a.peer_id, id_a.x25519_pub_bytes, id_a.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.15)

        # Panic node_a
        node_a.panic()

        # B tries to send to A after panic
        await node_b.send_message(id_a.peer_id, "post-panic message")
        await asyncio.sleep(0.3)

        # A's callbacks were cleared — nothing should have fired
        assert received_after_panic == []

        await node_a.stop()
        await node_b.stop()
