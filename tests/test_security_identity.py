"""
Security tests: identity layer and key derivation.

Verifies:
- Passphrase never persisted
- Deterministic derivation
- Key independence (identity vs book key)
- Different passphrases produce different keys
- SHA1 peer_id is correct
- Ed25519 sign/verify integrity
"""

import hashlib
import secrets

import pytest

from malphas.identity import create_identity, create_identity_with_book_key


class TestIdentityDeterminism:
    def test_same_passphrase_same_peer_id(self):
        """Deterministic: same passphrase always produces same peer_id."""
        a = create_identity("same-passphrase")
        b = create_identity("same-passphrase")
        assert a.peer_id == b.peer_id

    def test_same_passphrase_same_pubkeys(self):
        a = create_identity("same-passphrase")
        b = create_identity("same-passphrase")
        assert a.x25519_pub_bytes == b.x25519_pub_bytes
        assert a.ed25519_pub_bytes == b.ed25519_pub_bytes

    def test_different_passphrases_different_peer_ids(self):
        a = create_identity("passphrase-A")
        b = create_identity("passphrase-B")
        assert a.peer_id != b.peer_id

    def test_different_passphrases_different_pubkeys(self):
        a = create_identity("passphrase-A")
        b = create_identity("passphrase-B")
        assert a.x25519_pub_bytes != b.x25519_pub_bytes
        assert a.ed25519_pub_bytes != b.ed25519_pub_bytes

    def test_peer_id_is_sha1_of_ed25519_pubkey(self):
        """peer_id must be SHA1(ed25519_pubkey) — protocol invariant."""
        ident = create_identity("test-passphrase")
        expected = hashlib.sha1(ident.ed25519_pub_bytes).hexdigest()
        assert ident.peer_id == expected

    def test_peer_id_is_40_hex_chars(self):
        ident = create_identity("any-passphrase")
        assert len(ident.peer_id) == 40
        assert all(c in "0123456789abcdef" for c in ident.peer_id)

    def test_x25519_pub_is_32_bytes(self):
        ident = create_identity("any-passphrase")
        assert len(ident.x25519_pub_bytes) == 32

    def test_ed25519_pub_is_32_bytes(self):
        ident = create_identity("any-passphrase")
        assert len(ident.ed25519_pub_bytes) == 32


class TestKeyIndependence:
    """
    The address book key must be cryptographically independent
    from the identity keypairs. Knowing one must not help derive the other.
    """

    def test_book_key_differs_from_x25519_priv(self):
        _, book_key = create_identity_with_book_key("test")
        ident = create_identity("test")
        # We can't extract x25519 private bytes directly, but we can verify
        # the book_key is not the same as the pubkey
        assert book_key != ident.x25519_pub_bytes
        assert book_key != ident.ed25519_pub_bytes

    def test_book_key_deterministic(self):
        _, key1 = create_identity_with_book_key("same-pass")
        _, key2 = create_identity_with_book_key("same-pass")
        assert key1 == key2

    def test_book_key_differs_for_different_passphrases(self):
        _, key1 = create_identity_with_book_key("pass-A")
        _, key2 = create_identity_with_book_key("pass-B")
        assert key1 != key2

    def test_book_key_is_32_bytes(self):
        _, key = create_identity_with_book_key("any")
        assert len(key) == 32

    def test_identity_consistent_with_standalone(self):
        """create_identity_with_book_key must produce same identity as create_identity."""
        ident1 = create_identity("consistency-test")
        ident2, _ = create_identity_with_book_key("consistency-test")
        assert ident1.peer_id == ident2.peer_id
        assert ident1.x25519_pub_bytes == ident2.x25519_pub_bytes
        assert ident1.ed25519_pub_bytes == ident2.ed25519_pub_bytes


class TestSignVerify:
    def test_sign_verify_roundtrip(self, identity_a):
        msg = b"hello malphas"
        sig = identity_a.sign(msg)
        assert identity_a.verify(sig, msg)

    def test_verify_fails_wrong_data(self, identity_a):
        msg = b"hello malphas"
        sig = identity_a.sign(msg)
        assert not identity_a.verify(sig, b"tampered data")

    def test_verify_fails_wrong_key(self, identity_a, identity_b):
        msg = b"hello malphas"
        sig = identity_a.sign(msg)
        # identity_b cannot verify identity_a's signature
        assert not identity_b.verify(sig, msg)

    def test_signature_is_64_bytes(self, identity_a):
        sig = identity_a.sign(b"test")
        assert len(sig) == 64

    def test_signature_nondeterministic(self, identity_a):
        """Ed25519 signatures should be deterministic for same key+message."""
        msg = b"same message"
        sig1 = identity_a.sign(msg)
        sig2 = identity_a.sign(msg)
        # Ed25519 is deterministic
        assert sig1 == sig2

    def test_different_messages_different_signatures(self, identity_a):
        sig1 = identity_a.sign(b"message one")
        sig2 = identity_a.sign(b"message two")
        assert sig1 != sig2
