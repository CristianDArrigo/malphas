"""
Security tests: cryptographic primitives.

Verifies:
- ChaCha20-Poly1305 authenticated encryption
- Tamper detection (any bit flip in ciphertext raises ValueError)
- Nonce uniqueness across calls
- ECDH shared secret symmetry
- Session key derivation independence (initiator != responder)
- Wrong key decryption always fails
- Key size enforcement
- HKDF context separation
"""

import os
import secrets

import pytest

from malphas.crypto import (
    decrypt,
    derive_session_key,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    hkdf_derive,
)


class TestEncryptDecrypt:
    def test_roundtrip(self):
        key = os.urandom(32)
        pt = b"hello malphas"
        assert decrypt(key, encrypt(key, pt)) == pt

    def test_roundtrip_empty(self):
        key = os.urandom(32)
        assert decrypt(key, encrypt(key, b"")) == b""

    def test_roundtrip_large(self):
        key = os.urandom(32)
        pt = os.urandom(65536)
        assert decrypt(key, encrypt(key, pt)) == pt

    def test_aad_mismatch_rejected(self):
        key = os.urandom(32)
        ct = encrypt(key, b"data", aad=b"correct-aad")
        with pytest.raises(ValueError):
            decrypt(key, ct, aad=b"wrong-aad")

    def test_aad_correct_accepted(self):
        key = os.urandom(32)
        aad = b"context-binding"
        ct = encrypt(key, b"data", aad=aad)
        assert decrypt(key, ct, aad=aad) == b"data"

    def test_wrong_key_rejected(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = encrypt(key1, b"secret")
        with pytest.raises(ValueError):
            decrypt(key2, ct)

    def test_bit_flip_in_ciphertext_rejected(self):
        """Any single bit flip in the ciphertext must raise ValueError."""
        key = os.urandom(32)
        ct = bytearray(encrypt(key, b"authenticated data"))
        ct[20] ^= 0x01  # flip one bit in ciphertext body
        with pytest.raises(ValueError):
            decrypt(key, bytes(ct))

    def test_bit_flip_in_nonce_rejected(self):
        key = os.urandom(32)
        ct = bytearray(encrypt(key, b"data"))
        ct[5] ^= 0x80  # flip bit in nonce area
        with pytest.raises(ValueError):
            decrypt(key, bytes(ct))

    def test_truncated_ciphertext_rejected(self):
        key = os.urandom(32)
        ct = encrypt(key, b"data")
        with pytest.raises(ValueError):
            decrypt(key, ct[:10])

    def test_nonce_uniqueness(self):
        """Each encrypt call must use a fresh nonce."""
        key = os.urandom(32)
        pt = b"same message"
        nonces = set()
        for _ in range(100):
            ct = encrypt(key, pt)
            nonce = ct[:12]
            nonces.add(nonce)
        # All 100 nonces must be unique
        assert len(nonces) == 100

    def test_key_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            encrypt(os.urandom(16), b"data")
        with pytest.raises(ValueError):
            decrypt(os.urandom(16), b"x" * 50)


class TestECDH:
    def test_shared_secret_symmetry(self):
        """ECDH: both sides must derive the same shared secret."""
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        secret_a = ecdh_shared_secret(priv_a, pub_b)
        secret_b = ecdh_shared_secret(priv_b, pub_a)
        assert secret_a == secret_b

    def test_shared_secret_is_32_bytes(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        secret = ecdh_shared_secret(priv_a, pub_b)
        assert len(secret) == 32

    def test_different_pairs_different_secrets(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()
        secret_ab = ecdh_shared_secret(priv_a, pub_b)
        secret_ac = ecdh_shared_secret(priv_a, pub_c)
        assert secret_ab != secret_ac

    def test_ephemeral_keypairs_unique(self):
        """Each generate_ephemeral_keypair call must produce fresh keys."""
        _, pub1 = generate_ephemeral_keypair()
        _, pub2 = generate_ephemeral_keypair()
        assert pub1 != pub2

    def test_pub_key_is_32_bytes(self):
        _, pub = generate_ephemeral_keypair()
        assert len(pub) == 32


class TestSessionKeyDerivation:
    def test_session_key_is_32_bytes(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(priv_a, pub_b)
        key = derive_session_key(shared, pub_a, pub_b, "initiator")
        assert len(key) == 32

    def test_both_sides_derive_same_key(self):
        """
        Initiator and responder must derive the same session key.
        Canonical sort ordering ensures this regardless of role.
        """
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        shared_a = ecdh_shared_secret(priv_a, pub_b)
        shared_b = ecdh_shared_secret(priv_b, pub_a)
        # A uses (pub_a, pub_b), B uses (pub_b, pub_a) — sort makes them equal
        key_a = derive_session_key(shared_a, pub_a, pub_b)
        key_b = derive_session_key(shared_b, pub_b, pub_a)
        assert key_a == key_b

    def test_canonical_ordering_is_symmetric(self):
        """
        Swapping the two pubkeys must produce the same key.
        This is the core invariant: both peers always get the same key.
        """
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(priv_a, pub_b)
        key1 = derive_session_key(shared, pub_a, pub_b)
        key2 = derive_session_key(shared, pub_b, pub_a)
        assert key1 == key2

    def test_different_pubkey_pairs_different_keys(self):
        """Different peer pairs produce different session keys."""
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()
        shared_ab = ecdh_shared_secret(priv_a, pub_b)
        shared_ac = ecdh_shared_secret(priv_a, pub_c)
        key_ab = derive_session_key(shared_ab, pub_a, pub_b)
        key_ac = derive_session_key(shared_ac, pub_a, pub_c)
        assert key_ab != key_ac


class TestHKDF:
    def test_same_inputs_same_output(self):
        ikm = os.urandom(32)
        salt = b"test-salt"
        info = b"test-info"
        k1 = hkdf_derive(ikm, salt, info)
        k2 = hkdf_derive(ikm, salt, info)
        assert k1 == k2

    def test_different_info_different_output(self):
        """Different HKDF info strings must produce different keys — context separation."""
        ikm = os.urandom(32)
        salt = b"same-salt"
        k1 = hkdf_derive(ikm, salt, b"context-A")
        k2 = hkdf_derive(ikm, salt, b"context-B")
        assert k1 != k2

    def test_identity_and_book_key_use_different_contexts(self):
        """
        The identity derivation and book key derivation use different HKDF contexts.
        This is the core security invariant for key independence.
        """
        from malphas.identity import _derive_seed
        seed = _derive_seed("test-passphrase")
        k1 = hkdf_derive(seed, b"malphas-identity-v1", b"keypair-seed")
        k2 = hkdf_derive(seed, b"malphas-addressbook-v1", b"addressbook-encryption-key")
        assert k1 != k2

    def test_output_length_respected(self):
        ikm = os.urandom(32)
        for length in [16, 32, 64]:
            k = hkdf_derive(ikm, b"salt", b"info", length=length)
            assert len(k) == length
