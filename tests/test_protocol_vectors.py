"""
Protocol test vectors (PROTOCOL.md §14).

These pin the wire format against silent drift across refactors.
Each vector is one of two flavours:

  Deterministic
    Inputs → exact expected bytes. If you change the algorithm
    these break. If you change the *spec* these need to be
    updated in lockstep.

  Round-trip / invariant
    Where the encoding involves randomness (ephemeral keys,
    nonces), we verify that {encode → decode} round-trips and
    that the encoded form satisfies documented format invariants
    (length, prefix, base64 validity, ...). The reviewer's
    promise is "if you encrypt the same plaintext twice you'll
    get different ciphertexts but they'll both decrypt to the
    same plaintext".

If you find an external KAT (known-answer test) you'd like added
here — for instance a fixed-seed identity derivation vector you
want to share with another implementer — drop it in. This file
is the contract surface for §1.0.0 ↔ external review.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from malphas.crypto import (
    decrypt,
    derive_hmac_key,
    derive_session_key,
    ecdh_shared_secret,
    encrypt,
    hkdf_derive,
    hmac_sign,
    hmac_verify,
)
from malphas.identity import create_identity
from malphas.mnemonic import mnemonic_to_salt, salt_to_mnemonic
from malphas.onion import (
    FINAL_HOP_MARKER,
    peel_layer,
    peer_id_from_bytes,
    peer_id_to_bytes,
    wrap_onion,
)
from malphas.sealed_sender import seal, unseal

# ── §3 · Identity derivation (deterministic) ────────────────────────────────


def test_identity_is_deterministic_from_passphrase_alone():
    """The default-salt path. Same passphrase + same library
    version → exact same peer_id, x25519_pub, ed25519_pub."""
    a = create_identity("malphas-vector-passphrase-1")
    b = create_identity("malphas-vector-passphrase-1")
    assert a.peer_id == b.peer_id
    assert a.x25519_pub_bytes == b.x25519_pub_bytes
    assert a.ed25519_pub_bytes == b.ed25519_pub_bytes


def test_identity_changes_with_passphrase():
    a = create_identity("malphas-vector-passphrase-1")
    b = create_identity("malphas-vector-passphrase-2")
    assert a.peer_id != b.peer_id


def test_peer_id_is_40_hex_chars():
    """PROTOCOL.md §3: BLAKE2s(ed25519_pub, digest_size=20) hex →
    exactly 40 lowercase hex characters."""
    ident = create_identity("vec-peer-id-shape")
    assert len(ident.peer_id) == 40
    assert all(c in "0123456789abcdef" for c in ident.peer_id)


def test_x25519_pub_is_32_bytes():
    ident = create_identity("vec-x25519-shape")
    assert len(ident.x25519_pub_bytes) == 32


def test_ed25519_pub_is_32_bytes():
    ident = create_identity("vec-ed25519-shape")
    assert len(ident.ed25519_pub_bytes) == 32


# ── §12 · BIP39 mnemonic (deterministic) ────────────────────────────────────


# Two pinned salts and their expected 12-word mnemonics. If the
# wordlist or entropy mapping ever changes silently, these break.
_MNEMONIC_VECTORS = [
    (b"\x00" * 16,
     "abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon about"),
    (b"\xff" * 16,
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
]


def test_mnemonic_vectors_round_trip():
    for salt, expected_words in _MNEMONIC_VECTORS:
        words = salt_to_mnemonic(salt)
        assert words == expected_words, (
            f"mnemonic vector drift: {salt.hex()} -> {words!r}, "
            f"expected {expected_words!r}"
        )
        recovered = mnemonic_to_salt(words)
        assert recovered == salt


def test_mnemonic_is_12_words():
    """PROTOCOL.md §12: 128-bit entropy ⇒ 12 BIP39 words."""
    for salt, _ in _MNEMONIC_VECTORS:
        assert len(salt_to_mnemonic(salt).split()) == 12


# ── §3 · HKDF info strings (constants pinned in spec) ───────────────────────


def test_session_key_derivation_is_symmetric_and_deterministic():
    """`derive_session_key` sorts its two pubkey inputs so that A
    and B compute the same value regardless of who's initiator.
    Pinning that property here defends against a refactor that
    would silently break interop."""
    shared = b"\xaa" * 32
    pub_a = b"\x01" * 32
    pub_b = b"\x02" * 32
    k1 = derive_session_key(shared, pub_a, pub_b)
    k2 = derive_session_key(shared, pub_b, pub_a)
    assert k1 == k2
    assert len(k1) == 32


def test_hmac_key_derivation_pinned():
    sess = b"\x55" * 32
    h1 = derive_hmac_key(sess)
    h2 = derive_hmac_key(sess)
    assert h1 == h2
    assert len(h1) == 32
    # Domain separation: the HMAC key must differ from the session
    # key it was derived from.
    assert h1 != sess


def test_generic_hkdf_constants():
    """A few hand-picked HKDF outputs serve as KAT for HKDF-SHA256.
    These will catch a primitive swap (e.g. accidental SHA-1)."""
    out = hkdf_derive(
        ikm=b"\x00" * 32,
        salt=b"\x00" * 32,
        info=b"vec",
        length=32,
    )
    assert len(out) == 32
    # Pinning the exact bytes of one HKDF output. If this changes,
    # something major moved (primitive, salt handling, …).
    assert out == bytes.fromhex(
        "85c913f550ac008224038181a831e49bf3d283690d72d4ea0edc6c7018da7f01"
    )


# ── §7 · Authenticated payload (HMAC path) ──────────────────────────────────


def test_hmac_sign_verify_round_trip():
    key = b"\xa1" * 32
    data = b"the inner JSON of an AUTH_HMAC payload"
    tag = hmac_sign(key, data)
    assert len(tag) == 32   # HMAC-SHA256
    assert hmac_verify(key, data, tag) is True


def test_hmac_verify_rejects_wrong_data():
    key = b"\xa1" * 32
    tag = hmac_sign(key, b"original")
    assert hmac_verify(key, b"tampered", tag) is False


def test_hmac_verify_rejects_wrong_key():
    tag = hmac_sign(b"\x01" * 32, b"data")
    assert hmac_verify(b"\x02" * 32, b"data", tag) is False


# ── §8.2 · Sealed sender (round-trip; ephemeral key randomized) ─────────────


def test_sealed_sender_round_trip():
    recipient = X25519PrivateKey.generate()
    rec_pub = recipient.public_key().public_bytes_raw()

    eph_hex, sealed_b64 = seal("alice-peer-id-1234567890abcdef00ff", rec_pub)

    # Format invariants (PROTOCOL.md §8.2)
    assert len(eph_hex) == 64                # 32 bytes hex
    assert all(c in "0123456789abcdef" for c in eph_hex)
    raw = base64.b64decode(sealed_b64)
    assert len(raw) >= 12 + 16               # nonce + at least the tag

    recovered = unseal(eph_hex, sealed_b64, recipient)
    assert recovered == "alice-peer-id-1234567890abcdef00ff"


def test_sealed_sender_each_call_uses_fresh_ephemeral_key():
    recipient = X25519PrivateKey.generate()
    rec_pub = recipient.public_key().public_bytes_raw()
    eph1, _ = seal("peer-x", rec_pub)
    eph2, _ = seal("peer-x", rec_pub)
    # Same plaintext, two seals: ephemeral keys must differ — that's
    # what gives sealed sender its replay-distinguishability across
    # the wire and per-message PFS-like behaviour for the metadata.
    assert eph1 != eph2


# ── §6 · Onion layering (round-trip) ────────────────────────────────────────


def test_peer_id_marker_round_trip():
    assert peer_id_from_bytes(FINAL_HOP_MARKER) is None
    pid_hex = "abcdef" * 6 + "00ff"
    raw = peer_id_to_bytes(pid_hex)
    assert len(raw) == 20
    assert peer_id_from_bytes(raw) == pid_hex


def test_onion_three_hop_peels_to_plaintext():
    # Build three hops with fresh keypairs; wrap then peel.
    h1, h2, h3 = (X25519PrivateKey.generate() for _ in range(3))
    pub1 = h1.public_key().public_bytes_raw()
    pub2 = h2.public_key().public_bytes_raw()
    pub3 = h3.public_key().public_bytes_raw()
    pid1 = "11" * 20
    pid2 = "22" * 20
    pid3 = "33" * 20

    plaintext = b"the innermost message"
    onion = wrap_onion(plaintext, [(pub1, pid1), (pub2, pid2), (pub3, pid3)])

    # The wrap output starts with first_hop_id(20)+payload_len(4); the
    # outer relay strips that before passing the rest to peel_layer.
    # We mirror the production strip here (see node._handle_onion +
    # the `packet[24:]` call sites).
    layer = onion[24:]

    next1, inner1 = peel_layer(h1, layer)
    assert next1 == pid2
    next2, inner2 = peel_layer(h2, inner1)
    assert next2 == pid3
    next3, inner3 = peel_layer(h3, inner2)
    # Final hop reports next = None (sentinel match) and the
    # decrypted plaintext as inner.
    assert next3 is None
    assert inner3 == plaintext


# ── §3 · ECDH agreement (deterministic given keys) ──────────────────────────


def test_ecdh_agreement_symmetric():
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    a_pub = a.public_key().public_bytes_raw()
    b_pub = b.public_key().public_bytes_raw()

    s1 = ecdh_shared_secret(a, b_pub)
    s2 = ecdh_shared_secret(b, a_pub)
    assert s1 == s2
    assert len(s1) == 32


# ── ChaCha20-Poly1305 round-trip with AAD (used by sealed_sender) ───────────


def test_aead_round_trip_with_aad():
    key = b"\xc0" * 32
    aad = b"associated"
    pt = b"plaintext"
    ct = encrypt(key, pt, aad=aad)
    # Format: nonce (12) || ciphertext+tag
    assert len(ct) >= 12 + len(pt) + 16
    assert decrypt(key, ct, aad=aad) == pt


def test_aead_rejects_wrong_aad():
    import pytest
    key = b"\xc0" * 32
    ct = encrypt(key, b"x", aad=b"good")
    with pytest.raises(Exception):
        decrypt(key, ct, aad=b"bad")
