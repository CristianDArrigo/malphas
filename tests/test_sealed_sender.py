"""
Tests for malphas.sealed_sender — seal/unseal of the `from` peer_id.

Properties under test:
- Roundtrip: seal then unseal returns the original peer_id.
- Eph_pub is 32 random bytes; never repeated even for same input.
- Sealed bytes are indistinguishable-from-random (tag mismatch on
  any tampering: eph_pub bit-flip, sealed bit-flip, wrong recipient).
- Bad inputs surface as ValueError, never something more exotic.
"""

from __future__ import annotations

import base64

import pytest

from malphas.crypto import generate_ephemeral_keypair
from malphas.identity import create_identity
from malphas.sealed_sender import seal, unseal


def test_roundtrip_recovers_from_peer_id():
    ident_alice = create_identity("alice-seal")
    ident_bob = create_identity("bob-seal")

    eph_pub_hex, sealed_b64 = seal(ident_alice.peer_id, ident_bob.x25519_pub_bytes)
    recovered = unseal(eph_pub_hex, sealed_b64, ident_bob.x25519_priv)
    assert recovered == ident_alice.peer_id


def test_eph_pub_is_fresh_each_call():
    ident_bob = create_identity("bob-seal-2")
    a1, _ = seal("a" * 40, ident_bob.x25519_pub_bytes)
    a2, _ = seal("a" * 40, ident_bob.x25519_pub_bytes)
    assert a1 != a2  # ephemeral keypair is regenerated


def test_sealed_b64_is_fresh_each_call():
    """Random nonce in encrypt() means the same plaintext sealed twice
    produces different ciphertext."""
    ident_bob = create_identity("bob-seal-3")
    _, s1 = seal("a" * 40, ident_bob.x25519_pub_bytes)
    _, s2 = seal("a" * 40, ident_bob.x25519_pub_bytes)
    assert s1 != s2


def test_wrong_recipient_fails():
    ident_alice = create_identity("alice-seal-4")
    ident_bob = create_identity("bob-seal-4")
    ident_charlie = create_identity("charlie-seal-4")

    eph_pub, sealed = seal(ident_alice.peer_id, ident_bob.x25519_pub_bytes)
    # Charlie tries to unseal — must fail
    with pytest.raises(ValueError):
        unseal(eph_pub, sealed, ident_charlie.x25519_priv)


def test_tampered_eph_pub_fails():
    ident_alice = create_identity("alice-seal-5")
    ident_bob = create_identity("bob-seal-5")

    eph_pub, sealed = seal(ident_alice.peer_id, ident_bob.x25519_pub_bytes)
    # Flip a single hex char on eph_pub
    tampered = list(eph_pub)
    tampered[0] = "0" if tampered[0] != "0" else "1"
    tampered_str = "".join(tampered)

    with pytest.raises(ValueError):
        unseal(tampered_str, sealed, ident_bob.x25519_priv)


def test_tampered_sealed_fails():
    ident_alice = create_identity("alice-seal-6")
    ident_bob = create_identity("bob-seal-6")

    eph_pub, sealed = seal(ident_alice.peer_id, ident_bob.x25519_pub_bytes)
    # Flip a byte in the sealed ciphertext
    raw = bytearray(base64.b64decode(sealed))
    raw[-1] ^= 0x01
    tampered_b64 = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(ValueError):
        unseal(eph_pub, tampered_b64, ident_bob.x25519_priv)


def test_invalid_eph_pub_hex_raises_valueerror():
    ident_bob = create_identity("bob-seal-7")
    with pytest.raises(ValueError):
        unseal("not-hex-at-all", "AAAA", ident_bob.x25519_priv)


def test_invalid_sealed_b64_raises_valueerror():
    ident_bob = create_identity("bob-seal-8")
    _, eph_pub = generate_ephemeral_keypair()
    with pytest.raises(ValueError):
        unseal(eph_pub.hex(), "@@@not_b64@@@", ident_bob.x25519_priv)


def test_short_eph_pub_raises_valueerror():
    ident_bob = create_identity("bob-seal-9")
    with pytest.raises(ValueError):
        unseal("0011", "AAAA", ident_bob.x25519_priv)
