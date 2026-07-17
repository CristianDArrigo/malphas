"""
Known-answer tests pinning the exact KDF derivations to PROTOCOL.md (issue #9).

The salt/info strings and golden digests asserted here MUST match BOTH the
shipped functions AND the formulas written in PROTOCOL.md. If code and spec
drift apart, one of these breaks. Previously the suite pinned only the code's
constants, which silently enshrined a code/spec divergence.
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from malphas.crypto import derive_hmac_key, derive_session_key, hkdf_derive
from malphas.identity import derive_book_key_from_root
from malphas.onion import peel_layer, wrap_onion

ROOT = bytes(range(32))
SHARED = bytes(range(32))
PUB_A = bytes([1]) * 32
PUB_B = bytes([2]) * 32


def test_book_key_matches_protocol_md():
    # PROTOCOL.md §3.1:
    #   book_key = HKDF-SHA256(root32, salt=b"malphas-addressbook-v1",
    #                          info=b"addressbook-encryption-key", len=32)
    documented = hkdf_derive(
        ROOT, salt=b"malphas-addressbook-v1",
        info=b"addressbook-encryption-key", length=32,
    )
    assert derive_book_key_from_root(ROOT) == documented
    assert (
        derive_book_key_from_root(ROOT).hex()
        == "a73cc068399bb68eaf22dc4e9869815a5240627017002f257c20063c196edcda"
    )


def test_session_key_matches_protocol_md():
    # PROTOCOL.md §5:
    #   session_key = HKDF-SHA256(ECDH, salt=sorted(eph_pub_a, eph_pub_b) concat,
    #                             info=b"malphas-session-v1", len=32)
    ordered = sorted([PUB_A, PUB_B])
    documented = hkdf_derive(
        SHARED, salt=ordered[0] + ordered[1],
        info=b"malphas-session-v1", length=32,
    )
    assert derive_session_key(SHARED, PUB_A, PUB_B) == documented
    assert (
        derive_session_key(SHARED, PUB_A, PUB_B).hex()
        == "9f52ad7df57097ecce2f13cab94f91d8b1064b666877c4595b67fdb5e0e2e8d2"
    )


def test_hmac_key_matches_protocol_md():
    # PROTOCOL.md §5:
    #   hmac_key = HKDF-SHA256(session_key, salt=b"malphas-hmac-v1",
    #                          info=b"message-auth", 32)
    sk = derive_session_key(SHARED, PUB_A, PUB_B)
    documented = hkdf_derive(
        sk, salt=b"malphas-hmac-v1", info=b"message-auth", length=32,
    )
    assert derive_hmac_key(sk) == documented
    assert (
        derive_hmac_key(sk).hex()
        == "e8264ed693fb4316e75062e863b5bcdc5b795c2fece161268263e021fba9ffd3"
    )


def test_onion_layer_wire_format_matches_protocol_md():
    # PROTOCOL.md §6: each on-wire layer is [eph_pub:32][enc_len:4][encrypted],
    # and next_hop_id is carried INSIDE the AEAD plaintext, not in cleartext.
    hop_priv = X25519PrivateKey.generate()
    hop_pub = hop_priv.public_key().public_bytes_raw()
    packet = wrap_onion(b"payload", [(hop_pub, "aa" * 20)])
    # Outer framing: first_hop_id(20) || len(4) || layer
    layer = packet[24:]
    # Peeling with the hop's key must recover the payload; final hop => None.
    next_hop, inner = peel_layer(hop_priv, layer)
    assert next_hop is None
    assert inner == b"payload"
