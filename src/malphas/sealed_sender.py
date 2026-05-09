"""
Sealed sender — hide the `from` peer_id from anyone but the final
recipient.

The application-level onion already encrypts the payload between
sender and final destination. But if the session key with the first
hop is later exposed (compromised relay, post-mortem traffic capture
+ key recovery), the outer ChaCha20-Poly1305 layer can be peeled and
the inner JSON read. Today the inner JSON contains `"from": "<peer_id>"`
in plaintext — an attacker would learn the social graph from that.

Sealed sender re-encrypts the `from` field with a fresh ephemeral key
ECDH'd against the recipient's static X25519 public key, the same key
that's already pinned via the address book. Only the recipient's
X25519 private key can recover `real_from`. Everyone else (relays,
captured-and-decrypted-later observers) sees only opaque bytes.

Wire-format change introduced in v0.6.0:

  prev (≤0.5.x):  {"from": "<peer_id>", ...}
  now  (0.6.0):   {"from_eph": "<32-byte hex>",
                   "from_sealed": "<base64 ciphertext+tag>",
                   ...}
  ("from" is omitted; the receiver fills it in after decrypting.)

The outer auth tag (HMAC or Ed25519, see node.py) still covers the
whole JSON, so an attacker cannot swap `from_eph` or `from_sealed`
without invalidating it.
"""

from __future__ import annotations

import base64
import binascii

from .crypto import (
    decrypt,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    hkdf_derive,
)

_SALT = b"malphas-sealed-sender-v1"
_INFO = b"from"


def seal(from_peer_id: str, dest_x25519_pub: bytes) -> tuple[str, str]:
    """
    Encrypt `from_peer_id` against the recipient's static X25519 pubkey.

    Returns (eph_pub_hex, sealed_b64) — the two strings the sender
    embeds in the outgoing JSON payload (`from_eph`, `from_sealed`).

    The recipient calls `unseal()` with the same eph_pub and their
    own X25519 private key.
    """
    eph_priv, eph_pub = generate_ephemeral_keypair()
    shared = ecdh_shared_secret(eph_priv, dest_x25519_pub)
    from_key = hkdf_derive(shared, salt=_SALT, info=_INFO, length=32)
    sealed = encrypt(from_key, from_peer_id.encode("utf-8"), aad=eph_pub)
    return eph_pub.hex(), base64.b64encode(sealed).decode("ascii")


def unseal(
    eph_pub_hex: str,
    sealed_b64: str,
    my_x25519_priv: object,  # X25519PrivateKey, but typed at call site
) -> str:
    """
    Recover `from_peer_id` from a sealed envelope.

    Raises ValueError on any malformed input or auth-tag mismatch.
    Callers should treat that as a "drop silently" signal — exactly
    like the existing failures on the auth path.
    """
    try:
        eph_pub = bytes.fromhex(eph_pub_hex)
    except ValueError as e:
        raise ValueError(f"invalid eph_pub hex: {e}") from e
    if len(eph_pub) != 32:
        raise ValueError(f"invalid eph_pub length: {len(eph_pub)}")

    try:
        sealed = base64.b64decode(sealed_b64, validate=True)
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"invalid sealed b64: {e}") from e

    shared = ecdh_shared_secret(my_x25519_priv, eph_pub)  # type: ignore[arg-type]
    from_key = hkdf_derive(shared, salt=_SALT, info=_INFO, length=32)
    plaintext = decrypt(from_key, sealed, aad=eph_pub)
    return plaintext.decode("utf-8")
