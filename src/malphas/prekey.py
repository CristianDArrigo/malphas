"""
X3DH prekey key-agreement (issue #12).

The interactive handshake seeds a Double Ratchet only for a live, directly
connected peer. Messages sent to a peer we are NOT connected to (multi-hop
onion delivery) previously fell back to authenticating cleartext JSON with an
HMAC or an Ed25519 signature under only the recipient's *static* X25519 key,
with no per-message forward secrecy, and the Ed25519 path was non-deniable.

X3DH fixes this. Using the recipient's published **signed prekey** (SPK), a
sender derives a shared secret with three Diffie-Hellman operations and a fresh
ephemeral key, then seeds a Double Ratchet from it (see node.py). This gives:

  * forward secrecy from the sender's fresh ephemeral (`EK`), and ongoing
    per-message forward secrecy once the ratchet advances;
  * deniability: the shared secret is symmetric (both parties can compute it),
    so neither can prove to a third party who authored a message. The Ed25519
    signature only authenticates the long-lived prekey, not any message.

This is the reduced X3DH (identity key + signed prekey, no one-time prekeys).
One-time prekeys (which strengthen forward secrecy of the very first message
against a later recipient compromise) are a documented future enhancement.

Notation: IK = long-term identity X25519 key, SPK = signed prekey X25519 key,
EK = sender's per-session ephemeral X25519 key.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import ecdh_shared_secret, hkdf_derive

# Domain separation for the X3DH shared-secret KDF. The 32 0xFF prefix bytes
# match the Signal X3DH convention (they keep the KDF input from ever colliding
# with a raw X25519 public key).
_X3DH_KDF_PREFIX = b"\xff" * 32
_X3DH_KDF_SALT = b"malphas-x3dh-v1"
_X3DH_KDF_INFO = b"x3dh-shared-secret"
_SPK_SIG_CONTEXT = b"malphas-signed-prekey-v1"


def generate_signed_prekey(
    ed25519_signing_priv: Ed25519PrivateKey,
) -> tuple[X25519PrivateKey, bytes, bytes]:
    """
    Generate a signed prekey: a fresh X25519 keypair whose public part is
    signed by the node's Ed25519 identity key.

    Returns (spk_priv, spk_pub_bytes, spk_signature). The signature binds the
    prekey to the identity, so a peer importing it can confirm the prekey
    really belongs to the identity it is talking to.
    """
    spk_priv = X25519PrivateKey.generate()
    spk_pub = spk_priv.public_key().public_bytes_raw()
    spk_sig = bytes(ed25519_signing_priv.sign(_SPK_SIG_CONTEXT + spk_pub))
    return spk_priv, spk_pub, spk_sig


def verify_signed_prekey(
    spk_pub: bytes, spk_sig: bytes, ed25519_pub: bytes
) -> bool:
    """Verify an SPK signature against the claimed Ed25519 identity key."""
    try:
        Ed25519PublicKey.from_public_bytes(ed25519_pub).verify(
            spk_sig, _SPK_SIG_CONTEXT + spk_pub)
        return True
    except Exception:
        return False


def _kdf(dh_concat: bytes) -> bytes:
    return hkdf_derive(
        _X3DH_KDF_PREFIX + dh_concat,
        salt=_X3DH_KDF_SALT, info=_X3DH_KDF_INFO, length=32,
    )


def x3dh_initiator(
    my_ik_priv: X25519PrivateKey,
    their_ik_pub: bytes,
    their_spk_pub: bytes,
) -> tuple[bytes, bytes]:
    """
    Sender side. Derive the X3DH shared secret with a fresh ephemeral key.

    The caller MUST have already verified `their_spk_pub` via
    `verify_signed_prekey`. Returns (shared_secret, ephemeral_pub_bytes); send
    the ephemeral public alongside the message so the responder can reproduce
    the secret.
    """
    ek_priv = X25519PrivateKey.generate()
    ek_pub = ek_priv.public_key().public_bytes_raw()

    dh1 = ecdh_shared_secret(my_ik_priv, their_spk_pub)  # IK_A · SPK_B
    dh2 = ecdh_shared_secret(ek_priv, their_ik_pub)      # EK_A · IK_B
    dh3 = ecdh_shared_secret(ek_priv, their_spk_pub)     # EK_A · SPK_B
    return _kdf(dh1 + dh2 + dh3), ek_pub


def x3dh_responder(
    my_ik_priv: X25519PrivateKey,
    my_spk_priv: X25519PrivateKey,
    their_ik_pub: bytes,
    their_ek_pub: bytes,
) -> bytes:
    """
    Recipient side. Reproduce the X3DH shared secret from the sender's identity
    and ephemeral public keys plus our own identity + signed-prekey privates.
    """
    dh1 = ecdh_shared_secret(my_spk_priv, their_ik_pub)  # SPK_B · IK_A
    dh2 = ecdh_shared_secret(my_ik_priv, their_ek_pub)   # IK_B · EK_A
    dh3 = ecdh_shared_secret(my_spk_priv, their_ek_pub)  # SPK_B · EK_A
    return _kdf(dh1 + dh2 + dh3)
