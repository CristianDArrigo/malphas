"""
Crypto layer.
- X25519 ECDH for shared secret
- HKDF-SHA256 for key derivation
- ChaCha20-Poly1305 for authenticated encryption
- Ed25519 for message signing (via identity.py)

No custom crypto. All primitives from cryptography.hazmat.
"""

import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# --- Key derivation ----------------------------------------------------------

def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 key derivation."""
    hkdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def ecdh_shared_secret(
    my_priv: X25519PrivateKey,
    their_pub_bytes: bytes,
) -> bytes:
    """X25519 ECDH. Returns 32-byte raw shared secret."""
    their_pub = X25519PublicKey.from_public_bytes(their_pub_bytes)
    return my_priv.exchange(their_pub)


# --- Symmetric encryption ----------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    ChaCha20-Poly1305 encrypt.
    Returns: nonce (12) || ciphertext+tag
    """
    assert len(key) == 32, "Key must be 32 bytes"
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, aad or None)
    return nonce + ct


def decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """
    ChaCha20-Poly1305 decrypt.
    Expects: nonce (12) || ciphertext+tag
    Raises ValueError on authentication failure.
    """
    assert len(key) == 32, "Key must be 32 bytes"
    if len(data) < 12 + 16:
        raise ValueError("Ciphertext too short")
    nonce, ct = data[:12], data[12:]
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ct, aad or None)
    except Exception as e:
        raise ValueError("Decryption failed: authentication tag mismatch") from e


# --- Ephemeral session key exchange ------------------------------------------

def generate_ephemeral_keypair() -> Tuple[X25519PrivateKey, bytes]:
    """Generate a fresh X25519 keypair. Returns (priv, pub_bytes)."""
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub_bytes


def derive_session_key(
    shared_secret: bytes,
    pub_a: bytes,
    pub_b: bytes,
    role: str = "",  # kept for API compat, no longer affects derivation
) -> bytes:
    """
    Derive a symmetric session key from ECDH shared secret.
    Both sides must derive the same key. Canonical ordering via sort
    ensures the result is identical regardless of who is initiator/responder.
    ChaCha20-Poly1305 with random 12-byte nonces is safe bidirectionally
    with a single shared key.
    """
    ordered = sorted([pub_a, pub_b])
    salt = ordered[0] + ordered[1]
    info = b"malphas-session-v1"
    return hkdf_derive(shared_secret, salt=salt, info=info, length=32)


# --- Onion layer helpers -----------------------------------------------------

def pack_u16(n: int) -> bytes:
    return struct.pack(">H", n)


def unpack_u16(b: bytes) -> int:
    return struct.unpack(">H", b[:2])[0]


def pack_u32(n: int) -> bytes:
    return struct.pack(">I", n)


def unpack_u32(b: bytes) -> int:
    return struct.unpack(">I", b[:4])[0]
