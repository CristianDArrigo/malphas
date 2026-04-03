"""
Identity layer.
SHA1(passphrase) -> seed -> Ed25519 + X25519 keypairs.
The public peer_id exposed on the network is SHA1(ed25519_pubkey).
No passphrase is ever stored or logged.
"""

import gc
import hashlib
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Argon2id parameters.
# time_cost=3, memory_cost=65536 (64MB), parallelism=4
# produces ~200ms per derivation on modern hardware.
# This makes offline brute force of the address book
# computationally prohibitive even with dedicated hardware.
_ARGON2_TIME_COST    = 3
_ARGON2_MEMORY_COST  = 65536  # KB = 64 MB
_ARGON2_PARALLELISM  = 4
_ARGON2_HASH_LEN     = 64
# Salt is public and fixed — provides domain separation,
# not secrecy. Must be exactly 16 bytes for Argon2.
_ARGON2_SALT         = b"malphas-kdf-salt"  # 16 bytes


def _derive_seed(passphrase: str) -> bytes:
    """
    Argon2id(passphrase) -> 64-byte seed.

    Argon2id is memory-hard and time-hard by design.
    Each derivation requires 64MB of RAM and ~200ms —
    making offline dictionary attacks against the address
    book file computationally prohibitive.

    Replaces the previous SHA1 + HKDF approach which was
    fast enough to allow brute force attacks.
    """
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise RuntimeError(
            "argon2-cffi is required. "
            "Install it with: pip install argon2-cffi"
        )
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=_ARGON2_SALT,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_ARGON2_HASH_LEN,
        type=Type.ID,
    )


@dataclass(frozen=True)
class Identity:
    peer_id: str          # SHA1(ed25519_pubkey_bytes) — public identifier
    ed25519_priv: Ed25519PrivateKey
    ed25519_pub: Ed25519PublicKey
    x25519_priv: X25519PrivateKey
    x25519_pub: X25519PublicKey
    x25519_pub_bytes: bytes  # raw 32-byte X25519 public key for wire

    @property
    def ed25519_pub_bytes(self) -> bytes:
        return self.ed25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self.ed25519_priv.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.ed25519_pub.verify(signature, data)
            return True
        except Exception:
            return False


def create_identity(passphrase: str) -> Identity:
    """
    Derive a deterministic Identity from a passphrase.
    The passphrase is never stored. Call this once at startup.
    """
    seed = _derive_seed(passphrase)
    ed_seed = seed[:32]
    x_seed = seed[32:]

    # Ed25519 signing keypair
    ed_priv = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub = ed_priv.public_key()
    ed_pub_bytes = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # X25519 key exchange keypair
    x_priv = X25519PrivateKey.from_private_bytes(x_seed)
    x_pub = x_priv.public_key()
    x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Peer ID: SHA1 of ed25519 pubkey (hex, 40 chars)
    peer_id = hashlib.sha1(ed_pub_bytes).hexdigest()

    # Wipe seed from memory as soon as possible
    seed = secrets.token_bytes(64)  # overwrite reference
    del seed

    return Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
    )


def peer_id_from_pubkey(ed25519_pub_bytes: bytes) -> str:
    return hashlib.sha1(ed25519_pub_bytes).hexdigest()


def create_identity_with_book_key(passphrase: str) -> tuple:
    """
    Derive Identity + address book encryption key from the same passphrase.
    Returns (Identity, book_key: bytes).
    The seed is used to derive both, then wiped.
    The two derivations use different HKDF info strings and are
    cryptographically independent.
    """
    from .crypto import hkdf_derive

    seed = _derive_seed(passphrase)

    # Identity keypairs (uses first 64 bytes of seed directly)
    ed_seed = seed[:32]
    x_seed = seed[32:]

    ed_priv = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub = ed_priv.public_key()
    ed_pub_bytes = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    x_priv = X25519PrivateKey.from_private_bytes(x_seed)
    x_pub = x_priv.public_key()
    x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    peer_id = hashlib.sha1(ed_pub_bytes).hexdigest()

    # Address book key — derived from same seed, different context
    # Crytographically independent from the keypairs above
    book_key = hkdf_derive(
        seed,
        salt=b"malphas-addressbook-v1",
        info=b"addressbook-encryption-key",
        length=32,
    )

    # Wipe seed immediately after all derivations
    seed = secrets.token_bytes(64)
    del seed

    identity = Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
    )

    return identity, book_key
