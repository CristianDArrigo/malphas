"""
Identity layer.
Argon2id(passphrase) -> 64-byte seed -> Ed25519 + X25519 keypairs.
The public peer_id exposed on the network is BLAKE2s(ed25519_pubkey,
digest_size=20) — a 160-bit collision-resistant identifier. It is
hex-encoded to 40 characters on the wire; the length matches the
SHA1-based peer_id used in pre-0.5.0 builds, so storage and parser
formats (regexes, address book entries) remain unchanged.
No passphrase is ever stored or logged.
"""

import hashlib
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
)

from .secure_buffer import SecureBytes

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


def _derive_seed(passphrase: str) -> SecureBytes:
    """
    Argon2id(passphrase) -> 64-byte seed wrapped in a SecureBytes.

    Argon2id is memory-hard and time-hard by design.
    Each derivation requires 64MB of RAM and ~200ms —
    making offline dictionary attacks against the address
    book file computationally prohibitive.

    The output is wrapped in SecureBytes so the caller can wipe it as
    soon as the derived keys have been extracted. Best-effort mlock
    keeps the buffer out of swap on Linux.

    Replaces the previous SHA1 + HKDF approach which was
    fast enough to allow brute force attacks.
    """
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise RuntimeError(
            "argon2-cffi is required. "
            "Install it with: pip install argon2-cffi"
        )
    raw = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=_ARGON2_SALT,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_ARGON2_HASH_LEN,
        type=Type.ID,
    )
    # Argon2 hands us an immutable bytes object we cannot wipe.
    # Copy into SecureBytes; the immutable bytes remains live until GC,
    # but the long-lived reference is now wipeable.
    return SecureBytes.from_bytes(raw)


@dataclass(frozen=True)
class Identity:
    peer_id: str          # BLAKE2s(ed25519_pubkey_bytes, digest_size=20) — 40-char hex public identifier
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

    The intermediate Argon2 seed is held in a SecureBytes that is
    explicitly wiped (and unlocked from RAM) before this function
    returns.
    """
    with _derive_seed(passphrase) as seed:
        seed_bytes = bytes(seed)
        ed_seed = seed_bytes[:32]
        x_seed = seed_bytes[32:]

        # Ed25519 signing keypair
        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_seed)
        ed_pub = ed_priv.public_key()
        ed_pub_bytes = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # X25519 key exchange keypair
        x_priv = X25519PrivateKey.from_private_bytes(x_seed)
        x_pub = x_priv.public_key()
        x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Peer ID: BLAKE2s of ed25519 pubkey, truncated to 20 bytes
        # (40 hex chars). BLAKE2s is collision-resistant and faster than
        # SHA-256 on small inputs.
        peer_id = hashlib.blake2s(ed_pub_bytes, digest_size=20).hexdigest()
        # _derive_seed's SecureBytes is wiped on context exit below.

    return Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
    )


def peer_id_from_pubkey(ed25519_pub_bytes: bytes) -> str:
    return hashlib.blake2s(ed25519_pub_bytes, digest_size=20).hexdigest()


def create_identity_with_book_key(passphrase: str) -> tuple:
    """
    Derive Identity + address book encryption key from the same passphrase.
    Returns (Identity, book_key: bytes).

    Both derivations come from a single Argon2 seed wrapped in a
    SecureBytes that is wiped (and unlocked from RAM) before this
    function returns. The two derivations use different HKDF info
    strings and are cryptographically independent.

    The returned `book_key` is plain `bytes` to remain compatible with
    AddressBook / PinStore call sites; tightening that surface is a
    future iteration.
    """
    from .crypto import hkdf_derive

    with _derive_seed(passphrase) as seed:
        seed_bytes = bytes(seed)

        # Identity keypairs (uses first 64 bytes of seed directly)
        ed_seed = seed_bytes[:32]
        x_seed = seed_bytes[32:]

        ed_priv = Ed25519PrivateKey.from_private_bytes(ed_seed)
        ed_pub = ed_priv.public_key()
        ed_pub_bytes = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        x_priv = X25519PrivateKey.from_private_bytes(x_seed)
        x_pub = x_priv.public_key()
        x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        peer_id = hashlib.blake2s(ed_pub_bytes, digest_size=20).hexdigest()

        # Address book key — derived from same seed, different context.
        # Cryptographically independent from the keypairs above.
        book_key = hkdf_derive(
            seed_bytes,
            salt=b"malphas-addressbook-v1",
            info=b"addressbook-encryption-key",
            length=32,
        )
        # SecureBytes seed is wiped on context exit.

    identity = Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
    )

    return identity, book_key
