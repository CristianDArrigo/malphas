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
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .secure_buffer import SecureBytes

# Domain separation for the dedicated Tor onion-service key. Derived from the
# same identity seed but via HKDF so it is cryptographically independent of the
# messaging Ed25519 key. Handing THIS key to the Tor daemon (ADD_ONION) means
# the key that signs messages/handshakes/receipts/invites never leaves the
# process, even though the onion key must.
_TOR_IDENTITY_SALT = b"malphas-tor-identity-v1"
_TOR_IDENTITY_INFO = b"tor-onion-key"


def _derive_tor_key(seed_bytes: bytes) -> tuple["Ed25519PrivateKey", bytes]:
    from .crypto import hkdf_derive
    tor_seed = hkdf_derive(
        seed_bytes, salt=_TOR_IDENTITY_SALT, info=_TOR_IDENTITY_INFO, length=32
    )
    priv = Ed25519PrivateKey.from_private_bytes(tor_seed)
    pub_bytes = bytes(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return priv, pub_bytes

# Argon2id parameters.
# time_cost=3, memory_cost=65536 (64MB), parallelism=4
# produces ~200ms per derivation on modern hardware.
# This makes offline brute force of the address book
# computationally prohibitive even with dedicated hardware.
_ARGON2_TIME_COST    = 3
_ARGON2_MEMORY_COST  = 65536  # KB = 64 MB
_ARGON2_PARALLELISM  = 4
_ARGON2_HASH_LEN     = 64
# Legacy fallback salt — used when no per-user salt is provided.
# Pre-0.7.0 this was the only salt; tests still rely on it for
# deterministic identity derivation. Production CLI code passes a
# per-user 16-byte salt loaded from `~/.malphas/salt` instead, see
# malphas.salt_store.
_ARGON2_SALT_LEGACY  = b"malphas-kdf-salt"  # 16 bytes


def _derive_seed(passphrase: str, salt: bytes | None = None) -> SecureBytes:
    """
    Argon2id(passphrase, salt) -> 64-byte seed wrapped in a SecureBytes.

    `salt` should be a 16-byte per-user value loaded from
    `~/.malphas/salt`. If None, falls back to the legacy global
    constant — kept for test determinism, NOT recommended in
    production.

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
    effective_salt = salt if salt is not None else _ARGON2_SALT_LEGACY
    if len(effective_salt) != 16:
        raise ValueError(
            f"Argon2 salt must be exactly 16 bytes, got {len(effective_salt)}"
        )
    raw = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=effective_salt,
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
    # Dedicated Tor onion-service key (see _derive_tor_key). Separate from the
    # messaging identity so a compromise of the Tor daemon/ControlPort cannot
    # forge messaging-identity signatures.
    tor_ed25519_priv: Ed25519PrivateKey
    tor_ed25519_pub_bytes: bytes

    @property
    def ed25519_pub_bytes(self) -> bytes:
        return bytes(self.ed25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def sign(self, data: bytes) -> bytes:
        return bytes(self.ed25519_priv.sign(data))

    def tor_service_key(self) -> tuple[bytes, bytes]:
        """Return (pub_bytes, raw_priv_bytes) for the Tor onion service.

        This is the DEDICATED Tor key, never the messaging Ed25519 identity, so
        handing it to the Tor daemon via ADD_ONION does not expose the key that
        signs messages, handshakes, receipts and invites.
        """
        raw_priv = bytes(self.tor_ed25519_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        return self.tor_ed25519_pub_bytes, raw_priv

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.ed25519_pub.verify(signature, data)
            return True
        except Exception:
            return False


def create_identity(passphrase: str, salt: bytes | None = None) -> Identity:
    """
    Derive a deterministic Identity from a passphrase + salt.
    The passphrase is never stored. Call this once at startup.

    `salt` should be a per-user 16-byte value (see malphas.salt_store).
    If None, falls back to the legacy global salt — kept for test
    determinism only.

    The intermediate Argon2 seed is held in a SecureBytes that is
    explicitly wiped (and unlocked from RAM) before this function
    returns.
    """
    with _derive_seed(passphrase, salt) as seed:
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
        tor_priv, tor_pub_bytes = _derive_tor_key(seed_bytes)
        # _derive_seed's SecureBytes is wiped on context exit below.

    return Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
        tor_ed25519_priv=tor_priv,
        tor_ed25519_pub_bytes=tor_pub_bytes,
    )


def peer_id_from_pubkey(ed25519_pub_bytes: bytes) -> str:
    return hashlib.blake2s(ed25519_pub_bytes, digest_size=20).hexdigest()


def create_identity_with_book_key(
    passphrase: str, salt: bytes | None = None
) -> tuple[Identity, bytes]:
    """
    Derive Identity + address book encryption key from the same passphrase + salt.
    Returns (Identity, book_key: bytes).

    `salt` should be a per-user 16-byte value (see malphas.salt_store).
    If None, falls back to the legacy global salt for backward-
    compatible test paths only.

    Both derivations come from a single Argon2 seed wrapped in a
    SecureBytes that is wiped (and unlocked from RAM) before this
    function returns. The two derivations use different HKDF info
    strings and are cryptographically independent.

    The returned `book_key` is plain `bytes` to remain compatible with
    AddressBook / PinStore call sites; tightening that surface is a
    future iteration.
    """
    from .crypto import hkdf_derive

    with _derive_seed(passphrase, salt) as seed:
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
        tor_priv, tor_pub_bytes = _derive_tor_key(seed_bytes)
        # SecureBytes seed is wiped on context exit.

    identity = Identity(
        peer_id=peer_id,
        ed25519_priv=ed_priv,
        ed25519_pub=ed_pub,
        x25519_priv=x_priv,
        x25519_pub=x_pub,
        x25519_pub_bytes=x_pub_bytes,
        tor_ed25519_priv=tor_priv,
        tor_ed25519_pub_bytes=tor_pub_bytes,
    )

    return identity, book_key
