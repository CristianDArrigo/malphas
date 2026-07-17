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
# Argon2 salt for the DETERMINISTIC (test/legacy) identity path. Production
# identities are random roots wrapped under a passphrase-KEK (identity_store),
# so this only feeds create_identity(passphrase) used by the test fixtures.
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


ID_ROOT_LEN = 32
# Domain separation for deriving long-term keys from the 32-byte identity root.
# Every long-term key comes from this root via HKDF, so the root is the single
# secret to protect (wrapped under a passphrase-derived KEK on disk; see
# identity_store.py). Because a production root is RANDOM (not passphrase-
# derived), peer_id and keys are independent of the passphrase, which closes the
# offline "brute-force the passphrase from a public peer_id" oracle and lets the
# passphrase be rotated without changing identity.
_ID_ROOT_SALT = b"malphas-identity-root-v2"
_ID_ED_INFO = b"ed25519-signing-key"
_ID_X_INFO = b"x25519-dh-key"
_ID_DETERMINISTIC_INFO = b"deterministic-root"


def derive_identity_from_root(root: bytes) -> Identity:
    """
    Deterministically derive an Identity from a 32-byte root secret.

    All long-term keys (Ed25519 signing, X25519 DH, dedicated Tor key) are
    HKDF-derived from the root with distinct domain-separation labels, so they
    are cryptographically independent of one another.
    """
    from .crypto import hkdf_derive
    if len(root) != ID_ROOT_LEN:
        raise ValueError(f"identity root must be {ID_ROOT_LEN} bytes, got {len(root)}")

    ed_seed = hkdf_derive(root, salt=_ID_ROOT_SALT, info=_ID_ED_INFO, length=32)
    x_seed = hkdf_derive(root, salt=_ID_ROOT_SALT, info=_ID_X_INFO, length=32)

    ed_priv = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub = ed_priv.public_key()
    ed_pub_bytes = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    x_priv = X25519PrivateKey.from_private_bytes(x_seed)
    x_pub = x_priv.public_key()
    x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Peer ID: BLAKE2s of the Ed25519 pubkey, truncated to 20 bytes (40 hex).
    peer_id = hashlib.blake2s(ed_pub_bytes, digest_size=20).hexdigest()
    tor_priv, tor_pub_bytes = _derive_tor_key(root)

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


def derive_book_key_from_root(root: bytes) -> bytes:
    """Derive the address-book encryption key from the identity root."""
    from .crypto import hkdf_derive
    return hkdf_derive(
        root, salt=b"malphas-addressbook-v1",
        info=b"addressbook-encryption-key", length=32,
    )


def _deterministic_root(passphrase: str, salt: bytes | None) -> bytes:
    """
    Derive a deterministic 32-byte root from passphrase + salt via Argon2id.

    Used by the legacy/test `create_identity` path so identities stay
    reproducible across runs and tests. PRODUCTION identities use a random
    root (see `create_random_identity`), which is what removes the offline
    peer_id oracle and enables passphrase rotation.
    """
    from .crypto import hkdf_derive
    with _derive_seed(passphrase, salt) as seed:
        return hkdf_derive(
            bytes(seed), salt=_ID_ROOT_SALT,
            info=_ID_DETERMINISTIC_INFO, length=ID_ROOT_LEN,
        )


def create_random_identity() -> tuple[bytes, Identity, bytes]:
    """
    Generate a fresh identity from a random 32-byte root.

    Returns (root, identity, book_key). The caller is responsible for wrapping
    `root` under a passphrase-derived KEK for storage (see identity_store.py)
    and for backing it up as a mnemonic. Because the root is random, peer_id
    and keys do not depend on any passphrase.
    """
    import secrets as _secrets
    root = _secrets.token_bytes(ID_ROOT_LEN)
    return root, derive_identity_from_root(root), derive_book_key_from_root(root)


def create_identity(passphrase: str, salt: bytes | None = None) -> Identity:
    """
    Derive a deterministic Identity from a passphrase + salt.

    Legacy/test convenience: production identities are created with a random
    root via `create_random_identity`. `salt` should be a per-user 16-byte
    value; if None, falls back to the legacy global salt for test determinism.
    """
    return derive_identity_from_root(_deterministic_root(passphrase, salt))


def peer_id_from_pubkey(ed25519_pub_bytes: bytes) -> str:
    return hashlib.blake2s(ed25519_pub_bytes, digest_size=20).hexdigest()


def create_identity_with_book_key(
    passphrase: str, salt: bytes | None = None
) -> tuple[Identity, bytes]:
    """
    Derive Identity + address book encryption key from the same passphrase + salt.
    Returns (Identity, book_key: bytes).

    Deterministic test/legacy helper. Production identities are random roots
    (see identity_store); `salt` (if given) is a 16-byte value, else a legacy
    constant, used only to keep test derivations reproducible.

    Both derivations come from a single Argon2 seed wrapped in a
    SecureBytes that is wiped (and unlocked from RAM) before this
    function returns. The two derivations use different HKDF info
    strings and are cryptographically independent.

    The returned `book_key` is plain `bytes` to remain compatible with
    AddressBook / PinStore call sites; tightening that surface is a
    future iteration.
    """
    root = _deterministic_root(passphrase, salt)
    return derive_identity_from_root(root), derive_book_key_from_root(root)
