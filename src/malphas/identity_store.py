"""
Identity-at-rest: a passphrase-wrapped random identity root (issue #6).

The identity root is a random 32-byte secret from which every long-term key is
HKDF-derived (see identity.derive_identity_from_root). Instead of deriving the
identity *directly* from the passphrase (which made peer_id/keys a function of
the passphrase (an offline brute-force oracle) and made passphrase changes
equal to identity changes), the root is generated once at random and stored on
disk **wrapped** under a Key-Encryption-Key (KEK) derived from the passphrase
with Argon2id.

Consequences:
  * peer_id and keys are independent of the passphrase (no offline peer_id
    oracle: knowing the salt and a public peer_id reveals nothing about the
    passphrase);
  * the passphrase can be ROTATED by re-wrapping the same root, with no change
    to identity;
  * the root is backed up as a 24-word BIP39 mnemonic (mnemonic.root_to_mnemonic).

On-disk format at ~/.malphas/identity (JSON, mode 0600):
  {"v": 1, "kdf": "argon2id", "salt": <hex 16>, "wrapped_root": <hex nonce||ct>}
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .crypto import decrypt, encrypt
from .identity import (
    ID_ROOT_LEN,
    Identity,
    derive_book_key_from_root,
    derive_identity_from_root,
)

# AEAD associated data domain-separating the wrapped root from every other
# ChaCha20-Poly1305 blob in the system (address book, pin store, onion, ...).
_KEK_AAD = b"malphas-identity-root-kek-v1"
IDENTITY_FILE_VERSION = 1
_KEK_SALT_LEN = 16


def derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte KEK from the passphrase with Argon2id.

    Uses the same Argon2 cost parameters as the rest of malphas so the wrap is
    as expensive to brute-force as the old direct derivation was.
    """
    from argon2.low_level import Type, hash_secret_raw

    from .identity import (
        _ARGON2_MEMORY_COST,
        _ARGON2_PARALLELISM,
        _ARGON2_TIME_COST,
    )
    if len(salt) != _KEK_SALT_LEN:
        raise ValueError(f"KEK salt must be {_KEK_SALT_LEN} bytes, got {len(salt)}")
    return bytes(hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    ))


def wrap_root(root: bytes, passphrase: str, salt: bytes) -> bytes:
    """Encrypt the identity root under the passphrase-derived KEK."""
    return encrypt(derive_kek(passphrase, salt), root, aad=_KEK_AAD)


def unwrap_root(wrapped: bytes, passphrase: str, salt: bytes) -> bytes:
    """Decrypt the identity root. Raises ValueError on the wrong passphrase."""
    return decrypt(derive_kek(passphrase, salt), wrapped, aad=_KEK_AAD)


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".id-tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(path))
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _serialize(salt: bytes, wrapped_root: bytes) -> bytes:
    return json.dumps({
        "v": IDENTITY_FILE_VERSION,
        "kdf": "argon2id",
        "salt": salt.hex(),
        "wrapped_root": wrapped_root.hex(),
    }).encode("utf-8")


def _store(path: str, root: bytes, passphrase: str, salt: bytes) -> None:
    wrapped = wrap_root(root, passphrase, salt)
    _write_atomic(Path(path), _serialize(salt, wrapped))


def identity_file_exists(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.stat().st_size > 0


def create_and_store_identity(
    path: str, passphrase: str, root: bytes | None = None
) -> tuple[bytes, Identity, bytes]:
    """
    Create a fresh identity from a random root (or the supplied `root`, e.g.
    restored from a mnemonic), wrap it under the passphrase, and persist it.

    Returns (root, identity, book_key).
    """
    if root is None:
        root = secrets.token_bytes(ID_ROOT_LEN)
    if len(root) != ID_ROOT_LEN:
        raise ValueError(f"root must be {ID_ROOT_LEN} bytes, got {len(root)}")
    salt = secrets.token_bytes(_KEK_SALT_LEN)
    _store(path, root, passphrase, salt)
    return root, derive_identity_from_root(root), derive_book_key_from_root(root)


def load_identity(path: str, passphrase: str) -> tuple[bytes, Identity, bytes]:
    """
    Load and unwrap the stored identity root with `passphrase`.

    Returns (root, identity, book_key). Raises ValueError on a wrong passphrase
    or a corrupt/unsupported file.
    """
    p = Path(path)
    try:
        blob = json.loads(p.read_bytes().decode("utf-8"))
    except Exception as e:
        raise ValueError(f"identity file at {path} is unreadable: {e}") from e
    if blob.get("v") != IDENTITY_FILE_VERSION:
        raise ValueError(f"unsupported identity file version: {blob.get('v')}")
    salt = bytes.fromhex(blob["salt"])
    wrapped = bytes.fromhex(blob["wrapped_root"])
    root = unwrap_root(wrapped, passphrase, salt)
    if len(root) != ID_ROOT_LEN:
        raise ValueError("decrypted root has the wrong length")
    return root, derive_identity_from_root(root), derive_book_key_from_root(root)


def rotate_passphrase(path: str, old_passphrase: str, new_passphrase: str) -> None:
    """
    Re-wrap the identity root under a new passphrase (and a fresh KEK salt).

    Identity is unchanged; only the on-disk wrapping changes. Raises ValueError
    if `old_passphrase` is wrong.
    """
    root, _identity, _book = load_identity(path, old_passphrase)
    new_salt = secrets.token_bytes(_KEK_SALT_LEN)
    _store(path, root, new_passphrase, new_salt)
