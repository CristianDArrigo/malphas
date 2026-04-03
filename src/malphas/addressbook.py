"""
Encrypted address book.

On disk: nonce(12) || ChaCha20-Poly1305(book_key, padded_json)
The file is indistinguishable from random bytes without the key.

Padding: plaintext is padded to the nearest multiple of BLOCK_SIZE
before encryption to obscure the number of contacts.

book_key is derived from the same passphrase seed as the identity,
but with a different HKDF info string — crytographically independent.

Never stores the passphrase or the book_key. Both exist only in RAM
for the duration of the process.
"""

import json
import os
import secrets
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from .crypto import encrypt, decrypt, hkdf_derive

# Pad plaintext to nearest multiple of this to obscure contact count
BLOCK_SIZE = 4096  # bytes


@dataclass
class Contact:
    label: str          # human-readable nickname (stored encrypted)
    peer_id: str        # 40-char hex
    host: str
    port: int
    x25519_pub: str     # 64-char hex
    ed25519_pub: str    # 64-char hex

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Contact":
        return Contact(
            label=d["label"],
            peer_id=d["peer_id"],
            host=d["host"],
            port=d["port"],
            x25519_pub=d["x25519_pub"],
            ed25519_pub=d["ed25519_pub"],
        )


def derive_book_key(passphrase_seed: bytes) -> bytes:
    """
    Derive a 32-byte symmetric key for the address book.
    Uses a different HKDF info string than the identity derivation,
    so this key is cryptographically independent from the keypairs.
    """
    return hkdf_derive(
        passphrase_seed,
        salt=b"malphas-addressbook-v1",
        info=b"addressbook-encryption-key",
        length=32,
    )


def _pad(data: bytes, block_size: int) -> bytes:
    """Pad to nearest block_size multiple using 4-byte length prefix."""
    import struct
    length_prefix = struct.pack(">I", len(data))
    total = len(length_prefix) + len(data)
    remainder = total % block_size
    pad_len = (block_size - remainder) if remainder else 0
    return length_prefix + data + os.urandom(pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove padding via length prefix."""
    import struct
    if len(data) < 4:
        raise ValueError("Data too short")
    length = struct.unpack(">I", data[:4])[0]
    if 4 + length > len(data):
        raise ValueError("Invalid length prefix")
    return data[4: 4 + length]


class AddressBook:
    """
    Encrypted persistent address book.

    Usage:
        book = AddressBook(path, book_key)
        book.load()           # decrypt from disk
        book.add(contact)     # add + save
        book.remove(label)    # remove + save
        book.all()            # list contacts
        book.wipe_memory()    # clear RAM copy
    """

    def __init__(self, path: str, book_key: bytes):
        self._path = Path(path)
        self._key = book_key
        self._contacts: List[Contact] = []
        self._loaded = False

    # ── Persistence ──────────────────────────────────────────────────────────

    def load(self) -> bool:
        """
        Decrypt and load contacts from disk.
        Returns True if file existed and decrypted successfully.
        Returns False if file does not exist.
        Raises ValueError if file exists but decryption fails (wrong key or tampered).
        """
        if not self._path.exists() or self._path.stat().st_size == 0:
            self._loaded = True
            return False

        raw = self._path.read_bytes()
        try:
            padded = decrypt(self._key, raw)
            plaintext = _unpad(padded)
            data = json.loads(plaintext.decode("utf-8"))
            self._contacts = [Contact.from_dict(c) for c in data]
            self._loaded = True
            return True
        except Exception as e:
            raise ValueError(
                f"Address book decryption failed — wrong passphrase or corrupted file"
            ) from e

    def _save(self) -> None:
        """Encrypt and write contacts to disk atomically."""
        if not self._loaded:
            raise RuntimeError("Address book not loaded")

        plaintext = json.dumps(
            [c.to_dict() for c in self._contacts],
            ensure_ascii=False,
        ).encode("utf-8")

        padded = _pad(plaintext, BLOCK_SIZE)
        ciphertext = encrypt(self._key, padded)

        # Atomic write: write to temp file, then rename
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_bytes(ciphertext)
            tmp.replace(self._path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    # ── API ──────────────────────────────────────────────────────────────────

    def all(self) -> List[Contact]:
        return list(self._contacts)

    def get(self, label: str) -> Optional[Contact]:
        label = label.strip().lower()
        for c in self._contacts:
            if c.label.lower() == label:
                return c
        return None

    def get_by_peer_id(self, peer_id: str) -> Optional[Contact]:
        for c in self._contacts:
            if c.peer_id == peer_id:
                return c
        return None

    def add(self, contact: Contact) -> None:
        """Add or update a contact, then save."""
        # Remove existing entry for same peer_id or label
        self._contacts = [
            c for c in self._contacts
            if c.peer_id != contact.peer_id and c.label.lower() != contact.label.lower()
        ]
        self._contacts.append(contact)
        self._save()

    def remove(self, label: str) -> bool:
        """Remove by label. Returns True if found and removed."""
        before = len(self._contacts)
        self._contacts = [
            c for c in self._contacts
            if c.label.lower() != label.strip().lower()
        ]
        if len(self._contacts) < before:
            self._save()
            return True
        return False

    def remove_by_peer_id(self, peer_id: str) -> bool:
        before = len(self._contacts)
        self._contacts = [c for c in self._contacts if c.peer_id != peer_id]
        if len(self._contacts) < before:
            self._save()
            return True
        return False

    def wipe_memory(self) -> None:
        """Clear in-memory contact list. Does NOT delete the file."""
        self._contacts.clear()
        self._loaded = False

    def delete_file(self) -> None:
        """Permanently delete the encrypted file from disk."""
        self._path.unlink(missing_ok=True)
        self.wipe_memory()

    @property
    def path(self) -> Path:
        return self._path

    def __len__(self) -> int:
        return len(self._contacts)
