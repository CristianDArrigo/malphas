"""
Key pinning store (Trust On First Use).

On first contact with a peer_id, the Ed25519 public key is pinned.
On subsequent contacts, the key is compared against the pin.
A mismatch means either the peer changed passphrase or an attacker
is impersonating them — the connection is rejected.

The pin store is:
- In-memory (dict) for runtime lookups
- Optionally persisted to disk, encrypted with the same book_key
  as the address book (ChaCha20-Poly1305)

/trust <peer_id> resets a pin manually (for legitimate passphrase changes).
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional

from .crypto import encrypt, decrypt


class PinStore:
    def __init__(self, path: Optional[str] = None, key: Optional[bytes] = None):
        self._pins: Dict[str, str] = {}  # peer_id -> ed25519_pub hex
        self._path = Path(path) if path else None
        self._key = key

    def check_and_pin(self, peer_id: str, ed25519_pub: bytes) -> tuple:
        """
        Check a peer's key against the store.

        Returns:
            (True, None) — key matches existing pin or newly pinned
            (False, pinned_key_hex) — key mismatch, returns the expected key
        """
        pub_hex = ed25519_pub.hex()
        existing = self._pins.get(peer_id)

        if existing is None:
            # First contact — pin it
            self._pins[peer_id] = pub_hex
            self._save()
            return True, None

        if existing == pub_hex:
            return True, None

        # Mismatch
        return False, existing

    def trust(self, peer_id: str, ed25519_pub: Optional[bytes] = None) -> None:
        """
        Reset or remove pin for a peer. If ed25519_pub is given,
        pin to that key. Otherwise, remove the pin entirely
        (next contact will re-pin).
        """
        if ed25519_pub:
            self._pins[peer_id] = ed25519_pub.hex()
        else:
            self._pins.pop(peer_id, None)
        self._save()

    def get_pin(self, peer_id: str) -> Optional[str]:
        """Return the pinned Ed25519 pubkey hex for a peer, or None."""
        return self._pins.get(peer_id)

    def all_pins(self) -> Dict[str, str]:
        return dict(self._pins)

    # ── Persistence ──────────────────────────────────────────────────────

    def load(self) -> bool:
        """Load pins from encrypted file. Returns True if loaded."""
        if not self._path or not self._key:
            return False
        if not self._path.exists() or self._path.stat().st_size == 0:
            return False
        try:
            raw = self._path.read_bytes()
            plaintext = decrypt(self._key, raw)
            self._pins = json.loads(plaintext.decode())
            return True
        except Exception:
            # Corrupted or wrong key — start fresh
            return False

    def _save(self) -> None:
        """Encrypt and save pins to disk."""
        if not self._path or not self._key:
            return
        plaintext = json.dumps(self._pins).encode()
        ciphertext = encrypt(self._key, plaintext)
        tmp = self._path.with_suffix(".pintmp")
        try:
            tmp.write_bytes(ciphertext)
            tmp.replace(self._path)
        except Exception:
            tmp.unlink(missing_ok=True)

    def wipe(self) -> None:
        """Clear all pins from memory."""
        self._pins.clear()
