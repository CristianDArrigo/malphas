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

from .crypto import decrypt, encrypt

# AEAD associated data — domain separation from the address book, which
# shares the same book_key. See addressbook._BOOK_AAD. Legacy files used
# empty AAD; load() falls back and re-saves to upgrade.
_PIN_AAD = b"malphas-pinstore-v1"


class PinStoreCorruptError(Exception):
    """Raised when the pin file exists but cannot be decrypted/parsed.

    This is a security-relevant condition: silently starting with an empty
    pin set turns an integrity failure (tampering, the very MITM signal TOFU
    exists to detect) into a silent trust reset where every peer is re-pinned
    on next contact. Callers MUST treat this as fatal, not "start fresh".
    """


class PinStore:
    def __init__(self, path: str | None = None, key: bytes | None = None):
        self._pins: dict[str, str] = {}  # peer_id -> ed25519_pub hex
        self._path = Path(path) if path else None
        self._key = key

    def check_and_pin(self, peer_id: str, ed25519_pub: bytes) -> tuple[bool, str | None]:
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

        # Constant-time compare so a timing oracle can't be used to
        # fingerprint pin-store contents byte-by-byte. Pinned keys
        # are nominally public, but the safe path is the cheap path.
        import hmac as _hmac
        if _hmac.compare_digest(existing, pub_hex):
            return True, None

        # Mismatch
        return False, existing

    def trust(self, peer_id: str, ed25519_pub: bytes | None = None) -> None:
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

    def get_pin(self, peer_id: str) -> str | None:
        """Return the pinned Ed25519 pubkey hex for a peer, or None."""
        return self._pins.get(peer_id)

    def all_pins(self) -> dict[str, str]:
        return dict(self._pins)

    # ── Persistence ──────────────────────────────────────────────────────

    def load(self) -> bool:
        """Load pins from the encrypted file.

        Returns True if pins were loaded, False if there is simply no file
        yet (legitimate first run). Raises PinStoreCorruptError if the file
        EXISTS but won't decrypt/parse — never silently start with empty
        pins, which would wipe the TOFU trust anchor.
        """
        if not self._path or not self._key:
            return False
        if not self._path.exists() or self._path.stat().st_size == 0:
            return False
        upgrade = False
        try:
            raw = self._path.read_bytes()
            try:
                plaintext = decrypt(self._key, raw, aad=_PIN_AAD)
            except ValueError:
                # Legacy file written with empty AAD — accept and upgrade.
                plaintext = decrypt(self._key, raw)
                upgrade = True
            pins = json.loads(plaintext.decode())
            if not isinstance(pins, dict):
                raise ValueError("pin file did not contain a JSON object")
            self._pins = pins
            if upgrade:
                self._save()
            return True
        except Exception as e:
            raise PinStoreCorruptError(
                f"pin file at {self._path} exists but could not be "
                f"decrypted/parsed ({e}). Refusing to start with empty "
                f"pins — this could be tampering (MITM)."
            ) from e

    def _save(self) -> None:
        """Encrypt and durably save pins to disk.

        Raises on failure: a security store must not silently lose a newly
        pinned key (which would re-open a MITM window on next contact).
        """
        if not self._path or not self._key:
            return
        plaintext = json.dumps(self._pins).encode()
        ciphertext = encrypt(self._key, plaintext, aad=_PIN_AAD)
        tmp = self._path.with_suffix(".pintmp")
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(ciphertext)
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                pass
            os.replace(str(tmp), str(self._path))
            # fsync the directory so the rename is durable too.
            try:
                dir_fd = os.open(str(self._path.parent), os.O_RDONLY)
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

    def wipe(self) -> None:
        """Clear all pins from memory."""
        self._pins.clear()
