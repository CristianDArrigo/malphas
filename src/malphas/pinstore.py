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

# Cap on in-memory pins for UNKNOWN inbound peers (peers we never invited and
# that are not in the address book). These are held ephemerally and never
# written to disk, so an attacker who opens many inbound handshakes with fresh
# identities cannot grow the on-disk pin file without bound (each disk write
# re-encrypts the whole file, an O(n^2) amplifier). When the cap is exceeded
# the oldest ephemeral pin is evicted. Pins for known/invited peers persist
# normally and are not subject to this cap.
MAX_EPHEMERAL_PINS = 256


class PinStoreCorruptError(Exception):
    """Raised when the pin file exists but cannot be decrypted/parsed.

    This is a security-relevant condition: silently starting with an empty
    pin set turns an integrity failure (tampering, the very MITM signal TOFU
    exists to detect) into a silent trust reset where every peer is re-pinned
    on next contact. Callers MUST treat this as fatal, not "start fresh".
    """


class PinStore:
    def __init__(self, path: str | None = None, key: bytes | None = None):
        # peer_id -> {"ed25519": hex, "x25519": hex|None}. x25519 may be None
        # for pins migrated from the legacy ed25519-only format; it is filled
        # in on the next contact with that peer.
        self._pins: dict[str, dict[str, str | None]] = {}
        # Ephemeral, in-memory-only pins for unknown inbound peers. Insertion
        # order is used to evict the oldest when MAX_EPHEMERAL_PINS is hit.
        self._ephemeral_pins: dict[str, dict[str, str | None]] = {}
        self._path = Path(path) if path else None
        self._key = key

    def check_and_pin(self, peer_id: str, ed25519_pub: bytes,
                      x25519_pub: bytes | None = None,
                      persist: bool = True) -> tuple[bool, str | None]:
        """
        Check a peer's keys against the store (TOFU).

        Both the Ed25519 identity key and the static X25519 encryption key are
        pinned. They are derived from the same identity seed, so for a given
        peer they are always presented together — a matching Ed25519 with a
        *different* X25519 is an impersonation/tamper signal (the exact
        sealed-sender-redirection MITM), not a legitimate rotation, and is
        rejected.

        `persist` controls durability of a *first-contact* pin. Known/invited
        peers (persist=True, the default) are pinned to disk as before. Unknown
        inbound peers (persist=False) are pinned only in memory, capped at
        MAX_EPHEMERAL_PINS, so a flood of fresh inbound identities cannot grow
        the on-disk store without bound. Within a session an ephemeral pin
        still enforces TOFU for that peer_id.

        Returns:
            (True, None) — keys match the existing pin, or newly pinned
            (False, pinned_ed25519_hex) — mismatch; returns the expected key
        """
        import hmac as _hmac
        ed_hex = ed25519_pub.hex()
        x_hex = x25519_pub.hex() if x25519_pub is not None else None
        existing = self._pins.get(peer_id) or self._ephemeral_pins.get(peer_id)

        if existing is None:
            # First contact — pin both keys.
            record = {"ed25519": ed_hex, "x25519": x_hex}
            if persist:
                self._pins[peer_id] = record
                self._save()
            else:
                self._ephemeral_pins[peer_id] = record
                # Evict oldest ephemeral pins beyond the cap (FIFO).
                while len(self._ephemeral_pins) > MAX_EPHEMERAL_PINS:
                    oldest = next(iter(self._ephemeral_pins))
                    del self._ephemeral_pins[oldest]
            return True, None

        # Constant-time compare so a timing oracle can't fingerprint the
        # pin store byte-by-byte. Pinned keys are nominally public, but the
        # safe path is the cheap path.
        pinned_ed = existing.get("ed25519") or ""
        if not _hmac.compare_digest(pinned_ed, ed_hex):
            return False, (pinned_ed or None)

        # Ed25519 matches — check (or back-fill) the X25519 pin.
        pinned_x = existing.get("x25519")
        if pinned_x is None and x_hex is not None:
            existing["x25519"] = x_hex   # legacy/missing pin: record it now
            self._save()
        elif (pinned_x is not None and x_hex is not None
              and not _hmac.compare_digest(pinned_x, x_hex)):
            return False, pinned_ed
        return True, None

    def trust(self, peer_id: str, ed25519_pub: bytes | None = None,
              x25519_pub: bytes | None = None) -> None:
        """
        Reset or remove pin for a peer. If ed25519_pub is given, pin to that
        key (optionally with x25519_pub). Otherwise, remove the pin entirely
        (next contact will re-pin).
        """
        if ed25519_pub:
            self._pins[peer_id] = {
                "ed25519": ed25519_pub.hex(),
                "x25519": x25519_pub.hex() if x25519_pub is not None else None,
            }
        else:
            self._pins.pop(peer_id, None)
        self._save()

    def get_pin(self, peer_id: str) -> str | None:
        """Return the pinned Ed25519 pubkey hex for a peer, or None."""
        entry = self._pins.get(peer_id)
        return entry.get("ed25519") if entry else None

    def all_pins(self) -> dict[str, str]:
        """peer_id -> pinned Ed25519 hex (the X25519 pin is internal)."""
        return {pid: (e.get("ed25519") or "") for pid, e in self._pins.items()}

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
            # Migrate the legacy flat format {peer_id: ed25519_hex} to the
            # current {peer_id: {"ed25519": ..., "x25519": ...}} shape.
            normalized: dict[str, dict[str, str | None]] = {}
            for pid, val in pins.items():
                if isinstance(val, str):
                    normalized[pid] = {"ed25519": val, "x25519": None}
                    upgrade = True
                elif isinstance(val, dict) and val.get("ed25519"):
                    normalized[pid] = {"ed25519": val.get("ed25519"),
                                       "x25519": val.get("x25519")}
                else:
                    raise ValueError(f"malformed pin entry for {pid}")
            self._pins = normalized
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
