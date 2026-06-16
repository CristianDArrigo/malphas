"""
File transfer (chunked, in-memory).

Layered on top of the regular onion-encrypted message pipeline so that
the wire format additions are minimal: three new `kind` values inside
the existing JSON payload — `file_offer`, `file_chunk`, `file_ack`.

Constraints (deliberately tight, in line with the zero-disk policy):

- Files are buffered entirely in RAM on both sender (read once) and
  receiver (until /savefile is invoked). Cap at MAX_FILE_BYTES.
- Integrity is verified via SHA-256 of the assembled stream against the
  hash announced in the offer.
- Chunk delivery is order-independent and idempotent (dedup by index).
- A receiver can `cancel()` an in-progress file to free memory.

The module is pure (no I/O beyond reading the source path on the sender);
network glue lives in `MalphasNode`.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

CHUNK_SIZE = 32 * 1024              # 32 KB
MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB
# Upper bound on a single offered chunk size. The sender uses CHUNK_SIZE;
# a receiver must refuse an offer (or chunk) that claims a wildly larger
# per-chunk size, otherwise `chunk_count` small + `chunk_size` huge slips
# past the MAX_FILE_BYTES check while still buffering gigabytes.
MAX_CHUNK_SIZE = 1 * 1024 * 1024    # 1 MB
MAX_NAME_LEN = 255


def _sanitize_name(name: object) -> str:
    """Reduce an attacker-supplied file name to a safe basename.

    The name in a remote offer is untrusted: it can contain path
    separators (traversal), control / bidi-override characters (UI
    spoofing, log injection), or be absurdly long. We strip it to a bare
    basename of printable, separator-free characters. The result is only a
    display/suggestion hint — consumers must still choose their own save
    path — but this removes the sharpest edges at ingestion.
    """
    raw = str(name).replace("\\", "/").split("/")[-1]
    cleaned = "".join(
        ch for ch in raw
        if ch.isprintable() and ch not in '\\/' and ord(ch) >= 0x20
    )
    cleaned = cleaned.strip().lstrip(".")
    return cleaned[:MAX_NAME_LEN] or "file.bin"


@dataclass(frozen=True)
class FileOffer:
    file_id: str
    name: str
    size: int
    sha256: str
    chunk_size: int
    chunk_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> FileOffer:
        return FileOffer(
            file_id=d["file_id"],
            name=_sanitize_name(d["name"]),
            size=int(d["size"]),
            sha256=d["sha256"],
            chunk_size=int(d["chunk_size"]),
            chunk_count=int(d["chunk_count"]),
        )


def _new_file_id() -> str:
    return secrets.token_hex(16)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(64 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class OutgoingFile:
    """Sender-side handle. Computes offer + iterates chunks lazily."""

    def __init__(self, path: str, *, chunk_size: int = CHUNK_SIZE) -> None:
        size = os.path.getsize(path)
        if size <= 0:
            raise ValueError("Empty or missing file")
        if size > MAX_FILE_BYTES:
            raise ValueError(
                f"File too large: {size} bytes > {MAX_FILE_BYTES} cap"
            )
        self._path = path
        self._chunk_size = chunk_size
        self._size = size
        self._sha256 = _sha256_file(path)
        self._file_id = _new_file_id()
        # ceil division for chunk count
        self._chunk_count = (size + chunk_size - 1) // chunk_size

    @property
    def file_id(self) -> str:
        return self._file_id

    def offer(self) -> FileOffer:
        return FileOffer(
            file_id=self._file_id,
            name=os.path.basename(self._path),
            size=self._size,
            sha256=self._sha256,
            chunk_size=self._chunk_size,
            chunk_count=self._chunk_count,
        )

    def chunkify(self) -> Iterator[tuple[int, bytes]]:
        """Yield (index, bytes) pairs in order. Reads file fresh each call."""
        with open(self._path, "rb") as f:
            idx = 0
            while True:
                data = f.read(self._chunk_size)
                if not data:
                    break
                yield idx, data
                idx += 1


class IncomingFile:
    """Receiver-side buffer. Accepts chunks; assembles + verifies on demand."""

    def __init__(self, offer: FileOffer) -> None:
        if offer.size <= 0 or offer.size > MAX_FILE_BYTES:
            raise ValueError(
                f"Offered file size out of range: {offer.size} "
                f"(must be 1..{MAX_FILE_BYTES})"
            )
        if offer.chunk_size <= 0 or offer.chunk_size > MAX_CHUNK_SIZE:
            raise ValueError(
                f"Offered chunk_size out of range: {offer.chunk_size} "
                f"(must be 1..{MAX_CHUNK_SIZE})"
            )
        # chunk_count must be exactly what `size`/`chunk_size` implies.
        # This makes total buffered bytes provably <= size <= cap and
        # rejects the "small size, huge chunk_count" amplification offer.
        expected = (offer.size + offer.chunk_size - 1) // offer.chunk_size
        if offer.chunk_count != expected:
            raise ValueError(
                f"Inconsistent chunk_count {offer.chunk_count} "
                f"(expected {expected} for size={offer.size}, "
                f"chunk_size={offer.chunk_size})"
            )
        self._offer = offer
        self._chunks: dict[int, bytes] = {}
        self._bytes = 0
        self._cancelled = False

    @property
    def offer(self) -> FileOffer:
        return self._offer

    def add_chunk(self, idx: int, data: bytes) -> bool:
        """Insert a chunk (dedup by idx). Returns True if file is now complete."""
        if self._cancelled:
            return False
        if idx < 0 or idx >= self._offer.chunk_count:
            return False
        # Per-chunk size bound: no chunk may exceed the offered chunk_size.
        if len(data) > self._offer.chunk_size:
            return False
        # Running-total bound: never buffer more than the offered (and
        # already cap-checked) total size. Accounts for idempotent
        # re-inserts of the same index.
        prev = self._chunks.get(idx)
        new_total = self._bytes - (len(prev) if prev is not None else 0) + len(data)
        if new_total > self._offer.size:
            return False
        # Idempotent: reject re-insert with different bytes silently — the
        # sender re-sent the same chunk, no harm done.
        self._chunks[idx] = data
        self._bytes = new_total
        return self.is_complete()

    def is_complete(self) -> bool:
        return (
            not self._cancelled
            and len(self._chunks) == self._offer.chunk_count
        )

    def received_indices(self) -> list[int]:
        """Return the list of chunk indices the receiver already holds.

        Used by the v0.8.0 resume protocol: the receiver sends this
        list back to the sender so the sender can skip already-
        delivered chunks.
        """
        return sorted(self._chunks.keys())

    def progress(self) -> float:
        if self._offer.chunk_count == 0:
            return 1.0
        return len(self._chunks) / float(self._offer.chunk_count)

    def assemble(self) -> bytes:
        """Concatenate ordered chunks, verify SHA-256, return the stream."""
        if self._cancelled:
            raise ValueError("Transfer was cancelled")
        if not self.is_complete():
            raise ValueError("File not yet complete")
        ordered = b"".join(self._chunks[i] for i in range(self._offer.chunk_count))
        # Constant-time compare. The hash isn't a secret, but a
        # timing oracle on the integrity check is exactly the kind of
        # thing TM-05 calls out — better to leave nothing on the table.
        import hmac as _hmac
        if not _hmac.compare_digest(
                hashlib.sha256(ordered).hexdigest(),
                self._offer.sha256):
            raise ValueError("SHA-256 mismatch — file corrupted or tampered")
        if len(ordered) != self._offer.size:
            raise ValueError(
                f"Size mismatch: got {len(ordered)} bytes, expected {self._offer.size}"
            )
        return ordered

    def cancel(self) -> None:
        self._cancelled = True
        self._chunks.clear()


class FileTransferManager:
    """Per-node registry for in-flight transfers."""

    def __init__(self, max_concurrent: int = 8) -> None:
        self._max = max_concurrent
        self._outgoing: dict[str, OutgoingFile] = {}
        self._incoming: dict[str, IncomingFile] = {}

    # ── Outgoing ──────────────────────────────────────────────────────────────

    def register_outgoing(self, of: OutgoingFile) -> str:
        self._outgoing[of.file_id] = of
        return of.file_id

    def get_outgoing(self, file_id: str) -> OutgoingFile | None:
        return self._outgoing.get(file_id)

    # ── Incoming ──────────────────────────────────────────────────────────────

    def register_incoming(self, offer: FileOffer) -> IncomingFile:
        # Enforce the concurrency cap (was declared but never checked): each
        # IncomingFile buffers up to MAX_FILE_BYTES, so an unbounded number of
        # concurrent offers is a memory-exhaustion vector. Re-registering an
        # already-tracked file_id is allowed (resume), and doesn't count.
        if (offer.file_id not in self._incoming
                and len(self._incoming) >= self._max):
            raise ValueError(
                f"too many concurrent incoming transfers (cap={self._max})")
        ic = IncomingFile(offer)
        self._incoming[offer.file_id] = ic
        return ic

    def get_incoming(self, file_id: str) -> IncomingFile | None:
        return self._incoming.get(file_id)

    def drop_incoming(self, file_id: str) -> None:
        self._incoming.pop(file_id, None)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def cancel(self, file_id: str) -> None:
        ic = self._incoming.pop(file_id, None)
        if ic is not None:
            ic.cancel()
        self._outgoing.pop(file_id, None)

    def wipe(self) -> None:
        for ic in self._incoming.values():
            ic.cancel()
        self._incoming.clear()
        self._outgoing.clear()
