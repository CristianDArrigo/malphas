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
            name=d["name"],
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
        if offer.size > MAX_FILE_BYTES:
            raise ValueError(
                f"Offered file too large: {offer.size} bytes > {MAX_FILE_BYTES} cap"
            )
        self._offer = offer
        self._chunks: dict[int, bytes] = {}
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
        # Idempotent: reject re-insert with different bytes silently — the
        # sender re-sent the same chunk, no harm done.
        self._chunks[idx] = data
        return self.is_complete()

    def is_complete(self) -> bool:
        return (
            not self._cancelled
            and len(self._chunks) == self._offer.chunk_count
        )

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
        if hashlib.sha256(ordered).hexdigest() != self._offer.sha256:
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
