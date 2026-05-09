"""
Best-effort RAM hygiene for sensitive material (passphrase-derived seeds,
session keys, ratchet roots, address book master keys).

What this gives you:
- A mutable byte buffer (`bytearray` under the hood) that can be
  overwritten in place with zeros via `wipe()`. Crucially this is what
  immutable `bytes` objects cannot offer — you cannot zeroize a `bytes`
  object after the fact.
- A best-effort `mlock(2)` call on POSIX so the buffer's pages are
  pinned in RAM and not paged out to swap. If `mlock` fails (lack of
  capability, platform without the call, etc.) we degrade silently;
  this is a defense-in-depth measure, not a hard guarantee.
- Zeroization on `wipe()`, `__exit__`, and `__del__`. The compiler
  cannot dead-store-eliminate a `bytearray` in-place mutation in
  CPython, so the writes do persist until GC.

What this does NOT give you:
- Protection against an attacker with kernel access (root, ptrace,
  /proc/$pid/mem). Once that line is crossed, no userspace mitigation
  helps.
- Protection on Windows / macOS to the same level (mlock semantics
  differ; we only call libc.mlock on Linux/glibc).
- A magical guarantee that a copy made by Python (e.g. `bytes(buf)`)
  is also wiped — those copies are immutable and live until GC.

Usage:

    from .secure_buffer import SecureBytes

    seed = SecureBytes(64)            # zero-filled
    do_kdf_into(seed)
    key = derive(seed)
    seed.wipe()

    with SecureBytes.from_bytes(passphrase_bytes, wipe_source=True) as buf:
        do_argon2(buf)
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hmac as _hmac
from collections.abc import Iterator
from types import TracebackType
from typing import Any

# ── libc.mlock binding (best-effort, optional) ───────────────────────────────

_libc: ctypes.CDLL | None = None
try:
    _name = ctypes.util.find_library("c")
    if _name:
        _libc = ctypes.CDLL(_name, use_errno=True)
        # Declare the calling convention so ctypes does the right thing.
        _libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.mlock.restype = ctypes.c_int
        _libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.munlock.restype = ctypes.c_int
except Exception:
    _libc = None


def _mlock(buf: bytearray) -> bool:
    """Best-effort `mlock` on the buffer's storage. Returns True on success."""
    if _libc is None or len(buf) == 0:
        return False
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        rc: int = _libc.mlock(ctypes.cast(addr, ctypes.c_void_p), len(buf))
        return bool(rc == 0)
    except Exception:
        return False


def _munlock(buf: bytearray) -> None:
    if _libc is None or len(buf) == 0:
        return
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        _libc.munlock(ctypes.cast(addr, ctypes.c_void_p), len(buf))
    except Exception:
        pass


def _zero_in_place(buf: bytearray) -> None:
    """Overwrite every byte with zero, in place."""
    for i in range(len(buf)):
        buf[i] = 0


# ── SecureBytes ──────────────────────────────────────────────────────────────

class SecureBytes:
    """
    A wiped-on-drop, mlock'd-when-possible byte buffer for key material.
    """

    __slots__ = ("_raw", "_locked")

    def __init__(self, size: int) -> None:
        if size < 0:
            raise ValueError("size must be >= 0")
        self._raw = bytearray(size)
        self._locked = _mlock(self._raw)

    @classmethod
    def from_bytes(cls, data: Any, *, wipe_source: bool = False) -> SecureBytes:
        """
        Build a SecureBytes from `data`. `data` may be a `bytes`, a
        `bytearray`, or any buffer-protocol-compatible source.

        If `wipe_source` is True AND `data` is mutable (bytearray /
        memoryview onto a bytearray), the source is zeroized after the
        copy. Immutable `bytes` objects cannot be wiped — the call
        succeeds but the source remains intact.
        """
        view = memoryview(data)
        n = len(view)
        out = cls(n)
        out._raw[:] = view
        if wipe_source and isinstance(data, bytearray):
            _zero_in_place(data)
        return out

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Overwrite the buffer with zeros (idempotent)."""
        _zero_in_place(self._raw)

    def __enter__(self) -> SecureBytes:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            _zero_in_place(self._raw)
        except Exception:
            # Interpreter teardown can race; never raise from __del__.
            return
        if self._locked:
            try:
                _munlock(self._raw)
            except Exception:
                pass

    # ── Read accessors ─────────────────────────────────────────────────────

    def __bytes__(self) -> bytes:
        """Return an INDEPENDENT immutable copy of the current contents."""
        return bytes(self._raw)

    def __len__(self) -> int:
        return len(self._raw)

    def __iter__(self) -> Iterator[int]:
        # Iterating yields the byte values; useful for `zip(a, b)` style
        # tests on key-material divergence.
        return iter(self._raw)

    def __getitem__(self, key: int | slice) -> int | bytes:
        # Slice -> immutable bytes copy. Single int -> byte value.
        result = self._raw[key]
        if isinstance(result, int):
            return result
        return bytes(result)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, int):
            return item in self._raw
        if isinstance(item, (bytes, bytearray, memoryview)):
            return bytes(item) in bytes(self._raw)
        return False

    # ── Comparison (constant-time) ─────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecureBytes):
            return _hmac.compare_digest(bytes(self._raw), bytes(other._raw))
        if isinstance(other, (bytes, bytearray, memoryview)):
            return _hmac.compare_digest(bytes(self._raw), bytes(other))
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    def __hash__(self) -> int:
        # SecureBytes is mutable so it cannot be hashable in a meaningful
        # way; explicitly mark it as such.
        raise TypeError("SecureBytes is mutable and cannot be hashed")
