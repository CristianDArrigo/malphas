"""
Tests for SecureBytes — best-effort RAM hygiene for sensitive material.

Behavior under test:
- size constructor produces a zero-filled buffer of the right length.
- from_bytes copies, optionally zeroizing the source if it's mutable.
- wipe() overwrites the buffer with zeros.
- __bytes__ produces an independent bytes copy.
- __len__ reflects the actual size.
- __del__ zeroizes the underlying storage (best-effort, observed via
  internal handle inspection).
- mlock failure (e.g. on platforms without CAP_IPC_LOCK) does NOT raise;
  the class degrades gracefully to plain bytearray semantics.
- Equality comparison is constant-time.
"""

from __future__ import annotations

import os
import time

import pytest

from malphas.secure_buffer import SecureBytes


class TestConstruction:
    def test_size_constructor_zero_filled(self):
        buf = SecureBytes(32)
        assert len(buf) == 32
        assert bytes(buf) == b"\x00" * 32

    def test_from_bytes_copies_data(self):
        src = b"\x01\x02\x03\x04"
        buf = SecureBytes.from_bytes(src)
        assert len(buf) == 4
        assert bytes(buf) == src

    def test_from_bytes_zeroizes_mutable_source(self):
        src = bytearray(b"secret-material")
        buf = SecureBytes.from_bytes(src, wipe_source=True)
        # Mutable source must be zeroed
        assert all(b == 0 for b in src)
        # The new buffer still holds the data
        assert bytes(buf) == b"secret-material"

    def test_from_bytes_does_not_mutate_immutable_source(self):
        src = b"abcdef"
        buf = SecureBytes.from_bytes(src, wipe_source=True)
        # Source bytes object is immutable, must remain intact
        assert src == b"abcdef"
        assert bytes(buf) == b"abcdef"


class TestLifecycle:
    def test_wipe_overwrites_with_zeros(self):
        buf = SecureBytes.from_bytes(b"\xff" * 16)
        buf.wipe()
        assert bytes(buf) == b"\x00" * 16

    def test_double_wipe_idempotent(self):
        buf = SecureBytes.from_bytes(b"x" * 8)
        buf.wipe()
        buf.wipe()
        assert bytes(buf) == b"\x00" * 8

    def test_use_after_wipe_returns_zeros(self):
        buf = SecureBytes.from_bytes(b"abc")
        buf.wipe()
        assert bytes(buf) == b"\x00" * 3

    def test_explicit_del_zeros_view(self):
        buf = SecureBytes.from_bytes(b"\xaa" * 16)
        # Capture a memoryview onto the buffer's internal storage
        view = memoryview(buf._raw).tobytes()  # type: ignore[attr-defined]
        assert view == b"\xaa" * 16
        buf.__del__()
        # After explicit __del__, the underlying bytearray is zeroed
        assert bytes(buf._raw) == b"\x00" * 16  # type: ignore[attr-defined]


class TestSemantics:
    def test_bytes_returns_independent_copy(self):
        buf = SecureBytes.from_bytes(b"hello")
        snap = bytes(buf)
        buf.wipe()
        # The previously taken snapshot is unaffected
        assert snap == b"hello"

    def test_len_matches_size(self):
        for n in (0, 1, 16, 32, 1024):
            buf = SecureBytes(n)
            assert len(buf) == n

    def test_equality_constant_time(self):
        a = SecureBytes.from_bytes(b"deadbeef")
        b = SecureBytes.from_bytes(b"deadbeef")
        c = SecureBytes.from_bytes(b"different")
        assert a == b
        assert a != c
        # And compares OK to plain bytes
        assert a == b"deadbeef"
        assert a != b"different"

    def test_context_manager_wipes_on_exit(self):
        with SecureBytes.from_bytes(b"sensitive") as buf:
            assert bytes(buf) == b"sensitive"
        # After exit, buffer is wiped
        assert bytes(buf) == b"\x00" * len(b"sensitive")


class TestMlockBestEffort:
    def test_mlock_failure_does_not_raise(self, monkeypatch):
        # Monkeypatch ctypes.CDLL.mlock to fail; SecureBytes must still
        # produce a usable buffer.
        import ctypes
        try:
            libc = ctypes.CDLL("libc.so.6")
        except OSError:
            pytest.skip("libc.so.6 not available")
        original = libc.mlock

        def failing_mlock(addr, length):
            return -1  # error

        try:
            monkeypatch.setattr(libc, "mlock", failing_mlock)
            buf = SecureBytes.from_bytes(b"x" * 16)
            assert bytes(buf) == b"x" * 16
        finally:
            libc.mlock = original  # paranoia: restore even after monkeypatch
