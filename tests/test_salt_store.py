"""
Tests for malphas.salt_store — the per-user Argon2 salt persistence
introduced in v0.7.0.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from malphas.salt_store import SALT_LEN, load_or_create_salt


def _tmp_path() -> Path:
    d = tempfile.mkdtemp(prefix="malphas-salt-")
    return Path(d) / ".malphas" / "salt"


def test_creates_when_missing():
    path = _tmp_path()
    assert not path.exists()
    salt = load_or_create_salt(path)
    assert len(salt) == SALT_LEN
    assert path.exists()
    assert path.read_bytes() == salt


def test_creates_parent_dir():
    path = _tmp_path()
    assert not path.parent.exists()
    load_or_create_salt(path)
    assert path.parent.is_dir()


def test_reads_existing_unchanged():
    path = _tmp_path()
    first = load_or_create_salt(path)
    second = load_or_create_salt(path)
    assert first == second
    # File contents unchanged
    assert path.read_bytes() == first


def test_two_calls_at_fresh_paths_differ():
    a = load_or_create_salt(_tmp_path())
    b = load_or_create_salt(_tmp_path())
    assert a != b  # cosmically negligible probability of collision


def test_file_mode_0600():
    path = _tmp_path()
    load_or_create_salt(path)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got 0o{mode:03o}"


def test_wrong_length_raises():
    path = _tmp_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"too-short")
    with pytest.raises(ValueError):
        load_or_create_salt(path)


def test_path_is_directory_raises():
    d = Path(tempfile.mkdtemp(prefix="malphas-salt-d-"))
    with pytest.raises(ValueError):
        load_or_create_salt(d)


def test_no_tmp_leftover():
    path = _tmp_path()
    load_or_create_salt(path)
    leftover = list(path.parent.glob("*.salt-tmp"))
    assert leftover == []
