"""
Tests for the passphrase-wrapped random identity root (issue #6).

The identity root is a random 32-byte secret; all long-term keys derive from
it. It is stored wrapped under an Argon2id passphrase-KEK, so the passphrase
can be rotated without changing identity and there is no offline peer_id
oracle.
"""
import pytest

from malphas.identity_store import (
    create_and_store_identity,
    load_identity,
    rotate_passphrase,
)
from malphas.mnemonic import mnemonic_to_root, root_to_mnemonic


def test_wrap_unwrap_roundtrip_and_wrong_passphrase(tmp_path):
    path = str(tmp_path / "identity")
    root, idn, book_key = create_and_store_identity(path, "pass-one")
    assert len(root) == 32

    # Wrong passphrase must fail (AEAD auth), not silently return garbage.
    with pytest.raises(ValueError):
        load_identity(path, "wrong-passphrase")

    root2, idn2, book_key2 = load_identity(path, "pass-one")
    assert root2 == root
    assert idn2.peer_id == idn.peer_id
    assert book_key2 == book_key


def test_passphrase_rotation_preserves_identity(tmp_path):
    path = str(tmp_path / "identity")
    root, idn, _ = create_and_store_identity(path, "old-pass")

    rotate_passphrase(path, "old-pass", "new-pass")

    # Old passphrase no longer unwraps.
    with pytest.raises(ValueError):
        load_identity(path, "old-pass")

    # New passphrase recovers the SAME identity (root unchanged).
    root2, idn2, _ = load_identity(path, "new-pass")
    assert root2 == root
    assert idn2.peer_id == idn.peer_id


def test_root_is_independent_of_passphrase(tmp_path):
    # Two identities created with the SAME passphrase must differ (random root),
    # unlike the old deterministic-from-passphrase scheme.
    p1 = str(tmp_path / "id1")
    p2 = str(tmp_path / "id2")
    _, idn1, _ = create_and_store_identity(p1, "same-passphrase")
    _, idn2, _ = create_and_store_identity(p2, "same-passphrase")
    assert idn1.peer_id != idn2.peer_id


def test_root_mnemonic_roundtrip():
    root = bytes(range(32))
    words = root_to_mnemonic(root)
    assert len(words.split()) == 24
    assert mnemonic_to_root(words) == root


def test_restore_from_mnemonic_reproduces_identity(tmp_path):
    from malphas.identity import derive_identity_from_root

    path = str(tmp_path / "identity")
    root, idn, _ = create_and_store_identity(path, "backup-pass")
    words = root_to_mnemonic(root)

    # Simulate restore on another machine: root -> identity.
    restored = derive_identity_from_root(mnemonic_to_root(words))
    assert restored.peer_id == idn.peer_id
