"""
Tests for malphas.mnemonic — BIP39 12-word salt backup.
"""

from __future__ import annotations

import secrets

import pytest

from malphas.mnemonic import mnemonic_to_salt, salt_to_mnemonic


def test_known_bip39_vector_zero_entropy():
    """16 bytes of zeros must produce the canonical BIP39 fixture."""
    salt = b"\x00" * 16
    expected = ("abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about")
    assert salt_to_mnemonic(salt) == expected


def test_roundtrip_is_identity():
    for _ in range(20):
        salt = secrets.token_bytes(16)
        words = salt_to_mnemonic(salt)
        assert mnemonic_to_salt(words) == salt


def test_word_count_is_twelve():
    salt = secrets.token_bytes(16)
    words = salt_to_mnemonic(salt).split()
    assert len(words) == 12


def test_wrong_salt_length_raises():
    with pytest.raises(ValueError):
        salt_to_mnemonic(b"too-short")
    with pytest.raises(ValueError):
        salt_to_mnemonic(b"\x00" * 32)  # would be 24-word, not what we want
    with pytest.raises(ValueError):
        salt_to_mnemonic(b"")


def test_wrong_word_count_raises():
    with pytest.raises(ValueError):
        mnemonic_to_salt("abandon abandon")  # 2 words
    # 24 words must fail (we only accept 12)
    with pytest.raises(ValueError):
        mnemonic_to_salt(" ".join(["abandon"] * 23) + " art")
    # Empty string must fail
    with pytest.raises(ValueError):
        mnemonic_to_salt("")


def test_bad_checksum_raises():
    # Replace last word — checksum no longer matches.
    bad = ("abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon abandon abandon abandon")  # last "abandon" instead of "about"
    with pytest.raises(ValueError):
        mnemonic_to_salt(bad)


def test_word_not_in_wordlist_raises():
    bad = ("abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon abandon abandon zzzzzzzz")
    with pytest.raises(ValueError):
        mnemonic_to_salt(bad)


def test_extra_whitespace_tolerated():
    salt = b"\x00" * 16
    words = "  abandon  abandon  abandon abandon  abandon abandon abandon abandon abandon abandon abandon  about  "
    assert mnemonic_to_salt(words) == salt


def test_twelve_word_count_required_exactly():
    """11 and 13 word inputs must both fail."""
    salt = b"\x01" * 16
    words = salt_to_mnemonic(salt).split()
    with pytest.raises(ValueError):
        mnemonic_to_salt(" ".join(words[:11]))
    with pytest.raises(ValueError):
        mnemonic_to_salt(" ".join(words + ["about"]))
