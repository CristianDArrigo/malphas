"""
BIP39 mnemonics.

`root_to_mnemonic` / `mnemonic_to_root` (24 words, 256 bits) back up the
random identity ROOT and are the current identity backup (see
identity_store). `salt_to_mnemonic` / `mnemonic_to_salt` (12 words, 128
bits) are generic BIP39 helpers kept for the legacy/test salt path; they do
NOT back up a production identity. The mnemonic is never the passphrase.

The encoding is the standard English BIP39, so a mnemonic produced
here can also be read by any other BIP39 tool, and vice versa.

Backed by the `mnemonic>=0.20` PyPI package (Trezor's
python-mnemonic). Wordlist + checksum live there.
"""

from __future__ import annotations

from mnemonic import Mnemonic

_LANG = "english"
_SALT_LEN = 16
_WORD_COUNT = 12
_ROOT_LEN = 32
_ROOT_WORD_COUNT = 24


def root_to_mnemonic(root: bytes) -> str:
    """Encode a 32-byte identity root as a 24-word BIP39 mnemonic.

    Raises ValueError if `root` is not exactly 32 bytes.
    """
    if len(root) != _ROOT_LEN:
        raise ValueError(
            f"root must be exactly {_ROOT_LEN} bytes for a "
            f"{_ROOT_WORD_COUNT}-word mnemonic, got {len(root)} bytes"
        )
    return str(Mnemonic(_LANG).to_mnemonic(root))


def mnemonic_to_root(words: str) -> bytes:
    """Decode a 24-word BIP39 mnemonic back to a 32-byte identity root.

    Raises ValueError on wrong word count (must be 24), unknown words, or a
    failed checksum.
    """
    cleaned = " ".join(words.split())
    actual = len(cleaned.split())
    if actual != _ROOT_WORD_COUNT:
        raise ValueError(f"expected {_ROOT_WORD_COUNT} words, got {actual}")

    m = Mnemonic(_LANG)
    if not m.check(cleaned):
        raise ValueError(
            "invalid BIP39 mnemonic: checksum failed (one or more words "
            "are mistyped, mis-ordered, or not in the English wordlist)"
        )
    root = m.to_entropy(cleaned)
    if len(root) != _ROOT_LEN:
        raise ValueError(
            f"decoded entropy is {len(root)} bytes, expected {_ROOT_LEN}"
        )
    return bytes(root)


def salt_to_mnemonic(salt: bytes) -> str:
    """Encode a 16-byte salt as a 12-word BIP39 mnemonic.

    Raises ValueError if `salt` is not exactly 16 bytes.
    """
    if len(salt) != _SALT_LEN:
        raise ValueError(
            f"salt must be exactly {_SALT_LEN} bytes for a {_WORD_COUNT}-word "
            f"mnemonic, got {len(salt)} bytes"
        )
    return str(Mnemonic(_LANG).to_mnemonic(salt))


def mnemonic_to_salt(words: str) -> bytes:
    """Decode a 12-word BIP39 mnemonic back to a 16-byte salt.

    Raises ValueError on:
      - wrong word count (must be 12)
      - any word not in the BIP39 English wordlist
      - failed checksum (one or more words mistyped)
    """
    cleaned = " ".join(words.split())  # collapse whitespace
    actual = len(cleaned.split())
    if actual != _WORD_COUNT:
        raise ValueError(
            f"expected {_WORD_COUNT} words, got {actual}"
        )

    m = Mnemonic(_LANG)
    if not m.check(cleaned):
        raise ValueError(
            "invalid BIP39 mnemonic: checksum failed (one or more words "
            "are mistyped, mis-ordered, or not in the English wordlist)"
        )
    salt = m.to_entropy(cleaned)
    if len(salt) != _SALT_LEN:
        raise ValueError(
            f"decoded entropy is {len(salt)} bytes, expected {_SALT_LEN}"
        )
    return bytes(salt)
