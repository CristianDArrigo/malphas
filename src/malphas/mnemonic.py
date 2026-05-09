"""
BIP39 12-word mnemonic for the per-user salt.

Phase 2 (v0.7.0) introduced a 16-byte random salt at
`~/.malphas/salt`. Lose that file and the same passphrase produces a
fresh identity — every previously-paired contact becomes unreachable.

12 BIP39 words encode exactly 128 bits of entropy + 4 bits of
checksum, which lines up with our 16-byte salt. The mnemonic is
therefore a human-recordable backup of the salt material, nothing
more. It is **not** the passphrase — that one stays a free-form
string chosen and memorized by the user.

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


def salt_to_mnemonic(salt: bytes) -> str:
    """Encode a 16-byte salt as a 12-word BIP39 mnemonic.

    Raises ValueError if `salt` is not exactly 16 bytes.
    """
    if len(salt) != _SALT_LEN:
        raise ValueError(
            f"salt must be exactly {_SALT_LEN} bytes for a {_WORD_COUNT}-word "
            f"mnemonic, got {len(salt)} bytes"
        )
    return Mnemonic(_LANG).to_mnemonic(salt)


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
            "invalid BIP39 mnemonic — checksum failed (one or more words "
            "are mistyped, mis-ordered, or not in the English wordlist)"
        )
    salt = m.to_entropy(cleaned)
    if len(salt) != _SALT_LEN:
        raise ValueError(
            f"decoded entropy is {len(salt)} bytes, expected {_SALT_LEN}"
        )
    return bytes(salt)
