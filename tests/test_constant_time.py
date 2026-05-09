"""
Constant-time compare audit (TM-05).

Sensitive byte/string comparisons across malphas should go through
`hmac.compare_digest` (or a primitive that's constant-time
internally, like PyCA's `verify()` on signatures and AEAD `decrypt`).
This module pins the audit result with two kinds of guards:

1. Behavioural — the actual sensitive code paths return the right
   answer for both match and mismatch (smoke).
2. Source-grep — the modules that historically had the issue
   (`pinstore.py`, `files.py`) literally call `compare_digest`. If
   someone refactors and removes it, this test fails.

Comparisons NOT covered (and why they don't need constant-time):

- `node._dispatch` peer_id routing: peer_id is a public 40-char
  identifier visible on the wire; comparing it in non-constant
  time leaks no secret.
- `addressbook.find_by_label`: labels are user-chosen strings, not
  secrets, and the comparison happens after the address book is
  already decrypted in memory.
- `discovery` peer_id filters: same reason — public identifiers.
- `onion.peer_id_from_bytes` final-hop marker check: comparing
  decrypted plaintext against a public sentinel value visible to
  the entity making the comparison.
- AEAD tag verification (Poly1305) and Ed25519 signature
  verification: handled inside `cryptography.hazmat`, which is
  constant-time by construction.
"""

from __future__ import annotations

import hashlib
import inspect
import secrets
from pathlib import Path

import pytest

from malphas import files as files_mod
from malphas import pinstore as pinstore_mod
from malphas.crypto import hmac_sign, hmac_verify
from malphas.files import FileOffer, IncomingFile
from malphas.pinstore import PinStore


def _session_key() -> bytes:
    return secrets.token_bytes(32)


# ── Source-grep guards ──────────────────────────────────────────────────────


def test_pinstore_uses_compare_digest():
    src = Path(pinstore_mod.__file__).read_text()
    assert "compare_digest" in src, (
        "pinstore.py must use hmac.compare_digest for the pinned-key "
        "match check (TM-05)."
    )


def test_files_uses_compare_digest():
    src = Path(files_mod.__file__).read_text()
    assert "compare_digest" in src, (
        "files.py must use hmac.compare_digest on the SHA-256 "
        "integrity check (TM-05)."
    )


# ── Behavioural smoke ───────────────────────────────────────────────────────


def test_hmac_verify_accepts_correct_tag():
    key = _session_key()
    data = b"the quick brown fox"
    tag = hmac_sign(key, data)
    assert hmac_verify(key, data, tag) is True


def test_hmac_verify_rejects_wrong_tag():
    key = _session_key()
    data = b"the quick brown fox"
    bad = b"\x00" * 32
    assert hmac_verify(key, data, bad) is False


def test_hmac_verify_uses_compare_digest_internally():
    """The crypto.hmac_verify wrapper must call compare_digest, not
    `==`. This is the only authentication path used by AUTH_HMAC."""
    src = inspect.getsource(hmac_verify)
    assert "compare_digest" in src, (
        "hmac_verify must use hmac.compare_digest (TM-05)."
    )


def test_pinstore_first_contact_pins_and_subsequent_match(tmp_path):
    pin_path = tmp_path / "pins"
    key = secrets.token_bytes(32)
    p = PinStore(str(pin_path), key)
    p.load()
    pub_a = secrets.token_bytes(32)

    ok, expected = p.check_and_pin("peer-x", pub_a)
    assert ok is True and expected is None

    # Same key on second contact: still ok.
    ok, expected = p.check_and_pin("peer-x", pub_a)
    assert ok is True and expected is None


def test_pinstore_detects_key_change(tmp_path):
    pin_path = tmp_path / "pins"
    key = secrets.token_bytes(32)
    p = PinStore(str(pin_path), key)
    p.load()
    pub_a = secrets.token_bytes(32)
    pub_b = secrets.token_bytes(32)

    p.check_and_pin("peer-x", pub_a)
    ok, expected = p.check_and_pin("peer-x", pub_b)
    assert ok is False
    assert expected == pub_a.hex()


def _make_offer(payload: bytes) -> tuple[FileOffer, list[tuple[int, bytes]]]:
    chunk_size = 32 * 1024
    chunks: list[tuple[int, bytes]] = []
    for i in range(0, len(payload), chunk_size):
        chunks.append((i // chunk_size, payload[i:i + chunk_size]))
    offer = FileOffer(
        file_id="abc",
        name="x.bin",
        size=len(payload),
        chunk_count=len(chunks),
        chunk_size=chunk_size,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    return offer, chunks


def test_files_assemble_accepts_matching_sha256():
    payload = secrets.token_bytes(32 * 1024 * 3 + 17)
    offer, chunks = _make_offer(payload)
    ic = IncomingFile(offer)
    for idx, data in chunks:
        ic.add_chunk(idx, data)
    assert ic.assemble() == payload


def test_files_assemble_rejects_mismatched_sha256():
    payload = secrets.token_bytes(32 * 1024 * 2)
    offer, chunks = _make_offer(payload)
    # Tamper the offer's claimed hash.
    offer = FileOffer(
        file_id=offer.file_id,
        name=offer.name,
        size=offer.size,
        chunk_count=offer.chunk_count,
        chunk_size=offer.chunk_size,
        sha256="0" * 64,
    )
    ic = IncomingFile(offer)
    for idx, data in chunks:
        ic.add_chunk(idx, data)
    with pytest.raises(ValueError, match="SHA-256"):
        ic.assemble()
