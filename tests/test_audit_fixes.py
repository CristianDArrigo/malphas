"""Regression tests for the pre-1.0.0 independent security-audit fixes.

Covers the unit-testable invariants introduced by the audit pass: x25519 key
pinning, the file-transfer concurrency cap, invite peer_id binding, ratchet
header authentication, and address-book file permissions.
"""

from __future__ import annotations

import base64
import json
import os
import stat

import pytest

from malphas.identity import create_identity_with_book_key

# ── PinStore: x25519 pinned alongside ed25519 (sealed-sender redirect MITM) ──

class TestPinStoreX25519:
    def test_pins_and_rejects_swapped_x25519(self):
        from malphas.pinstore import PinStore
        ps = PinStore()
        ed, x = b"\x01" * 32, b"\x02" * 32
        ok, _ = ps.check_and_pin("peer", ed, x)
        assert ok is True
        # same identity key + same encryption key → accepted
        ok, _ = ps.check_and_pin("peer", ed, x)
        assert ok is True
        # same ed25519 but a DIFFERENT x25519 is the swap we must catch
        ok, _ = ps.check_and_pin("peer", ed, b"\x03" * 32)
        assert ok is False

    def test_backfills_legacy_x25519_pin(self):
        from malphas.pinstore import PinStore
        ps = PinStore()
        ed = b"\x01" * 32
        ps.check_and_pin("peer", ed)                        # legacy: x unknown
        ok, _ = ps.check_and_pin("peer", ed, b"\x02" * 32)  # back-fill
        assert ok is True
        ok, _ = ps.check_and_pin("peer", ed, b"\x03" * 32)  # now a mismatch
        assert ok is False

    def test_get_pin_still_returns_ed25519_hex(self):
        from malphas.pinstore import PinStore
        ps = PinStore()
        ed = b"\xaa" * 32
        ps.check_and_pin("peer", ed, b"\xbb" * 32)
        assert ps.get_pin("peer") == ed.hex()


# ── FileTransferManager: concurrency cap actually enforced ──

class TestFileConcurrencyCap:
    @staticmethod
    def _offer(i: int):
        from malphas.files import FileOffer
        return FileOffer(file_id=f"{i:064x}", name="x.bin", size=10,
                         sha256="0" * 64, chunk_size=32768, chunk_count=1)

    def test_cap_enforced_and_resume_exempt(self):
        from malphas.files import FileTransferManager
        m = FileTransferManager(max_concurrent=2)
        m.register_incoming(self._offer(1))
        m.register_incoming(self._offer(2))
        with pytest.raises(ValueError):
            m.register_incoming(self._offer(3))
        # re-registering an already-tracked id (a resume) must still be allowed
        m.register_incoming(self._offer(1))


# ── Invite: peer_id is bound to the signed ed25519 key ──

class TestInvitePeerIdBinding:
    def test_forged_peer_id_rejected(self):
        from malphas.invite import PREFIX, parse_invite
        ident, _ = create_identity_with_book_key("inv-forge")
        payload = {
            "type": "invite", "v": 1,
            "peer_id": "a" * 40,           # forged — not BLAKE2s(ed25519_pub)
            "x25519_pub": ident.x25519_pub_bytes.hex(),
            "ed25519_pub": ident.ed25519_pub_bytes.hex(),
            "host": "x.onion", "port": 80,
        }
        jb = json.dumps(payload).encode()
        sig = ident.sign(jb)               # a *valid* signature over the payload
        url = PREFIX + base64.urlsafe_b64encode(sig + jb).decode()
        with pytest.raises(ValueError):
            parse_invite(url)

    def test_legit_invite_still_parses(self):
        from malphas.invite import generate_invite, parse_invite
        ident, _ = create_identity_with_book_key("inv-ok")
        url = generate_invite(ident, "x.onion", 80, onion="x.onion")
        data = parse_invite(url)
        assert data["peer_id"] == ident.peer_id


# ── Ratchet: the cleartext header is authenticated as AEAD AAD ──

class TestRatchetHeaderAAD:
    @staticmethod
    def _pair():
        from malphas.crypto import ecdh_shared_secret, generate_ephemeral_keypair
        from malphas.ratchet import RatchetState
        pa, ua = generate_ephemeral_keypair()
        pb, ub = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(pa, ub)
        a = RatchetState.from_shared_secret(shared, pa, ub, is_initiator=True)
        b = RatchetState.from_shared_secret(shared, pb, ua, is_initiator=False)
        return a, b

    def test_tampered_header_rejected(self):
        from malphas.ratchet import MessageHeader
        a, b = self._pair()
        header, ct = a.encrypt(b"top secret")
        tampered = MessageHeader(dh_pub=header.dh_pub,
                                 prev_count=header.prev_count + 7,
                                 msg_num=header.msg_num)
        with pytest.raises(Exception):
            b.decrypt(tampered, ct)

    def test_untampered_still_decrypts(self):
        a, b = self._pair()
        header, ct = a.encrypt(b"hello")
        assert b.decrypt(header, ct) == b"hello"


# ── AddressBook: ciphertext written 0600 (not world-readable) ──

class TestAddressBookPerms:
    def test_book_file_is_0600(self, tmp_path):
        from malphas.addressbook import AddressBook, Contact
        _, key = create_identity_with_book_key("ab-perm")
        path = tmp_path / "book"
        ab = AddressBook(str(path), key)
        ab.load()   # initialise the (empty) store before the first save
        ab.add(Contact(label="raven", peer_id="b" * 40,
                       host="x.onion", port=80,
                       x25519_pub="aa" * 32, ed25519_pub="bb" * 32))
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600
