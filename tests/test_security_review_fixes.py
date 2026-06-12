"""
Regression tests for the 2026 security review fixes.

Each test pins the behaviour of one fix so the hole cannot silently
reopen. IDs (C1, C2, H1...) match the review write-up.
"""

import asyncio
import dataclasses

import pytest

from malphas.identity import create_identity
from malphas.node import MalphasNode

# ── C1: Double Ratchet skip-message DoS ──────────────────────────────────────

class TestC1RatchetSkipBound:
    def _pair(self):
        from malphas.crypto import generate_ephemeral_keypair
        from malphas.ratchet import RatchetState
        shared = b"\x11" * 32
        b_priv, b_pub = generate_ephemeral_keypair()
        a = RatchetState.from_shared_secret(shared, b_priv, b_pub, is_initiator=True)
        b = RatchetState.from_shared_secret(shared, b_priv, b_pub, is_initiator=False)
        return a, b

    def test_skip_beyond_max_raises_fast(self):
        from malphas.ratchet import MAX_SKIP, MessageHeader
        a, b = self._pair()
        h, c = a.encrypt(b"hi")
        # Forge a header that asks the receiver to skip far more than
        # MAX_SKIP messages in one go. Pre-fix this looped ~msg_num times
        # (attacker-controlled uint32) pinning the CPU; now it must raise.
        forged = MessageHeader(dh_pub=h.dh_pub, prev_count=0, msg_num=MAX_SKIP + 50_000)
        with pytest.raises(ValueError):
            b.decrypt(forged, c)

    def test_skip_within_limit_still_works(self):
        # Losing a handful of messages must still decrypt later ones.
        a, b = self._pair()
        msgs = [a.encrypt(f"m{i}".encode()) for i in range(10)]
        pt = b.decrypt(msgs[9][0], msgs[9][1])   # skips 0..8
        assert pt == b"m9"


# ── C2: unbounded frame length → OOM ─────────────────────────────────────────

class TestC2FrameCap:
    async def _conn(self, length_field: int):
        import struct

        from malphas.node import HEADER_LEN, PeerConnection
        reader = asyncio.StreamReader()
        # type byte + 4-byte length; no body needed (cap check is first)
        reader.feed_data(struct.pack(">BI", 0x03, length_field))
        reader.feed_eof()
        return PeerConnection(reader, _DummyWriter())

    async def test_oversized_frame_rejected(self):
        conn = await self._conn(0xFFFFFFFF)   # ~4 GiB
        with pytest.raises(ConnectionError):
            await conn.recv_raw()

    async def test_normal_frame_accepted(self):
        import struct

        from malphas.node import PeerConnection
        reader = asyncio.StreamReader()
        body = b"hello"
        reader.feed_data(struct.pack(">BI", 0x03, len(body)) + body)
        reader.feed_eof()
        conn = PeerConnection(reader, _DummyWriter())
        mtype, payload = await conn.recv_raw()
        assert payload == body


class _DummyWriter:
    def close(self): pass
    def get_extra_info(self, *_a, **_k): return ("127.0.0.1", 0)


# ── H1: file-chunk buffer amplification ──────────────────────────────────────

class TestH1FileChunkBound:
    def _offer(self, **over):
        from malphas.files import FileOffer
        base = dict(file_id="a" * 32, name="f.bin", size=64,
                    sha256="0" * 64, chunk_size=32, chunk_count=2)
        base.update(over)
        return FileOffer(**base)

    def test_inconsistent_chunk_count_rejected(self):
        from malphas.files import IncomingFile
        # size=1 but chunk_count=100000 was the amplification offer.
        with pytest.raises(ValueError):
            IncomingFile(self._offer(size=1, chunk_size=32, chunk_count=100_000))

    def test_oversize_total_rejected(self):
        from malphas.files import MAX_FILE_BYTES, IncomingFile
        with pytest.raises(ValueError):
            IncomingFile(self._offer(size=MAX_FILE_BYTES + 1,
                                     chunk_size=1024,
                                     chunk_count=(MAX_FILE_BYTES + 1024) // 1024))

    def test_chunk_larger_than_declared_rejected(self):
        from malphas.files import IncomingFile
        ic = IncomingFile(self._offer())   # chunk_size=32
        assert ic.add_chunk(0, b"x" * 33) is False     # > chunk_size
        assert ic.add_chunk(0, b"x" * 32) is False     # ok size, not complete yet

    def test_running_total_cannot_exceed_size(self):
        from malphas.files import IncomingFile
        ic = IncomingFile(self._offer(size=40, chunk_size=32, chunk_count=2))
        assert ic.add_chunk(0, b"x" * 32) is False
        # second chunk would push total to 64 > size 40 → rejected
        assert ic.add_chunk(1, b"x" * 32) is False


# ── M8: filename sanitisation at ingestion ───────────────────────────────────

class TestM8FilenameSanitize:
    def test_traversal_and_control_stripped(self):
        from malphas.files import _sanitize_name
        assert _sanitize_name("../../etc/passwd") == "passwd"
        assert _sanitize_name("a/b\\c.txt") == "c.txt"
        assert "\x00" not in _sanitize_name("ev\x00il.bin")
        assert _sanitize_name("") == "file.bin"
        assert len(_sanitize_name("x" * 9999)) <= 255

    def test_from_dict_sanitizes(self):
        from malphas.files import FileOffer
        o = FileOffer.from_dict(dict(
            file_id="a" * 32, name="../../secret", size=10,
            sha256="0" * 64, chunk_size=32, chunk_count=1))
        assert "/" not in o.name and o.name == "secret"


# ── H3: forged read receipts ─────────────────────────────────────────────────

class TestH3ReceiptBinding:
    def _setup(self):
        from malphas.receipts import ReceiptTracker, sign_receipt
        dest = create_identity("dest")
        other = create_identity("other")
        tr = ReceiptTracker()
        pr = tr.track("msg-1", b"\x07" * 16, dest.peer_id, "hi")
        return tr, dest, other, pr

    def test_receipt_from_wrong_peer_rejected(self):
        from malphas.receipts import sign_receipt
        tr, dest, other, pr = self._setup()
        # `other` signs the challenge and tries to confirm a message that
        # was sent to `dest`. Must be rejected on the from_peer_id binding.
        sig = sign_receipt("msg-1", pr.nonce, other.ed25519_priv)
        ok = tr.resolve("msg-1", sig, other.ed25519_pub, from_peer_id=other.peer_id)
        assert ok is False

    def test_receipt_from_real_dest_accepted(self):
        from malphas.receipts import sign_receipt
        tr, dest, other, pr = self._setup()
        sig = sign_receipt("msg-1", pr.nonce, dest.ed25519_priv)
        ok = tr.resolve("msg-1", sig, dest.ed25519_pub, from_peer_id=dest.peer_id)
        assert ok is True


# ── H6: pin store corruption handling + AAD ──────────────────────────────────

class TestH6PinStore:
    def test_roundtrip(self, tmp_path):
        from malphas.pinstore import PinStore
        key = b"\x02" * 32
        p = str(tmp_path / "pins")
        a = create_identity("a")
        ps = PinStore(p, key)
        ps.check_and_pin(a.peer_id, a.ed25519_pub_bytes)
        ps2 = PinStore(p, key)
        assert ps2.load() is True
        assert ps2.get_pin(a.peer_id) == a.ed25519_pub_bytes.hex()

    def test_corrupt_file_raises_not_silent(self, tmp_path):
        from malphas.pinstore import PinStore, PinStoreCorruptError
        p = tmp_path / "pins"
        p.write_bytes(b"not a valid encrypted pin file at all, definitely")
        ps = PinStore(str(p), b"\x03" * 32)
        with pytest.raises(PinStoreCorruptError):
            ps.load()

    def test_missing_file_is_not_corrupt(self, tmp_path):
        from malphas.pinstore import PinStore
        ps = PinStore(str(tmp_path / "nope"), b"\x03" * 32)
        assert ps.load() is False   # legit first run


# ── M6: address book / pin store domain separation ───────────────────────────

class TestM6DomainSeparation:
    def test_pin_file_cannot_load_as_addressbook(self, tmp_path):
        from malphas.addressbook import AddressBook
        from malphas.pinstore import PinStore
        key = b"\x04" * 32
        a = create_identity("a")
        # Write a pin file (AAD = pinstore) ...
        pin_path = tmp_path / "shared"
        ps = PinStore(str(pin_path), key)
        ps.check_and_pin(a.peer_id, a.ed25519_pub_bytes)
        # ... then try to open the SAME bytes as an address book with the
        # SAME key. Distinct AAD must make this fail authentication.
        book = AddressBook(str(pin_path), key)
        with pytest.raises(ValueError):
            book.load()


# ── H7: invite expiry ────────────────────────────────────────────────────────

class TestH7InviteExpiry:
    def test_valid_invite_parses(self):
        from malphas.invite import generate_invite, parse_invite
        idn = create_identity("inv")
        url = generate_invite(idn, "10.0.0.1", 8000)
        data = parse_invite(url)
        assert data["peer_id"] == idn.peer_id
        assert "exp" in data

    def test_expired_invite_rejected(self):
        from malphas.invite import generate_invite, parse_invite
        idn = create_identity("inv")
        url = generate_invite(idn, "10.0.0.1", 8000, ttl_seconds=-1)  # already expired
        with pytest.raises(ValueError):
            parse_invite(url)


# ── L: onion-address version byte ────────────────────────────────────────────

class TestOnionVersionByte:
    def test_non_v3_rejected(self):
        import base64
        import hashlib

        from malphas.transport import onion_to_ed25519_pub
        pub = b"\x09" * 32
        version = b"\x04"   # not v3
        checksum = hashlib.sha3_256(b".onion checksum" + pub + version).digest()[:2]
        raw = pub + checksum + version
        addr = base64.b32encode(raw).decode().lower() + ".onion"
        with pytest.raises(ValueError):
            onion_to_ed25519_pub(addr)


# ── C3 + H2: identity binding (integration with real nodes) ──────────────────

async def _connect(a: MalphasNode, b: MalphasNode, id_b):
    return await a.connect_to_peer(
        "127.0.0.1", b.port, id_b.peer_id,
        id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
    )


class TestIdentityBinding:
    async def test_c3_ratchet_sender_spoof_dropped(
        self, node_a, node_b, identity_a, identity_b, identity_c, monkeypatch
    ):
        # b is connected to a and shares a ratchet. b crafts a message whose
        # SEALED `from` is c (a peer a knows but isn't connected to). a must
        # drop it: the ratchet only proves "b sent this", and the sealed
        # from is attacker-chosen, so from_id must match the session peer.
        ok = await _connect(node_a, node_b, identity_b)
        assert ok is True
        # a knows c (so get_peer(c) would succeed — proves the drop is the
        # binding check, not merely "unknown sender").
        node_a.discovery.add_peer(
            identity_c.peer_id, "127.0.0.1", 9, identity_c.x25519_pub_bytes,
            identity_c.ed25519_pub_bytes)

        received: list = []
        node_a.on_message(lambda frm, content: received.append((frm, content)))

        import malphas.node as nodemod
        real_seal = nodemod.seal_from
        monkeypatch.setattr(
            nodemod, "seal_from",
            lambda _real_from, dest_pub: real_seal(identity_c.peer_id, dest_pub),
        )

        await node_b.send_message(identity_a.peer_id, "spoofed-from-c")
        await asyncio.sleep(0.3)
        assert received == [], f"spoofed message was delivered: {received}"

    async def test_h2_handshake_rejects_peer_id_key_mismatch(
        self, node_a, identity_b
    ):
        # Stand up a node that LIES about its peer_id (claims a peer_id that
        # is not BLAKE2s(its ed25519_pub)). The handshake must reject it.
        liar_identity = dataclasses.replace(identity_b, peer_id="0" * 40)
        liar = MalphasNode(liar_identity, host="127.0.0.1", port=17786,
                           cover_traffic=False)
        await liar.start()
        try:
            ok = await node_a.connect_to_peer(
                "127.0.0.1", 17786, liar_identity.peer_id,
                liar_identity.x25519_pub_bytes, liar_identity.ed25519_pub_bytes,
            )
            assert ok is False
        finally:
            await liar.stop()
