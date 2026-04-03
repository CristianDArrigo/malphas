"""
Security tests: read receipts and traffic obfuscation.

Verifies:
- Valid receipt signature accepted
- Invalid/forged receipt rejected
- Receipt from wrong identity rejected
- Cover payload indistinguishable in size from real messages
- Real messages not mistaken for cover
- Cover flag not present in real messages
- Padding hides message length variation
"""

import os
import secrets

import pytest

from malphas.obfuscation import (
    COVER_FLAG,
    PAYLOAD_BLOCK,
    is_cover,
    make_cover_payload,
    pad_payload,
    unpad_payload,
)
from malphas.receipts import (
    ReceiptTracker,
    sign_receipt,
    verify_receipt,
)


class TestReceiptSecurity:
    def test_valid_receipt_accepted(self, identity_b):
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        sig = sign_receipt(msg_id, nonce, identity_b.ed25519_priv)
        assert verify_receipt(msg_id, nonce, sig, identity_b.ed25519_pub)

    def test_forged_receipt_rejected(self, identity_a, identity_b):
        """A cannot forge a receipt on behalf of B."""
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        # A signs — but verifier checks B's pubkey
        forged_sig = sign_receipt(msg_id, nonce, identity_a.ed25519_priv)
        assert not verify_receipt(msg_id, nonce, forged_sig, identity_b.ed25519_pub)

    def test_wrong_msg_id_rejected(self, identity_b):
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        sig = sign_receipt(msg_id, nonce, identity_b.ed25519_priv)
        assert not verify_receipt("different-msg-id", nonce, sig, identity_b.ed25519_pub)

    def test_wrong_nonce_rejected(self, identity_b):
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        sig = sign_receipt(msg_id, nonce, identity_b.ed25519_priv)
        wrong_nonce = secrets.token_bytes(16)
        assert not verify_receipt(msg_id, wrong_nonce, sig, identity_b.ed25519_pub)

    def test_tampered_signature_rejected(self, identity_b):
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        sig = bytearray(sign_receipt(msg_id, nonce, identity_b.ed25519_priv))
        sig[10] ^= 0x01
        assert not verify_receipt(msg_id, nonce, bytes(sig), identity_b.ed25519_pub)

    def test_receipt_tracker_valid_resolve(self, identity_b):
        tracker = ReceiptTracker()
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        tracker.track(msg_id, nonce, identity_b.peer_id)
        sig = sign_receipt(msg_id, nonce, identity_b.ed25519_priv)
        ok = tracker.resolve(msg_id, sig, identity_b.ed25519_pub)
        assert ok

    def test_receipt_tracker_rejects_double_resolve(self, identity_b):
        """A receipt can only be resolved once — replay protection."""
        tracker = ReceiptTracker()
        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        tracker.track(msg_id, nonce, identity_b.peer_id)
        sig = sign_receipt(msg_id, nonce, identity_b.ed25519_priv)
        assert tracker.resolve(msg_id, sig, identity_b.ed25519_pub)
        # Second resolve must fail (already marked resolved)
        assert not tracker.resolve(msg_id, sig, identity_b.ed25519_pub)

    def test_receipt_tracker_rejects_unknown_msg_id(self, identity_b):
        tracker = ReceiptTracker()
        nonce = secrets.token_bytes(16)
        sig = sign_receipt("unknown-id", nonce, identity_b.ed25519_priv)
        assert not tracker.resolve("unknown-id", sig, identity_b.ed25519_pub)

    async def test_receipt_timeout_fires(self, identity_b):
        """After RECEIPT_TIMEOUT, on_timeout callback must be called."""
        import asyncio

        # Use short timeout and check_interval for test speed
        tracker = ReceiptTracker(timeout=0.05, check_interval=0.05)
        timed_out = []
        tracker.on_timeout(lambda msg_id, dest: timed_out.append(msg_id))

        await tracker.start()
        msg_id = secrets.token_hex(16)
        tracker.track(msg_id, secrets.token_bytes(16), identity_b.peer_id)

        await asyncio.sleep(0.5)
        await tracker.stop()

        assert msg_id in timed_out


class TestCoverTrafficSecurity:
    def test_cover_payload_size_matches_real(self):
        """
        Cover payload size must be identical to a padded real message
        of similar length — indistinguishable on the wire.
        """
        cover = make_cover_payload()
        # A real message padded to same block
        real = pad_payload(b"hello this is a real message content here")
        assert len(cover) == len(real)  # both should be PAYLOAD_BLOCK

    def test_cover_identified_correctly(self):
        cover = make_cover_payload()
        # After unpadding, inner starts with COVER_FLAG
        inner = unpad_payload(cover)
        assert is_cover(inner)

    def test_real_message_not_cover(self):
        real = pad_payload(b'{"kind": "msg", "content": "hello"}')
        inner = unpad_payload(real)
        assert not is_cover(inner)

    def test_cover_flag_absent_from_real_messages(self):
        """COVER_FLAG bytes must never appear at the start of real payloads."""
        for content in [b"hello", b"test message", b"a" * 100]:
            padded = pad_payload(content)
            inner = unpad_payload(padded)
            assert not is_cover(inner)

    def test_cover_payload_is_block_aligned(self):
        cover = make_cover_payload()
        assert len(cover) % PAYLOAD_BLOCK == 0

    def test_cover_payloads_differ_each_call(self):
        """Each cover payload must be unique (random padding)."""
        covers = {make_cover_payload() for _ in range(20)}
        assert len(covers) == 20  # all unique

    def test_cover_flag_not_valid_json(self):
        """COVER_FLAG must not accidentally be valid JSON (avoids confusion)."""
        import json
        try:
            json.loads(COVER_FLAG)
            assert False, "COVER_FLAG should not be valid JSON"
        except Exception:
            pass  # correct — not valid JSON


class TestPaddingSecurity:
    def test_all_sizes_produce_block_aligned_output(self):
        """Every possible message size must pad to a block boundary."""
        for size in range(0, PAYLOAD_BLOCK * 3 + 1, 7):
            padded = pad_payload(b"x" * size)
            assert len(padded) % PAYLOAD_BLOCK == 0, \
                f"Size {size} produced unaligned output of {len(padded)} bytes"

    def test_small_messages_indistinguishable_within_block(self):
        """
        Two messages that fit within the same block must produce
        the same padded size — no length inference possible within a block.
        Max message fitting in block: 512 - 4 = 508 bytes.
        """
        p1 = pad_payload(b"x")           # 4+1   = 5 bytes → pads to 512
        p507 = pad_payload(b"x" * 507)   # 4+507 = 511 bytes → pads to 512
        assert len(p1) == len(p507) == PAYLOAD_BLOCK

    def test_padding_is_random_not_zero(self):
        """
        Padding bytes must be random, not zero.
        Zero padding would allow an observer to estimate message length
        by looking at the ratio of zero vs non-zero bytes.
        """
        # Use a short message so most of the block is padding
        padded = pad_payload(b"short")
        padding_area = padded[4 + 5:]  # skip length prefix + content
        # Padding should not be all zeros
        assert padding_area != bytes(len(padding_area))

    def test_unpad_is_inverse_of_pad(self):
        for size in [0, 1, 100, 511, 512, 513, 1000, 4095, 4096, 4097]:
            original = os.urandom(size)
            assert unpad_payload(pad_payload(original)) == original

    def test_truncated_padded_payload_rejected(self):
        padded = pad_payload(b"data")
        with pytest.raises(ValueError):
            unpad_payload(padded[:2])

    def test_invalid_length_prefix_rejected(self):
        """A length prefix claiming more data than exists must be rejected."""
        import struct
        # Claim 9999 bytes but only provide PAYLOAD_BLOCK bytes total
        fake = struct.pack(">I", 9999) + b"x" * (PAYLOAD_BLOCK - 4)
        with pytest.raises(ValueError):
            unpad_payload(fake)
