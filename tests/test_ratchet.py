"""
Tests for Double Ratchet implementation.
"""
import os
import pytest
from malphas.crypto import kdf_chain


class TestKDFChain:
    def test_produces_new_chain_key_and_message_key(self):
        chain_key = os.urandom(32)
        new_chain_key, message_key = kdf_chain(chain_key)
        assert len(new_chain_key) == 32
        assert len(message_key) == 32
        assert new_chain_key != chain_key
        assert message_key != chain_key
        assert new_chain_key != message_key

    def test_deterministic(self):
        chain_key = os.urandom(32)
        a1, b1 = kdf_chain(chain_key)
        a2, b2 = kdf_chain(chain_key)
        assert a1 == a2
        assert b1 == b2

    def test_chain_produces_unique_keys_per_step(self):
        ck = os.urandom(32)
        message_keys = set()
        for _ in range(100):
            ck, mk = kdf_chain(ck)
            message_keys.add(mk)
        assert len(message_keys) == 100

    def test_different_input_different_output(self):
        ck1, mk1 = kdf_chain(os.urandom(32))
        ck2, mk2 = kdf_chain(os.urandom(32))
        assert ck1 != ck2
        assert mk1 != mk2


from malphas.ratchet import RatchetState


class TestRatchetState:
    def _make_pair(self):
        from malphas.crypto import generate_ephemeral_keypair, ecdh_shared_secret
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(priv_a, pub_b)
        state_a = RatchetState.from_shared_secret(shared, priv_a, pub_b, is_initiator=True)
        state_b = RatchetState.from_shared_secret(shared, priv_b, pub_a, is_initiator=False)
        return state_a, state_b

    def test_single_message(self):
        a, b = self._make_pair()
        header, ciphertext = a.encrypt(b"hello")
        plaintext = b.decrypt(header, ciphertext)
        assert plaintext == b"hello"

    def test_multiple_messages_same_direction(self):
        a, b = self._make_pair()
        for i in range(10):
            msg = f"message {i}".encode()
            header, ct = a.encrypt(msg)
            pt = b.decrypt(header, ct)
            assert pt == msg

    def test_bidirectional(self):
        a, b = self._make_pair()
        h1, c1 = a.encrypt(b"from A")
        assert b.decrypt(h1, c1) == b"from A"
        h2, c2 = b.encrypt(b"from B")
        assert a.decrypt(h2, c2) == b"from B"
        h3, c3 = a.encrypt(b"A again")
        assert b.decrypt(h3, c3) == b"A again"

    def test_each_message_different_ciphertext(self):
        a, b = self._make_pair()
        _, c1 = a.encrypt(b"same")
        _, c2 = a.encrypt(b"same")
        assert c1 != c2

    def test_out_of_order_messages(self):
        a, b = self._make_pair()
        h1, c1 = a.encrypt(b"first")
        h2, c2 = a.encrypt(b"second")
        h3, c3 = a.encrypt(b"third")
        assert b.decrypt(h3, c3) == b"third"
        assert b.decrypt(h1, c1) == b"first"
        assert b.decrypt(h2, c2) == b"second"

    def test_replay_rejected(self):
        a, b = self._make_pair()
        h, c = a.encrypt(b"once")
        b.decrypt(h, c)
        with pytest.raises(ValueError):
            b.decrypt(h, c)

    def test_tampered_ciphertext_rejected(self):
        a, b = self._make_pair()
        h, c = a.encrypt(b"data")
        tampered = bytearray(c)
        tampered[10] ^= 0xFF
        with pytest.raises(ValueError):
            b.decrypt(h, bytes(tampered))

    def test_skipped_keys_bounded(self):
        a, b = self._make_pair()
        headers_cts = []
        for i in range(200):
            h, c = a.encrypt(f"msg{i}".encode())
            headers_cts.append((h, c))
        pt = b.decrypt(headers_cts[-1][0], headers_cts[-1][1])
        assert pt == b"msg199"

    def test_different_sessions_different_keys(self):
        a1, b1 = self._make_pair()
        a2, b2 = self._make_pair()
        _, c1 = a1.encrypt(b"same content")
        _, c2 = a2.encrypt(b"same content")
        assert c1 != c2
