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
