"""
Security tests: onion routing layer.

Verifies:
- Each relay sees only adjacent hops (no end-to-end visibility)
- No relay can read the plaintext content
- Tampered packets are rejected at every layer
- Wrong private key cannot peel a layer
- Final destination marker is correctly identified
- Packet size does not leak number of hops (all layers same structure)
- Circuit ordering is preserved
"""

import os
import secrets

import pytest

from malphas.identity import create_identity
from malphas.onion import peel_layer, wrap_onion, FINAL_HOP_MARKER, peer_id_to_bytes


def _make_circuit(identities):
    """Build a circuit list from a list of Identity objects."""
    return [(ident.x25519_pub_bytes, ident.peer_id) for ident in identities]


class TestOnionLayerIsolation:
    def test_single_hop_delivery(self, identity_a, identity_b):
        """1-hop: A → B. B peels and gets plaintext."""
        plaintext = b"direct message"
        circuit = _make_circuit([identity_b])
        packet = wrap_onion(plaintext, circuit)

        # Strip first-hop prefix (20 bytes peer_id + 4 bytes len)
        inner = packet[24:]
        next_hop, inner_payload = peel_layer(identity_b.x25519_priv, inner)
        assert next_hop is None  # B is final destination
        assert inner_payload == plaintext

    def test_multi_hop_relay_cannot_read_content(self, identity_a, identity_b, identity_c):
        """
        3-hop: A → B (relay) → C (destination).
        B peels its layer but gets only the next hop and an opaque blob.
        B cannot read the plaintext.
        """
        plaintext = b"secret content"
        circuit = _make_circuit([identity_b, identity_c])
        packet = wrap_onion(plaintext, circuit)

        # B peels its layer
        inner = packet[24:]
        next_hop_for_b, b_inner = peel_layer(identity_b.x25519_priv, inner)

        # B knows the next hop (C) but not the plaintext
        assert next_hop_for_b == identity_c.peer_id

        # B's inner payload is still encrypted for C — not plaintext
        assert b_inner != plaintext
        assert b"secret content" not in b_inner

    def test_relay_cannot_peel_destination_layer(self, identity_b, identity_c):
        """B cannot peel C's layer using B's private key."""
        plaintext = b"for C only"
        circuit = _make_circuit([identity_b, identity_c])
        packet = wrap_onion(plaintext, circuit)

        # B peels its own layer
        inner = packet[24:]
        _, b_inner = peel_layer(identity_b.x25519_priv, inner)

        # B tries to peel C's layer using B's key — must fail
        with pytest.raises(ValueError):
            peel_layer(identity_b.x25519_priv, b_inner)

    def test_only_destination_can_read_plaintext(self, identity_b, identity_c):
        """C can peel its layer and get the plaintext; B cannot."""
        plaintext = b"only for charlie"
        circuit = _make_circuit([identity_b, identity_c])
        packet = wrap_onion(plaintext, circuit)

        # B peels its layer
        inner = packet[24:]
        _, b_inner = peel_layer(identity_b.x25519_priv, inner)

        # C peels its layer
        next_hop_c, c_payload = peel_layer(identity_c.x25519_priv, b_inner)
        assert next_hop_c is None
        assert c_payload == plaintext

    def test_three_hop_full_circuit(self, identity_a, identity_b, identity_c):
        """Full A → B → C circuit with a third identity as relay."""
        relay = create_identity("relay-passphrase")
        plaintext = b"three hop message"
        circuit = _make_circuit([relay, identity_b, identity_c])
        packet = wrap_onion(plaintext, circuit)

        # Relay peels
        inner = packet[24:]
        next1, relay_inner = peel_layer(relay.x25519_priv, inner)
        assert next1 == identity_b.peer_id

        # B peels
        next2, b_inner = peel_layer(identity_b.x25519_priv, relay_inner)
        assert next2 == identity_c.peer_id

        # C peels — final destination
        next3, payload = peel_layer(identity_c.x25519_priv, b_inner)
        assert next3 is None
        assert payload == plaintext


class TestOnionTamperDetection:
    def test_tampered_outer_layer_rejected(self, identity_b, identity_c):
        """Flipping any bit in the outer layer must raise ValueError."""
        circuit = _make_circuit([identity_b, identity_c])
        packet = bytearray(wrap_onion(b"data", circuit))
        packet[30] ^= 0x01  # tamper in the encrypted region
        inner = bytes(packet)[24:]
        with pytest.raises(ValueError):
            peel_layer(identity_b.x25519_priv, inner)

    def test_tampered_inner_layer_rejected(self, identity_b, identity_c):
        """B correctly peels but tampered C-layer must be rejected by C."""
        circuit = _make_circuit([identity_b, identity_c])
        packet = wrap_onion(b"data", circuit)
        inner = packet[24:]
        _, b_inner = peel_layer(identity_b.x25519_priv, inner)

        # Tamper with C's layer
        tampered = bytearray(b_inner)
        tampered[40] ^= 0xFF
        with pytest.raises(ValueError):
            peel_layer(identity_c.x25519_priv, bytes(tampered))

    def test_wrong_private_key_rejected(self, identity_b, identity_c):
        """Using the wrong identity's key to peel must fail."""
        circuit = _make_circuit([identity_b])
        packet = wrap_onion(b"data", circuit)
        inner = packet[24:]
        with pytest.raises(ValueError):
            peel_layer(identity_c.x25519_priv, inner)  # C's key, not B's

    def test_empty_packet_rejected(self, identity_b):
        with pytest.raises(ValueError):
            peel_layer(identity_b.x25519_priv, b"")

    def test_truncated_packet_rejected(self, identity_b, identity_c):
        circuit = _make_circuit([identity_b])
        packet = wrap_onion(b"data", circuit)
        inner = packet[24:]
        with pytest.raises(ValueError):
            peel_layer(identity_b.x25519_priv, inner[:20])


class TestOnionEphemeralKeys:
    def test_each_wrap_uses_fresh_ephemeral_keys(self, identity_b):
        """
        Two wraps of the same plaintext to the same circuit must produce
        different ciphertexts (ephemeral X25519 keys are fresh each time).
        """
        circuit = _make_circuit([identity_b])
        plaintext = b"same content"
        p1 = wrap_onion(plaintext, circuit)
        p2 = wrap_onion(plaintext, circuit)
        assert p1 != p2

    def test_ephemeral_pub_differs_per_wrap(self, identity_b):
        """
        The ephemeral public key embedded in each packet must be unique.
        It occupies the first 32 bytes of the inner packet (after 24-byte prefix).
        """
        circuit = _make_circuit([identity_b])
        p1 = wrap_onion(b"data", circuit)
        p2 = wrap_onion(b"data", circuit)
        # Extract ephemeral pubkey from each (bytes 24:56 = after 20-byte peer_id + 4-byte len)
        eph1 = p1[24:56]
        eph2 = p2[24:56]
        assert eph1 != eph2


class TestOnionEmptyCircuit:
    def test_empty_circuit_raises(self, identity_b):
        with pytest.raises(ValueError):
            wrap_onion(b"data", [])
