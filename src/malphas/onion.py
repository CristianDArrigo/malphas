"""
Onion routing layer.

Build:
  wrap_onion(message, [(relay1_x25519_pub, relay1_id), ..., (dest_x25519_pub, dest_id)])
  Each layer adds: ephemeral_pub (32) || next_hop_id (20) || encrypted_inner

Peel:
  peel_layer(my_x25519_priv, data) -> (next_hop_id | None, inner_data)

Wire format per layer:
  [ephemeral_pub: 32][next_hop_id: 20][payload_len: 4][encrypted_payload]

If next_hop_id == b'\x00' * 20: this is the final destination.
The decrypted payload at the last layer is the plaintext message.
"""

import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import (
    decrypt,
    derive_session_key,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    pack_u32,
    unpack_u32,
)

FINAL_HOP_MARKER = b"\x00" * 20  # 20 zero bytes = "deliver to me"
PEER_ID_LEN = 20  # SHA1 hex is 40 chars but we store raw 20 bytes on wire
# Actually peer_id is hex string (40 chars) but on wire we use 20 raw bytes


def peer_id_to_bytes(peer_id_hex: str) -> bytes:
    """Convert 40-char hex peer_id to 20 raw bytes."""
    return bytes.fromhex(peer_id_hex)


def peer_id_from_bytes(b: bytes) -> Optional[str]:
    """Convert 20 raw bytes to hex peer_id. None if final hop marker."""
    if b == FINAL_HOP_MARKER:
        return None
    return b.hex()


def wrap_onion(
    plaintext: bytes,
    circuit: List[Tuple[bytes, str]],  # [(x25519_pub_bytes, peer_id_hex), ...]
) -> bytes:
    """
    Build an onion-encrypted packet.
    circuit[0] = first relay (outermost layer)
    circuit[-1] = destination (innermost layer)

    Each hop can only decrypt its own layer and see the next hop.
    """
    if not circuit:
        raise ValueError("Circuit must have at least 1 hop")

    # Build from innermost (destination) to outermost (first relay)
    payload = plaintext
    next_hop_id_bytes = FINAL_HOP_MARKER  # destination marker

    for x25519_pub_bytes, _peer_id in reversed(circuit):
        eph_priv, eph_pub_bytes = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(eph_priv, x25519_pub_bytes)
        session_key = derive_session_key(
            shared, eph_pub_bytes, x25519_pub_bytes, "initiator"
        )

        # Encrypt: next_hop_id || payload
        inner = next_hop_id_bytes + pack_u32(len(payload)) + payload
        encrypted = encrypt(session_key, inner, aad=eph_pub_bytes)

        # This layer's wire format: eph_pub || len(encrypted) || encrypted
        payload = eph_pub_bytes + pack_u32(len(encrypted)) + encrypted

        # Update next_hop for the layer above (reversed, so this becomes outer)
        # The "next hop" for the layer above is the current node's peer_id
        next_hop_id_bytes = peer_id_to_bytes(_peer_id)

    # Prepend the first hop indicator (who receives this packet)
    first_hop_id = peer_id_to_bytes(circuit[0][1])
    return first_hop_id + pack_u32(len(payload)) + payload


def peel_layer(
    my_x25519_priv: X25519PrivateKey,
    data: bytes,
) -> Tuple[Optional[str], bytes]:
    """
    Peel one onion layer.

    data format: eph_pub(32) || payload_len(4) || encrypted_payload

    Returns:
      (next_hop_id, inner_payload)
      next_hop_id is None if this node is the final destination.

    Raises ValueError on decryption failure (wrong key or tampered packet).
    """
    if len(data) < 32 + 4:
        raise ValueError("Onion packet too short")

    eph_pub_bytes = data[:32]
    payload_len = unpack_u32(data[32:36])

    if len(data) < 36 + payload_len:
        raise ValueError("Onion packet truncated")

    encrypted = data[36: 36 + payload_len]

    # Derive session key
    my_pub_bytes = my_x25519_priv.public_key().public_bytes_raw()
    shared = ecdh_shared_secret(my_x25519_priv, eph_pub_bytes)
    session_key = derive_session_key(
        shared, eph_pub_bytes, my_pub_bytes, "initiator"
    )

    inner = decrypt(session_key, encrypted, aad=eph_pub_bytes)

    # Parse inner: next_hop_id(20) || inner_payload_len(4) || inner_payload
    if len(inner) < 20 + 4:
        raise ValueError("Decrypted onion layer too short")

    next_hop_raw = inner[:20]
    inner_len = unpack_u32(inner[20:24])
    inner_payload = inner[24: 24 + inner_len]

    next_hop_id = peer_id_from_bytes(next_hop_raw)
    return next_hop_id, inner_payload
