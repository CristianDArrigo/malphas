"""
Double Ratchet implementation.

Provides per-message forward secrecy: each message is encrypted with
a unique key derived from a ratcheting KDF chain. Compromising one
message key does not expose past or future messages.

Based on the Signal Double Ratchet specification:
https://signal.org/docs/specifications/doubleratchet/

State is in-memory only (consistent with zero-disk policy).
On reconnect, a fresh ratchet is initialized from the new handshake.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .crypto import (
    decrypt,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    hkdf_derive,
    kdf_chain,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


MAX_SKIP = 100


@dataclass
class MessageHeader:
    dh_pub: bytes
    prev_count: int
    msg_num: int

    def serialize(self) -> bytes:
        import struct
        return self.dh_pub + struct.pack(">II", self.prev_count, self.msg_num)

    @staticmethod
    def deserialize(data: bytes) -> "MessageHeader":
        import struct
        dh_pub = data[:32]
        prev_count, msg_num = struct.unpack(">II", data[32:40])
        return MessageHeader(dh_pub=dh_pub, prev_count=prev_count, msg_num=msg_num)


class RatchetState:
    def __init__(self):
        self._dh_priv: Optional[X25519PrivateKey] = None
        self._dh_pub: Optional[bytes] = None
        self._remote_dh_pub: Optional[bytes] = None
        self._root_key: Optional[bytes] = None
        self._send_chain_key: Optional[bytes] = None
        self._recv_chain_key: Optional[bytes] = None
        self._send_msg_num: int = 0
        self._recv_msg_num: int = 0
        self._prev_send_count: int = 0
        self._skipped: Dict[Tuple[bytes, int], bytes] = {}

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        our_dh_priv: X25519PrivateKey,
        remote_dh_pub: bytes,
        is_initiator: bool,
    ) -> "RatchetState":
        state = cls()
        state._remote_dh_pub = remote_dh_pub
        state._root_key = hkdf_derive(
            shared_secret,
            salt=b"malphas-ratchet-root-v1",
            info=b"root-key",
            length=32,
        )

        if is_initiator:
            state._dh_priv, state._dh_pub = generate_ephemeral_keypair()
            dh_output = ecdh_shared_secret(state._dh_priv, remote_dh_pub)
            state._root_key, state._send_chain_key = _kdf_root(
                state._root_key, dh_output
            )
            state._recv_chain_key = None
        else:
            state._dh_priv = our_dh_priv
            state._dh_pub = our_dh_priv.public_key().public_bytes_raw()
            state._send_chain_key = None
            state._recv_chain_key = None

        return state

    def encrypt(self, plaintext: bytes) -> Tuple[MessageHeader, bytes]:
        if self._send_chain_key is None:
            raise RuntimeError("Sending chain not initialized")

        self._send_chain_key, message_key = kdf_chain(self._send_chain_key)
        header = MessageHeader(
            dh_pub=self._dh_pub,
            prev_count=self._prev_send_count,
            msg_num=self._send_msg_num,
        )
        self._send_msg_num += 1
        ciphertext = encrypt(message_key, plaintext)
        return header, ciphertext

    def decrypt(self, header: MessageHeader, ciphertext: bytes) -> bytes:
        skip_key = (header.dh_pub, header.msg_num)
        if skip_key in self._skipped:
            mk = self._skipped.pop(skip_key)
            return decrypt(mk, ciphertext)

        if header.dh_pub != self._remote_dh_pub:
            self._skip_messages(header.prev_count)
            self._dh_ratchet(header.dh_pub)

        self._skip_messages(header.msg_num)

        self._recv_chain_key, message_key = kdf_chain(self._recv_chain_key)
        self._recv_msg_num += 1

        return decrypt(message_key, ciphertext)

    def _dh_ratchet(self, new_remote_pub: bytes) -> None:
        self._prev_send_count = self._send_msg_num
        self._send_msg_num = 0
        self._recv_msg_num = 0
        self._remote_dh_pub = new_remote_pub

        dh_output = ecdh_shared_secret(self._dh_priv, new_remote_pub)
        self._root_key, self._recv_chain_key = _kdf_root(
            self._root_key, dh_output
        )

        self._dh_priv, self._dh_pub = generate_ephemeral_keypair()

        dh_output = ecdh_shared_secret(self._dh_priv, new_remote_pub)
        self._root_key, self._send_chain_key = _kdf_root(
            self._root_key, dh_output
        )

    def _skip_messages(self, until: int) -> None:
        if self._recv_chain_key is None:
            return
        while self._recv_msg_num < until:
            self._recv_chain_key, mk = kdf_chain(self._recv_chain_key)
            self._skipped[(self._remote_dh_pub, self._recv_msg_num)] = mk
            self._recv_msg_num += 1
            if len(self._skipped) > MAX_SKIP:
                oldest = next(iter(self._skipped))
                del self._skipped[oldest]


def _kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    derived = hkdf_derive(
        dh_output,
        salt=root_key,
        info=b"malphas-ratchet-dh-v1",
        length=64,
    )
    return derived[:32], derived[32:]
