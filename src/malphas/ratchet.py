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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import (
    decrypt,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    hkdf_derive,
    kdf_chain,
)

# Max messages a single header may ask us to skip in one chain. Bounds both
# the skipped-key cache size and (critically) the number of KDF iterations
# per inbound frame — see _skip_messages. 1000 matches the Signal reference
# default: generous enough for real message loss, cheap enough (≈1000 HKDF
# steps, sub-millisecond) that it cannot be used for CPU exhaustion.
MAX_SKIP = 1000


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
    def __init__(self) -> None:
        self._dh_priv: X25519PrivateKey | None = None
        self._dh_pub: bytes | None = None
        self._remote_dh_pub: bytes | None = None
        self._root_key: bytes | None = None
        self._send_chain_key: bytes | None = None
        self._recv_chain_key: bytes | None = None
        self._send_msg_num: int = 0
        self._recv_msg_num: int = 0
        self._prev_send_count: int = 0
        self._skipped: dict[tuple[bytes, int], bytes] = {}

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

    def encrypt(self, plaintext: bytes) -> tuple[MessageHeader, bytes]:
        if self._send_chain_key is None:
            raise RuntimeError("Sending chain not initialized")
        # When the sending chain exists, the local DH public must too —
        # they are paired in `from_shared_secret` / `_dh_ratchet`.
        assert self._dh_pub is not None

        self._send_chain_key, message_key = kdf_chain(self._send_chain_key)
        header = MessageHeader(
            dh_pub=self._dh_pub,
            prev_count=self._prev_send_count,
            msg_num=self._send_msg_num,
        )
        self._send_msg_num += 1
        # Bind the (cleartext, on-wire) header to the ciphertext as AEAD AAD.
        # serialize() is the exact 40 bytes that travel on the wire, and the
        # receiver's deserialize()->serialize() round-trips to the same bytes,
        # so the tags match. Without this the header (dh_pub, prev_count,
        # msg_num) is unauthenticated alongside the ciphertext.
        ciphertext = encrypt(message_key, plaintext, aad=header.serialize())
        return header, ciphertext

    def decrypt(self, header: MessageHeader, ciphertext: bytes) -> bytes:
        aad = header.serialize()
        skip_key = (header.dh_pub, header.msg_num)
        if skip_key in self._skipped:
            mk = self._skipped.pop(skip_key)
            return decrypt(mk, ciphertext, aad=aad)

        if header.dh_pub != self._remote_dh_pub:
            self._skip_messages(header.prev_count)
            self._dh_ratchet(header.dh_pub)

        self._skip_messages(header.msg_num)

        # By this point the receiving chain is set: either the snippet
        # above already ratcheted it via `_dh_ratchet`, or the caller is
        # decrypting a message that arrived after a prior decrypt that
        # initialized it.
        assert self._recv_chain_key is not None
        self._recv_chain_key, message_key = kdf_chain(self._recv_chain_key)
        self._recv_msg_num += 1

        return decrypt(message_key, ciphertext, aad=aad)

    def _dh_ratchet(self, new_remote_pub: bytes) -> None:
        self._prev_send_count = self._send_msg_num
        self._send_msg_num = 0
        self._recv_msg_num = 0
        self._remote_dh_pub = new_remote_pub

        # _dh_ratchet runs only on a state that has been bootstrapped
        # via `from_shared_secret`, so both the local DH key and the
        # root key are populated by now.
        assert self._dh_priv is not None
        assert self._root_key is not None

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
        # Hard bound on how many messages a single header may ask us to
        # skip. `until` comes straight off the wire (header.prev_count /
        # header.msg_num, both attacker-controlled uint32). Without this
        # check the loop below would run up to ~4.29e9 HKDF iterations for
        # one crafted frame, pinning the (single-threaded) event loop —
        # the classic Double Ratchet skip-DoS. The Signal spec mandates
        # raising here rather than only bounding the cache size.
        if until - self._recv_msg_num > MAX_SKIP:
            raise ValueError(
                f"too many skipped messages: "
                f"{until - self._recv_msg_num} > MAX_SKIP={MAX_SKIP}"
            )
        # The receive chain is always paired with a known remote DH pub.
        assert self._remote_dh_pub is not None
        remote_pub = self._remote_dh_pub
        while self._recv_msg_num < until:
            self._recv_chain_key, mk = kdf_chain(self._recv_chain_key)
            self._skipped[(remote_pub, self._recv_msg_num)] = mk
            self._recv_msg_num += 1
            if len(self._skipped) > MAX_SKIP:
                oldest = next(iter(self._skipped))
                del self._skipped[oldest]


def _kdf_root(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    derived = hkdf_derive(
        dh_output,
        salt=root_key,
        info=b"malphas-ratchet-dh-v1",
        length=64,
    )
    return derived[:32], derived[32:]
