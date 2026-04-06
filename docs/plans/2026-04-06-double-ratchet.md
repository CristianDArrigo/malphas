# Double Ratchet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-message forward secrecy via the Double Ratchet algorithm, so a compromised message key exposes only that single message — not past or future messages in the session.

**Architecture:** A new `ratchet.py` module implements the symmetric ratchet (KDF chain) and the DH ratchet (X25519 key rotation). Each `PeerConnection` holds a `RatchetState` initialized from the ECDH shared secret established during handshake. Every message encrypts with a unique message key derived from the ratchet, then advances the chain. The receiving side mirrors the ratchet advancement. Out-of-order messages are handled by caching skipped message keys (up to a limit). The ratchet state lives in RAM only (consistent with zero-disk policy). On reconnect, a fresh ratchet is initialized from the new handshake — no state persistence needed.

**Tech Stack:** X25519, HKDF-SHA256, ChaCha20-Poly1305 (all already in malphas). No new dependencies.

**Reference:** [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/malphas/ratchet.py` | Create | Double Ratchet state machine: KDF chain, DH ratchet, encrypt/decrypt per message |
| `src/malphas/crypto.py` | Modify | Add `kdf_chain()` helper for ratchet chain key derivation |
| `src/malphas/node.py` | Modify | Initialize ratchet on handshake, use ratchet for message encrypt/decrypt instead of static HMAC |
| `tests/test_ratchet.py` | Create | Unit tests for ratchet: chain advancement, DH ratchet, out-of-order, key independence |
| `tests/test_integration_e2e.py` | Modify | Add E2E test verifying per-message forward secrecy |

---

### Task 1: KDF Chain Primitive

**Files:**
- Modify: `src/malphas/crypto.py`
- Create: `tests/test_ratchet.py`

The KDF chain is the core building block. Given a chain key, it produces a message key (for encrypting one message) and a new chain key (for the next message). This is a single HKDF call with two different info strings.

- [ ] **Step 1: Write failing test for kdf_chain**

```python
# tests/test_ratchet.py
"""
Tests for Double Ratchet implementation.

Verifies:
- KDF chain produces unique message keys per step
- Chain key advances deterministically
- DH ratchet rotates keys on direction change
- Out-of-order messages decrypt correctly
- Skipped keys are bounded
- Different sessions produce different ratchet states
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ratchet.py::TestKDFChain -v`
Expected: FAIL with `ImportError: cannot import name 'kdf_chain'`

- [ ] **Step 3: Implement kdf_chain in crypto.py**

Add to `src/malphas/crypto.py` after the `hmac_verify` function:

```python
# --- Double Ratchet KDF chain ------------------------------------------------

def kdf_chain(chain_key: bytes) -> tuple:
    """
    Advance a KDF chain by one step.
    Returns (new_chain_key, message_key).

    This is the core primitive of the Double Ratchet symmetric ratchet.
    Each call produces a unique message key and advances the chain.
    Signal spec: KDF_CK(ck) = (HKDF(ck, info="chain"), HKDF(ck, info="message"))
    """
    new_chain_key = hkdf_derive(chain_key, salt=b"malphas-ratchet-v1", info=b"chain", length=32)
    message_key = hkdf_derive(chain_key, salt=b"malphas-ratchet-v1", info=b"message", length=32)
    return new_chain_key, message_key
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_ratchet.py::TestKDFChain -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add src/malphas/crypto.py tests/test_ratchet.py
git commit -m "add kdf_chain primitive for Double Ratchet"
```

---

### Task 2: Ratchet State Machine

**Files:**
- Create: `src/malphas/ratchet.py`
- Modify: `tests/test_ratchet.py`

The ratchet state holds the sending and receiving chain keys, the DH ratchet keypair, and a cache of skipped message keys. It provides `encrypt()` and `decrypt()` methods that advance the chains.

- [ ] **Step 1: Write failing tests for RatchetState**

Append to `tests/test_ratchet.py`:

```python
from malphas.ratchet import RatchetState


class TestRatchetState:
    def _make_pair(self):
        """Create a pair of ratchet states from a shared secret (simulating handshake)."""
        from malphas.crypto import generate_ephemeral_keypair, ecdh_shared_secret
        # Simulate handshake: both sides have a shared secret
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        shared = ecdh_shared_secret(priv_a, pub_b)
        # Initiator and responder create ratchet states
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
        # A -> B
        h1, c1 = a.encrypt(b"from A")
        assert b.decrypt(h1, c1) == b"from A"
        # B -> A
        h2, c2 = b.encrypt(b"from B")
        assert a.decrypt(h2, c2) == b"from B"
        # A -> B again
        h3, c3 = a.encrypt(b"A again")
        assert b.decrypt(h3, c3) == b"A again"

    def test_each_message_different_ciphertext(self):
        a, b = self._make_pair()
        _, c1 = a.encrypt(b"same")
        _, c2 = a.encrypt(b"same")
        assert c1 != c2  # different message keys

    def test_out_of_order_messages(self):
        a, b = self._make_pair()
        h1, c1 = a.encrypt(b"first")
        h2, c2 = a.encrypt(b"second")
        h3, c3 = a.encrypt(b"third")
        # Deliver out of order
        assert b.decrypt(h3, c3) == b"third"
        assert b.decrypt(h1, c1) == b"first"
        assert b.decrypt(h2, c2) == b"second"

    def test_replay_rejected(self):
        a, b = self._make_pair()
        h, c = a.encrypt(b"once")
        b.decrypt(h, c)
        with pytest.raises(ValueError):
            b.decrypt(h, c)  # replay

    def test_tampered_ciphertext_rejected(self):
        a, b = self._make_pair()
        h, c = a.encrypt(b"data")
        tampered = bytearray(c)
        tampered[10] ^= 0xFF
        with pytest.raises(ValueError):
            b.decrypt(h, bytes(tampered))

    def test_skipped_keys_bounded(self):
        a, b = self._make_pair()
        # Send 200 messages without decrypting — should not OOM
        headers_cts = []
        for i in range(200):
            h, c = a.encrypt(f"msg{i}".encode())
            headers_cts.append((h, c))
        # Decrypt the last one — skips 199 keys (capped)
        # Should work but some early ones may be lost
        pt = b.decrypt(headers_cts[-1][0], headers_cts[-1][1])
        assert pt == b"msg199"

    def test_different_sessions_different_keys(self):
        a1, b1 = self._make_pair()
        a2, b2 = self._make_pair()
        _, c1 = a1.encrypt(b"same content")
        _, c2 = a2.encrypt(b"same content")
        assert c1 != c2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ratchet.py::TestRatchetState -v`
Expected: FAIL with `ImportError: cannot import name 'RatchetState'`

- [ ] **Step 3: Implement RatchetState**

Create `src/malphas/ratchet.py`:

```python
"""
Double Ratchet implementation.

Provides per-message forward secrecy: each message is encrypted with
a unique key derived from a ratcheting KDF chain. Compromising one
message key does not expose past or future messages.

Based on the Signal Double Ratchet specification:
https://signal.org/docs/specifications/doubleratchet/

State is in-memory only (consistent with zero-disk policy).
On reconnect, a fresh ratchet is initialized from the new handshake.

Components:
- Symmetric ratchet: KDF chain that advances per message
- DH ratchet: X25519 key rotation on direction change
"""

from dataclasses import dataclass, field
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


MAX_SKIP = 100  # max skipped message keys to cache


@dataclass
class MessageHeader:
    """Header sent with each ratchet-encrypted message."""
    dh_pub: bytes      # sender's current DH ratchet public key (32 bytes)
    prev_count: int    # number of messages in previous sending chain
    msg_num: int       # message number in current sending chain

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
    """
    Double Ratchet state for one peer connection.

    Initialized from the ECDH shared secret established during handshake.
    The initiator and responder initialize differently to break symmetry.
    """

    def __init__(self):
        self._dh_priv: Optional[X25519PrivateKey] = None
        self._dh_pub: Optional[bytes] = None          # our current DH pub
        self._remote_dh_pub: Optional[bytes] = None    # peer's current DH pub
        self._root_key: Optional[bytes] = None
        self._send_chain_key: Optional[bytes] = None
        self._recv_chain_key: Optional[bytes] = None
        self._send_msg_num: int = 0
        self._recv_msg_num: int = 0
        self._prev_send_count: int = 0
        self._skipped: Dict[Tuple[bytes, int], bytes] = {}  # (dh_pub, msg_num) -> message_key

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        our_dh_priv: X25519PrivateKey,
        remote_dh_pub: bytes,
        is_initiator: bool,
    ) -> "RatchetState":
        """
        Initialize ratchet from handshake ECDH result.

        The initiator performs the first DH ratchet step immediately.
        The responder waits for the first message to trigger it.
        """
        state = cls()
        state._remote_dh_pub = remote_dh_pub

        # Derive root key from shared secret
        state._root_key = hkdf_derive(
            shared_secret,
            salt=b"malphas-ratchet-root-v1",
            info=b"root-key",
            length=32,
        )

        if is_initiator:
            # Initiator: generate fresh DH pair and perform first ratchet step
            state._dh_priv, state._dh_pub = generate_ephemeral_keypair()
            dh_output = ecdh_shared_secret(state._dh_priv, remote_dh_pub)
            state._root_key, state._send_chain_key = _kdf_root(
                state._root_key, dh_output
            )
            state._recv_chain_key = None  # set on first received message
        else:
            # Responder: use the handshake DH pair, wait for initiator's first message
            state._dh_priv = our_dh_priv
            state._dh_pub = our_dh_priv.public_key().public_bytes_raw()
            state._send_chain_key = None  # set after first DH ratchet
            state._recv_chain_key = None

        return state

    def encrypt(self, plaintext: bytes) -> Tuple[MessageHeader, bytes]:
        """
        Encrypt a message, advancing the sending chain.
        Returns (header, ciphertext).
        """
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
        """
        Decrypt a message, advancing the receiving chain or performing
        a DH ratchet step if the sender's DH key has changed.
        """
        # Check skipped keys first (out-of-order messages)
        skip_key = (header.dh_pub, header.msg_num)
        if skip_key in self._skipped:
            mk = self._skipped.pop(skip_key)
            return decrypt(mk, ciphertext)

        # If sender's DH key changed, perform DH ratchet
        if header.dh_pub != self._remote_dh_pub:
            self._skip_messages(header.prev_count)
            self._dh_ratchet(header.dh_pub)

        # Skip ahead if needed (messages arrived out of order)
        self._skip_messages(header.msg_num)

        # Advance receiving chain
        self._recv_chain_key, message_key = kdf_chain(self._recv_chain_key)
        self._recv_msg_num += 1

        return decrypt(message_key, ciphertext)

    def _dh_ratchet(self, new_remote_pub: bytes) -> None:
        """Perform a DH ratchet step with a new remote public key."""
        self._prev_send_count = self._send_msg_num
        self._send_msg_num = 0
        self._recv_msg_num = 0
        self._remote_dh_pub = new_remote_pub

        # Derive new receiving chain key
        dh_output = ecdh_shared_secret(self._dh_priv, new_remote_pub)
        self._root_key, self._recv_chain_key = _kdf_root(
            self._root_key, dh_output
        )

        # Generate new DH keypair for sending
        self._dh_priv, self._dh_pub = generate_ephemeral_keypair()

        # Derive new sending chain key
        dh_output = ecdh_shared_secret(self._dh_priv, new_remote_pub)
        self._root_key, self._send_chain_key = _kdf_root(
            self._root_key, dh_output
        )

    def _skip_messages(self, until: int) -> None:
        """Cache message keys for skipped messages (out-of-order delivery)."""
        if self._recv_chain_key is None:
            return
        while self._recv_msg_num < until:
            self._recv_chain_key, mk = kdf_chain(self._recv_chain_key)
            self._skipped[(self._remote_dh_pub, self._recv_msg_num)] = mk
            self._recv_msg_num += 1
            # Bound the cache
            if len(self._skipped) > MAX_SKIP:
                # Remove oldest entry
                oldest = next(iter(self._skipped))
                del self._skipped[oldest]


def _kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root chain KDF: derive new root key and chain key from DH output.
    Signal spec: KDF_RK(rk, dh_out) = HKDF(rk, dh_out, info="root")
    Returns (new_root_key, chain_key).
    """
    derived = hkdf_derive(
        dh_output,
        salt=root_key,
        info=b"malphas-ratchet-dh-v1",
        length=64,
    )
    return derived[:32], derived[32:]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ratchet.py -v`
Expected: All 14 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/malphas/ratchet.py tests/test_ratchet.py
git commit -m "implement Double Ratchet state machine with DH ratchet and out-of-order support"
```

---

### Task 3: Integrate Ratchet into Node

**Files:**
- Modify: `src/malphas/node.py`

The `PeerConnection` gets a `RatchetState` initialized from the handshake. `_try_send` uses `ratchet.encrypt()` instead of static HMAC. `_deliver` uses `ratchet.decrypt()`. The header is serialized and prepended to the payload.

- [ ] **Step 1: Add ratchet to PeerConnection and handshake**

In `src/malphas/node.py`, add import at the top:

```python
from .ratchet import RatchetState, MessageHeader
```

Add `ratchet` field to `PeerConnection.__init__`:

```python
self.ratchet: Optional[RatchetState] = None
```

In `_perform_handshake`, after `conn.hmac_key = derive_hmac_key(session_key)`, add:

```python
# Initialize Double Ratchet for per-message forward secrecy
conn.ratchet = RatchetState.from_shared_secret(
    shared, eph_priv, their_eph, is_initiator=outbound
)
```

- [ ] **Step 2: Modify _try_send to use ratchet**

Replace the HMAC authentication block in `_try_send`:

```python
        dest_conn = self._connections.get(dest_peer_id)
        if dest_conn and dest_conn.ratchet:
            # Double Ratchet: per-message forward secrecy
            header, ratchet_ct = dest_conn.ratchet.encrypt(payload_bytes)
            # Wire format: "R" + header(40) + ratchet_ciphertext
            authenticated = b"R" + header.serialize() + ratchet_ct
        elif dest_conn and dest_conn.hmac_key:
            tag = hmac_sign(dest_conn.hmac_key, payload_bytes)
            authenticated = tag + payload_bytes
        else:
            tag = self.identity.sign(payload_bytes)
            authenticated = tag + payload_bytes
```

- [ ] **Step 3: Modify _deliver to handle ratchet messages**

In `_deliver`, before the existing HMAC/Ed25519 detection, add ratchet detection:

```python
        # Check for ratchet-encrypted message (prefix "R")
        if len(signed) > 41 and signed[0:1] == b"R":
            header_data = signed[1:41]
            ratchet_ct = signed[41:]
            header = MessageHeader.deserialize(header_data)

            # Find which connection this came from
            # Try all connections — the header's DH pub identifies the sender
            for peer_id, conn in self._connections.items():
                if conn.ratchet:
                    try:
                        payload_bytes = conn.ratchet.decrypt(header, ratchet_ct)
                        try:
                            data = json.loads(payload_bytes.decode())
                        except Exception:
                            continue
                        kind = data.get("kind")
                        from_id = data.get("from", "")
                        if not kind or not from_id:
                            continue
                        # Verify sender is known
                        peer = self.discovery.get_peer(from_id)
                        if not peer:
                            return
                        if kind == KIND_MESSAGE:
                            await self._deliver_message(data, from_id)
                        elif kind == KIND_RECEIPT:
                            await self._deliver_receipt(data, from_id, peer)
                        return
                    except (ValueError, RuntimeError):
                        continue
            return  # no connection could decrypt
```

- [ ] **Step 4: Also use ratchet for _send_receipt**

In `_send_receipt`, replace the HMAC block:

```python
        sender_conn = self._connections.get(from_id)
        if sender_conn and sender_conn.ratchet:
            header, ratchet_ct = sender_conn.ratchet.encrypt(payload_bytes)
            authenticated = b"R" + header.serialize() + ratchet_ct
        elif sender_conn and sender_conn.hmac_key:
            tag = hmac_sign(sender_conn.hmac_key, payload_bytes)
            authenticated = tag + payload_bytes
        else:
            tag = self.identity.sign(payload_bytes)
            authenticated = tag + payload_bytes
        padded = pad_payload(authenticated)
```

- [ ] **Step 5: Run existing E2E tests**

Run: `pytest tests/test_integration_e2e.py tests/test_functional_node.py -v --tb=short`
Expected: All PASS (ratchet is now used but behavior is transparent)

- [ ] **Step 6: Commit**

```bash
git add src/malphas/node.py
git commit -m "integrate Double Ratchet into message send/receive pipeline"
```

---

### Task 4: Forward Secrecy E2E Test

**Files:**
- Modify: `tests/test_integration_e2e.py`

Add a test that proves per-message forward secrecy: the same message sent twice in the same session produces different ciphertexts, and knowing one message key doesn't help decrypt another.

- [ ] **Step 1: Write forward secrecy E2E test**

Append to `tests/test_integration_e2e.py`:

```python
class TestForwardSecrecy:
    async def test_same_message_different_ciphertexts(self, pair):
        """Two identical messages must produce different ciphertexts
        (different message keys from the ratchet)."""
        a, b, id_a, id_b = pair
        received = []
        b.on_message(lambda f, c: received.append(c))

        await a.send_message(id_b.peer_id, "same content")
        await a.send_message(id_b.peer_id, "same content")
        await asyncio.sleep(0.5)

        assert len(received) == 2
        assert received[0] == "same content"
        assert received[1] == "same content"

    async def test_ratchet_survives_direction_change(self, pair):
        """Messages work after switching sender direction (DH ratchet)."""
        a, b, id_a, id_b = pair
        recv_b = []
        recv_a = []
        b.on_message(lambda f, c: recv_b.append(c))
        a.on_message(lambda f, c: recv_a.append(c))

        # A -> B
        await a.send_message(id_b.peer_id, "a1")
        await asyncio.sleep(0.3)
        # B -> A (direction change triggers DH ratchet)
        await b.send_message(id_a.peer_id, "b1")
        await asyncio.sleep(0.3)
        # A -> B again
        await a.send_message(id_b.peer_id, "a2")
        await asyncio.sleep(0.3)

        assert "a1" in recv_b
        assert "a2" in recv_b
        assert "b1" in recv_a
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_integration_e2e.py::TestForwardSecrecy -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration_e2e.py
git commit -m "add forward secrecy E2E tests for Double Ratchet"
```

---

### Task 5: Panic Wipe Ratchet State

**Files:**
- Modify: `src/malphas/node.py`

The ratchet state in each PeerConnection must be wiped on `/panic`.

- [ ] **Step 1: Add ratchet wipe to panic**

In `node.py` `panic()` method, before closing connections, add:

```python
        # Wipe ratchet states
        for conn in self._connections.values():
            if conn.ratchet:
                conn.ratchet = None
```

- [ ] **Step 2: Write test**

Append to `tests/test_security_argon2_panic.py`:

```python
    async def test_panic_clears_ratchet_state(self):
        from malphas.node import MalphasNode
        id_a = create_identity("panic-ratchet-a")
        id_b = create_identity("panic-ratchet-b")
        node_a = MalphasNode(id_a, "127.0.0.1", 18108, cover_traffic=False)
        node_b = MalphasNode(id_b, "127.0.0.1", 18109, cover_traffic=False)
        await node_a.start()
        await node_b.start()

        await node_a.connect_to_peer(
            "127.0.0.1", 18109,
            id_b.peer_id, id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
        )
        await asyncio.sleep(0.15)

        conn = node_a._connections.get(id_b.peer_id)
        assert conn is not None
        assert conn.ratchet is not None

        node_a.panic()

        # After panic, all connections are closed and ratchets wiped
        assert len(node_a._connections) == 0

        await node_a.stop()
        await node_b.stop()
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_security_argon2_panic.py::TestPanicWipe::test_panic_clears_ratchet_state -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/malphas/node.py tests/test_security_argon2_panic.py
git commit -m "wipe ratchet state on panic"
```

---

### Task 6: Update Audit and Documentation

**Files:**
- Modify: `scripts/audit.sh`
- Modify: `README.md`

- [ ] **Step 1: Add ratchet check to audit.sh**

Append before the summary section in `scripts/audit.sh`:

```bash
# ── 16. Double Ratchet per-message keys ──────────────────────────────────────

$PYTHON -c "
from malphas.ratchet import RatchetState
from malphas.crypto import generate_ephemeral_keypair, ecdh_shared_secret

priv_a, pub_a = generate_ephemeral_keypair()
priv_b, pub_b = generate_ephemeral_keypair()
shared = ecdh_shared_secret(priv_a, pub_b)

a = RatchetState.from_shared_secret(shared, priv_a, pub_b, is_initiator=True)
b = RatchetState.from_shared_secret(shared, priv_b, pub_a, is_initiator=False)

# Each message gets a unique key
_, c1 = a.encrypt(b'msg1')
_, c2 = a.encrypt(b'msg1')
assert c1 != c2, 'same ciphertext for different ratchet steps'

# Decryption works
h, c = a.encrypt(b'test')
pt = b.decrypt(h, c)
assert pt == b'test', 'ratchet decrypt failed'
" 2>/dev/null
check "Double Ratchet: per-message forward secrecy" "\$?"
```

- [ ] **Step 2: Update README.md**

In the Limitations section, replace:

```
**No forward secrecy per message.** Session keys are established once per connection and used for all messages in that session. If a session key is compromised (e.g., via memory dump), all messages from that session are at risk. The Double Ratchet protocol (used by Signal) would provide per-message forward secrecy but is not yet implemented.
```

With:

```
**Forward secrecy.** malphas implements the Double Ratchet protocol for per-message forward secrecy. Each message is encrypted with a unique key derived from a ratcheting KDF chain. Compromising a single message key does not expose past or future messages. The DH ratchet rotates X25519 keys on each direction change, providing break-in recovery. Ratchet state is in-memory only — on reconnect, a fresh ratchet is initialized from the new handshake.
```

In the Cryptographic Stack table, add a row:

```
| Ratchet | Double Ratchet (KDF chain + DH) | Per-message forward secrecy |
```

In the References section, the Double Ratchet link already exists — change "Not yet implemented" to "Implemented in malphas for per-message forward secrecy."

- [ ] **Step 3: Commit**

```bash
git add scripts/audit.sh README.md
git commit -m "document Double Ratchet: update README, add audit check"
```

---

### Task 7: Full Test Suite Verification

- [ ] **Step 1: Run the complete test suite**

```bash
pytest tests/ -m "not tor and not slow" -q --tb=short
```

Expected: All tests PASS, zero failures.

- [ ] **Step 2: Run the self-audit**

```bash
bash scripts/audit.sh
```

Expected: 16 checks, all PASS.

- [ ] **Step 3: Final commit and push**

```bash
git push origin main
```
