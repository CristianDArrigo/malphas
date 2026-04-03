"""
Read receipt system.

Flow:
  1. Sender A embeds (msg_id, nonce) in every message
  2. Recipient C, upon decryption, signs (msg_id || nonce || "read") with Ed25519
  3. C sends the signed receipt back through a reverse circuit
  4. A verifies the signature with C's known Ed25519 pubkey

What this detects:
  - Message never arrived at C (no receipt within timeout)
  - Circuit broken before destination (same)

What this does NOT detect:
  - A purely passive wiretapper (they can't send the receipt)
  - A compromised destination that both reads AND sends the receipt

Pending receipts are kept in memory only. No disk writes.
"""

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


RECEIPT_TIMEOUT = 30.0   # seconds before a pending receipt is considered lost
RECEIPT_INFO = b"malphas-read-receipt-v1"


@dataclass
class PendingReceipt:
    msg_id: str
    nonce: bytes          # 16 random bytes
    dest_peer_id: str
    sent_at: float
    content_preview: str  # first 40 chars for UI, never logged
    resolved: bool = False
    received: bool = False


def make_receipt_challenge(msg_id: str, nonce: bytes) -> bytes:
    """
    The data that the recipient must sign to prove they received the message.
    msg_id (utf-8) || nonce (16) || RECEIPT_INFO
    """
    return msg_id.encode() + nonce + RECEIPT_INFO


def sign_receipt(
    msg_id: str,
    nonce: bytes,
    ed25519_priv,
) -> bytes:
    """Called by the recipient. Returns 64-byte Ed25519 signature."""
    challenge = make_receipt_challenge(msg_id, nonce)
    return ed25519_priv.sign(challenge)


def verify_receipt(
    msg_id: str,
    nonce: bytes,
    signature: bytes,
    ed25519_pub,
) -> bool:
    """Called by the sender. Returns True if signature is valid."""
    challenge = make_receipt_challenge(msg_id, nonce)
    try:
        ed25519_pub.verify(signature, challenge)
        return True
    except Exception:
        return False


class ReceiptTracker:
    """
    Tracks pending read receipts in memory.
    Triggers callbacks on receipt or timeout.
    No disk persistence.
    """

    def __init__(self, timeout: float = RECEIPT_TIMEOUT, check_interval: float = 5.0):
        self._pending: Dict[str, PendingReceipt] = {}
        self._on_receipt: Optional[Callable] = None
        self._on_timeout: Optional[Callable] = None
        self._task: Optional[asyncio.Task] = None
        self._timeout = timeout
        self._check_interval = check_interval

    def on_receipt(self, callback: Callable) -> None:
        """callback(msg_id, dest_peer_id, received: bool)"""
        self._on_receipt = callback

    def on_timeout(self, callback: Callable) -> None:
        self._on_timeout = callback

    def track(
        self,
        msg_id: str,
        nonce: bytes,
        dest_peer_id: str,
        content_preview: str = "",
    ) -> PendingReceipt:
        pr = PendingReceipt(
            msg_id=msg_id,
            nonce=nonce,
            dest_peer_id=dest_peer_id,
            sent_at=time.time(),
            content_preview=content_preview[:40],
        )
        self._pending[msg_id] = pr
        return pr

    def resolve(self, msg_id: str, signature: bytes, sender_pub) -> bool:
        """
        Called when a receipt arrives.
        Verifies the signature, marks as received.
        Returns True if valid.
        """
        pr = self._pending.get(msg_id)
        if not pr or pr.resolved:
            return False

        valid = verify_receipt(msg_id, pr.nonce, signature, sender_pub)
        if valid:
            pr.resolved = True
            pr.received = True
            if self._on_receipt:
                asyncio.create_task(
                    self._maybe_call(self._on_receipt, msg_id, pr.dest_peer_id, True)
                )
        return valid

    async def _maybe_call(self, cb, *args):
        try:
            if asyncio.iscoroutinefunction(cb):
                await cb(*args)
            else:
                cb(*args)
        except Exception:
            pass

    async def start(self) -> None:
        self._task = asyncio.create_task(self._timeout_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        self._pending.clear()

    async def _timeout_loop(self) -> None:
        while True:
            await asyncio.sleep(self._check_interval)
            now = time.time()
            expired = [
                pr for pr in self._pending.values()
                if not pr.resolved and (now - pr.sent_at) > self._timeout
            ]
            for pr in expired:
                pr.resolved = True
                pr.received = False
                if self._on_timeout:
                    await self._maybe_call(
                        self._on_timeout, pr.msg_id, pr.dest_peer_id
                    )
                del self._pending[pr.msg_id]

    def pending_count(self) -> int:
        return sum(1 for p in self._pending.values() if not p.resolved)

    def wipe(self) -> None:
        self._pending.clear()
