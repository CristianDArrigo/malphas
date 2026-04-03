"""
Traffic obfuscation: padding + cover traffic.

Padding:
  All message payloads are padded to the nearest multiple of PAYLOAD_BLOCK
  before encryption. This prevents size-based content inference.

  Wire format: length(4) || plaintext || random_padding

Cover traffic:
  Each node periodically sends encrypted dummy packets to random known peers.
  The packet is indistinguishable from a real onion packet to an observer.
  The recipient decrypts and sees the COVER_FLAG, then silently drops it.
  Interval is randomized within [min, max] to prevent timing fingerprinting.
"""

import asyncio
import os
import secrets
import struct
import time
from typing import Callable, List, Optional

# Pad all payloads to multiples of this size
PAYLOAD_BLOCK = 512  # bytes

# Cover traffic settings
COVER_MIN_INTERVAL = 10.0   # seconds
COVER_MAX_INTERVAL = 40.0   # seconds

# Flag embedded in decrypted cover payload
COVER_FLAG = b"\x00COVER\x00"  # 7 bytes, not valid UTF-8 JSON → safe discriminator


# ── Padding ──────────────────────────────────────────────────────────────────

def pad_payload(plaintext: bytes) -> bytes:
    """
    Pad plaintext to nearest PAYLOAD_BLOCK multiple.
    Format: length(4, big-endian) || plaintext || random_padding
    Random padding (not zero) to avoid distinguishing from real content.
    """
    length_prefix = struct.pack(">I", len(plaintext))
    total = 4 + len(plaintext)
    remainder = total % PAYLOAD_BLOCK
    pad_len = (PAYLOAD_BLOCK - remainder) if remainder else 0
    padding = os.urandom(pad_len)  # random, not zeros
    return length_prefix + plaintext + padding


def unpad_payload(data: bytes) -> bytes:
    """
    Extract plaintext from padded payload.
    Raises ValueError on malformed input.
    """
    if len(data) < 4:
        raise ValueError("Padded payload too short")
    length = struct.unpack(">I", data[:4])[0]
    if 4 + length > len(data):
        raise ValueError("Length prefix exceeds data size")
    return data[4: 4 + length]


def is_cover(decrypted_payload: bytes) -> bool:
    """Check if a decrypted payload is a cover traffic packet."""
    return decrypted_payload[:len(COVER_FLAG)] == COVER_FLAG


def make_cover_payload() -> bytes:
    """
    Generate a cover traffic payload.
    Padded to PAYLOAD_BLOCK like a real message.
    Contains COVER_FLAG so the recipient can identify and drop it.
    """
    # Random body after the flag to fill the block naturally
    body = COVER_FLAG + os.urandom(PAYLOAD_BLOCK - 4 - len(COVER_FLAG))
    return pad_payload(body)


# ── Cover traffic engine ──────────────────────────────────────────────────────

class CoverTrafficEngine:
    """
    Periodically sends cover packets to random peers.

    The send_fn is called with (peer_id, payload_bytes) and should
    route the payload through the onion layer to that peer.
    An observer on the wire sees encrypted traffic identical to real messages.
    """

    def __init__(
        self,
        get_peers_fn: Callable[[], List[str]],   # returns list of peer_ids
        send_cover_fn: Callable,                  # async (peer_id) -> None
        min_interval: float = COVER_MIN_INTERVAL,
        max_interval: float = COVER_MAX_INTERVAL,
    ):
        self._get_peers = get_peers_fn
        self._send_cover = send_cover_fn
        self._min = min_interval
        self._max = max_interval
        self._task: Optional[asyncio.Task] = None
        self._enabled = True

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._enabled = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while True:
            # Randomized sleep to prevent timing fingerprinting
            interval = self._min + secrets.randbelow(
                int((self._max - self._min) * 100)
            ) / 100.0
            await asyncio.sleep(interval)

            if not self._enabled:
                continue

            peers = self._get_peers()
            if not peers:
                continue

            # Pick a random peer
            target = secrets.choice(peers)
            try:
                await self._send_cover(target)
            except Exception:
                pass  # silent — cover traffic failure is non-critical
