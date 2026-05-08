"""
In-memory message store.
Zero persistence. Zero logging.
Messages expire after TTL seconds and are wiped from memory.
"""

import secrets
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class Message:
    id: str
    from_peer: str        # peer_id (hex)
    to_peer: str          # peer_id (hex)
    content: str          # plaintext (after decryption)
    timestamp: float      # unix wall-clock timestamp (display)
    expires_at: float     # monotonic deadline (immune to clock skew)
    delivered: bool = False

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "from_peer": self.from_peer,
            "to_peer": self.to_peer,
            "content": self.content,
            "timestamp": self.timestamp,
            "delivered": self.delivered,
        }


class MessageStore:
    """
    Thread-safe in-memory message store.
    No writes to disk. Messages wiped after TTL.
    """

    def __init__(self, ttl_seconds: int = 3600, max_messages: int = 500) -> None:
        self._ttl = ttl_seconds
        self._max = max_messages
        # conversation_key -> deque of Message
        self._store: dict[str, deque[Message]] = {}

    def _conversation_key(self, a: str, b: str) -> str:
        """Canonical key regardless of sender/receiver order."""
        return "_".join(sorted([a, b]))

    def store(
        self,
        from_peer: str,
        to_peer: str,
        content: str,
        msg_id: str | None = None,
    ) -> Message:
        msg = Message(
            id=msg_id or secrets.token_hex(16),
            from_peer=from_peer,
            to_peer=to_peer,
            content=content,
            timestamp=time.time(),
            expires_at=time.monotonic() + self._ttl,
        )
        key = self._conversation_key(from_peer, to_peer)
        if key not in self._store:
            self._store[key] = deque(maxlen=self._max)
        self._store[key].append(msg)
        return msg

    def get_conversation(self, peer_a: str, peer_b: str) -> list[dict[str, Any]]:
        """Return non-expired messages for a conversation, oldest first."""
        key = self._conversation_key(peer_a, peer_b)
        if key not in self._store:
            return []
        result: list[dict[str, Any]] = []
        live: deque[Message] = deque()
        for msg in self._store[key]:
            if not msg.is_expired():
                result.append(msg.to_dict())
                live.append(msg)
        self._store[key] = live
        return result

    def purge_expired(self) -> int:
        """Remove all expired messages. Returns count removed."""
        removed = 0
        for key in list(self._store.keys()):
            before = len(self._store[key])
            self._store[key] = deque(
                (m for m in self._store[key] if not m.is_expired()),
                maxlen=self._max,
            )
            removed += before - len(self._store[key])
            if not self._store[key]:
                del self._store[key]
        return removed

    def wipe(self) -> None:
        """Zero out all stored messages."""
        self._store.clear()
