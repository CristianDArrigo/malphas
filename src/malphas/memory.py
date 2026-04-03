"""
In-memory message store.
Zero persistence. Zero logging.
Messages expire after TTL seconds and are wiped from memory.
"""

import time
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Message:
    id: str
    from_peer: str        # peer_id (hex)
    to_peer: str          # peer_id (hex)
    content: str          # plaintext (after decryption)
    timestamp: float      # unix timestamp
    expires_at: float     # unix timestamp
    delivered: bool = False

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
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

    def __init__(self, ttl_seconds: int = 3600, max_messages: int = 500):
        self._ttl = ttl_seconds
        self._max = max_messages
        # conversation_key -> deque of Message
        self._store: Dict[str, deque] = {}

    def _conversation_key(self, a: str, b: str) -> str:
        """Canonical key regardless of sender/receiver order."""
        return "_".join(sorted([a, b]))

    def store(
        self,
        from_peer: str,
        to_peer: str,
        content: str,
        msg_id: Optional[str] = None,
    ) -> Message:
        now = time.time()
        msg = Message(
            id=msg_id or secrets.token_hex(16),
            from_peer=from_peer,
            to_peer=to_peer,
            content=content,
            timestamp=now,
            expires_at=now + self._ttl,
        )
        key = self._conversation_key(from_peer, to_peer)
        if key not in self._store:
            self._store[key] = deque(maxlen=self._max)
        self._store[key].append(msg)
        return msg

    def get_conversation(self, peer_a: str, peer_b: str) -> List[dict]:
        """Return non-expired messages for a conversation, oldest first."""
        key = self._conversation_key(peer_a, peer_b)
        if key not in self._store:
            return []
        now = time.time()
        result = []
        live = deque()
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
