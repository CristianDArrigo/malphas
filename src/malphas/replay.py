"""
Replay protection cache.

A bounded sliding window of (from_peer_id, msg_id) pairs already
delivered to the application layer. Used by MalphasNode._deliver
to drop replayed onion packets coming back from a malicious relay
or a packet recorder/injector on the wire.

Properties:
- O(1) lookup via dict.
- O(1) eviction (FIFO) via OrderedDict.
- Per-entry TTL (default = MessageStore TTL).
- Hard cap on entries to bound memory.
- In-memory only — wiped on stop()/panic().
- Single asyncio thread, no locking required.
"""

import time
from collections import OrderedDict

DEFAULT_TTL = 3600
DEFAULT_MAX = 10_000


class ReplayCache:
    """Sliding window of seen (from_id, msg_id) pairs."""

    def __init__(self, ttl: int = DEFAULT_TTL, max_entries: int = DEFAULT_MAX):
        self._ttl = float(ttl)
        self._max = int(max_entries)
        self._entries: OrderedDict[tuple[str, str], float] = OrderedDict()

    def seen(self, from_id: str, msg_id: str) -> bool:
        """
        Record (from_id, msg_id). Returns True if it was already present
        and not yet expired (i.e. this is a replay), False otherwise.

        On replay (True), the timestamp is NOT refreshed: a replayed
        packet should not extend the lifetime of the entry, otherwise
        an attacker could keep replaying to keep the slot warm and crowd
        out legitimate entries.

        On insert (False), eviction is applied if the cache is full.
        """
        key = (from_id, msg_id)
        now = time.monotonic()
        existing = self._entries.get(key)
        if existing is not None and (now - existing) <= self._ttl:
            return True

        # Either new entry, or stale entry that we replace.
        if existing is not None:
            # Stale — remove first, then re-insert at the tail.
            del self._entries[key]

        self._entries[key] = now

        # Bound memory by evicting the oldest entries (FIFO).
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

        return False

    def purge_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        now = time.monotonic()
        removed = 0
        # Iterate over a snapshot of keys to allow mutation
        for key in list(self._entries.keys()):
            ts = self._entries.get(key)
            if ts is None:
                continue
            if (now - ts) > self._ttl:
                del self._entries[key]
                removed += 1
            else:
                # OrderedDict insertion order ≈ time order if we never refresh,
                # so once we hit a non-expired entry we can stop.
                break
        return removed

    def wipe(self) -> None:
        """Drop all entries."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: tuple[str, str]) -> bool:
        ts = self._entries.get(key)
        if ts is None:
            return False
        if (time.monotonic() - ts) > self._ttl:
            return False
        return True
