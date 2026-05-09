"""
N-way pairwise group chat (v0.9.0).

Group chat implemented as a fanout: the sender encrypts the same
message once per member, using the existing 1-to-1 infrastructure
(sealed sender, auth-type prefix, replay cache, onion routing).
There is no shared group key, no add/remove member ratchet, no
cross-peer membership consensus.

Pros:
  • Each pairwise copy gets the full 1-to-1 security: sealed sender,
    replay cache, Double Ratchet (where available), HMAC/Ed25519
    outer auth, onion routing through 3 hops.
  • No new group cryptography to design or audit.
  • Trivially compatible with the existing dispatch pipeline.

Cons:
  • O(N) wire bytes per message. We hard-cap members at MAX_MEMBERS
    (50) to keep this honest.
  • Adding a member doesn't rotate any past keys — a future-member
    won't see history (intentional), but a former-member who keeps
    receiving (because nobody told them they're out) will continue
    to read messages until the sender stops including them.

Storage is in-memory only. `panic()` wipes it. Persistence to the
encrypted address book is a future iter.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

MAX_MEMBERS = 50
MAX_NAME_LEN = 64


def _new_group_id() -> str:
    """16 random bytes → 32 hex chars."""
    return secrets.token_hex(16)


@dataclass
class Group:
    group_id: str
    name: str
    creator: str  # peer_id of who created it
    members: list[str] = field(default_factory=list)  # peer_ids; creator is always included

    def add_member(self, peer_id: str) -> None:
        if peer_id in self.members:
            return
        if len(self.members) >= MAX_MEMBERS:
            raise ValueError(f"group is full ({MAX_MEMBERS} members)")
        self.members.append(peer_id)

    def remove_member(self, peer_id: str) -> bool:
        if peer_id not in self.members:
            return False
        self.members.remove(peer_id)
        return True

    def member_count(self) -> int:
        return len(self.members)


class GroupRegistry:
    """Per-node in-memory registry of joined groups."""

    def __init__(self) -> None:
        self._by_id: dict[str, Group] = {}
        self._by_name: dict[str, str] = {}  # name → group_id

    # ── Create / lookup ──────────────────────────────────────────────────────

    def create(self, name: str, creator: str, members: list[str]) -> Group:
        if not name or len(name) > MAX_NAME_LEN:
            raise ValueError(f"group name must be 1..{MAX_NAME_LEN} chars")
        if name in self._by_name:
            raise ValueError(f"group name already exists: {name}")

        group = Group(group_id=_new_group_id(), name=name, creator=creator)
        # Creator is the first member.
        group.add_member(creator)
        for m in members:
            if m != creator:
                group.add_member(m)
        self._by_id[group.group_id] = group
        self._by_name[name] = group.group_id
        return group

    def register(self, group: Group) -> None:
        """Insert an externally-built Group (used when receiving a group_invite)."""
        if not group.group_id or group.group_id in self._by_id:
            return
        if group.name in self._by_name and self._by_name[group.name] != group.group_id:
            # Name collision — rename to avoid clobbering local groups.
            group.name = f"{group.name}#{group.group_id[:8]}"
        self._by_id[group.group_id] = group
        self._by_name[group.name] = group.group_id

    def get_by_id(self, group_id: str) -> Group | None:
        return self._by_id.get(group_id)

    def get_by_name(self, name: str) -> Group | None:
        gid = self._by_name.get(name)
        return self._by_id.get(gid) if gid else None

    def lookup(self, key: str) -> Group | None:
        """Resolve either a group_id or a group name."""
        return self.get_by_id(key) or self.get_by_name(key)

    def all_groups(self) -> list[Group]:
        return list(self._by_id.values())

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def remove(self, group_id: str) -> None:
        g = self._by_id.pop(group_id, None)
        if g is not None:
            self._by_name.pop(g.name, None)

    def wipe(self) -> None:
        self._by_id.clear()
        self._by_name.clear()
