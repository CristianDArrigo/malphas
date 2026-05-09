"""
Tests for malphas.groups + N-way pairwise group chat (v0.9.0).

Unit: GroupRegistry CRUD, member cap, name collision.
E2E: 3-node fanout (A creates group with B and C; A sends; both
receive).
"""

from __future__ import annotations

import asyncio

import pytest

from malphas.groups import MAX_MEMBERS, Group, GroupRegistry
from malphas.identity import create_identity
from malphas.node import MalphasNode

# ── Unit ──────────────────────────────────────────────────────────────────────


def test_group_add_and_count():
    g = Group(group_id="abc" * 8 + "00", name="t", creator="alice")
    g.add_member("alice")
    g.add_member("bob")
    assert g.member_count() == 2
    # Idempotent
    g.add_member("bob")
    assert g.member_count() == 2


def test_group_max_members_enforced():
    g = Group(group_id="abc" * 8 + "00", name="t", creator="alice")
    for i in range(MAX_MEMBERS):
        g.add_member(f"peer{i:02d}")
    assert g.member_count() == MAX_MEMBERS
    with pytest.raises(ValueError):
        g.add_member("one-too-many")


def test_group_remove_member():
    g = Group(group_id="abc" * 8 + "00", name="t", creator="alice")
    g.add_member("alice")
    g.add_member("bob")
    assert g.remove_member("bob") is True
    assert g.member_count() == 1
    assert g.remove_member("bob") is False  # already gone


def test_registry_create_and_lookup():
    r = GroupRegistry()
    g = r.create("rivendell", creator="alice", members=["bob", "charlie"])
    assert "alice" in g.members
    assert "bob" in g.members
    assert "charlie" in g.members
    assert r.lookup("rivendell") is g
    assert r.lookup(g.group_id) is g


def test_registry_name_collision_raises():
    r = GroupRegistry()
    r.create("dup", creator="alice", members=[])
    with pytest.raises(ValueError):
        r.create("dup", creator="alice", members=[])


def test_registry_register_existing_name_renames():
    r = GroupRegistry()
    r.create("shared", creator="alice", members=[])
    # Receiving an externally-built Group with the same name must not
    # clobber the local one — registry renames it.
    incoming = Group(group_id="ff" * 16, name="shared", creator="bob")
    incoming.add_member("bob")
    r.register(incoming)
    # Both must coexist by group_id
    assert r.get_by_id(incoming.group_id) is incoming
    assert r.get_by_name("shared") is not incoming
    # Renamed
    assert "shared#" in incoming.name


def test_registry_wipe():
    r = GroupRegistry()
    r.create("a", creator="alice", members=[])
    r.create("b", creator="alice", members=[])
    r.wipe()
    assert r.all_groups() == []


# ── E2E ──────────────────────────────────────────────────────────────────────


async def _connect(a: MalphasNode, b: MalphasNode, id_b) -> bool:
    ok = await a.connect_to_peer(
        "127.0.0.1", b.port,
        id_b.peer_id,
        id_b.x25519_pub_bytes,
        id_b.ed25519_pub_bytes,
    )
    await asyncio.sleep(0.15)
    return ok


@pytest.fixture
async def trio():
    id_a = create_identity("group-alice")
    id_b = create_identity("group-bob")
    id_c = create_identity("group-charlie")
    a = MalphasNode(id_a, "127.0.0.1", 18501, cover_traffic=False)
    b = MalphasNode(id_b, "127.0.0.1", 18502, cover_traffic=False)
    c = MalphasNode(id_c, "127.0.0.1", 18503, cover_traffic=False)
    await a.start()
    await b.start()
    await c.start()
    # Full mesh — onion routing requires that every node along the
    # circuit has a live TCP session with the next hop. With only 3
    # nodes the only available "circuit" is direct, and any random
    # relay must in turn be able to reach the destination.
    assert await _connect(a, b, id_b)
    assert await _connect(a, c, id_c)
    assert await _connect(b, c, id_c)
    yield a, b, c, id_a, id_b, id_c
    await a.stop()
    await b.stop()
    await c.stop()


class TestGroupChatIntegration:
    async def test_create_group_and_invite_distributed(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        invites_b: list[tuple] = []
        invites_c: list[tuple] = []
        b.on_group_invite(
            lambda f, gid, gname, ms: invites_b.append((f, gid, gname, tuple(ms)))
        )
        c.on_group_invite(
            lambda f, gid, gname, ms: invites_c.append((f, gid, gname, tuple(ms)))
        )

        gid = await a.create_group("fellowship", [id_b.peer_id, id_c.peer_id])
        assert gid is not None
        await asyncio.sleep(0.5)

        assert len(invites_b) == 1
        assert len(invites_c) == 1
        assert invites_b[0][1] == gid
        assert invites_c[0][1] == gid
        assert invites_b[0][2] == "fellowship"

    async def test_group_message_fanout(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        msgs_b: list[tuple] = []
        msgs_c: list[tuple] = []
        b.on_group_message(
            lambda f, gid, gname, content: msgs_b.append((f, gid, gname, content))
        )
        c.on_group_message(
            lambda f, gid, gname, content: msgs_c.append((f, gid, gname, content))
        )

        gid = await a.create_group("council", [id_b.peer_id, id_c.peer_id])
        assert gid is not None
        await asyncio.sleep(0.4)  # let invites land

        ok = await a.send_group_message(gid, "the ring must be destroyed")
        assert ok is True
        await asyncio.sleep(0.5)

        assert len(msgs_b) == 1
        assert len(msgs_c) == 1
        assert msgs_b[0][3] == "the ring must be destroyed"
        assert msgs_c[0][3] == "the ring must be destroyed"
        # Sender peer_id is preserved in the from_id
        assert msgs_b[0][0] == id_a.peer_id
        assert msgs_c[0][0] == id_a.peer_id

    async def test_leave_removes_local_only(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group("guild", [id_b.peer_id, id_c.peer_id])
        assert gid is not None
        await asyncio.sleep(0.3)

        # B leaves — only B's local registry forgets the group.
        ok = b.leave_group(gid)
        assert ok is True
        assert b._groups.get_by_id(gid) is None
        # A and C still know.
        assert a._groups.get_by_id(gid) is not None
        assert c._groups.get_by_id(gid) is not None

    async def test_panic_wipes_groups(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group("temp", [id_b.peer_id])
        assert gid is not None
        a.panic()
        assert a._groups.get_by_id(gid) is None
