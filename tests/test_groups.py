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

    # ── TM-01 partial: membership change propagation (1.0.0-rc3) ────────────

    async def test_add_member_notifies_existing_members(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group("squad", [id_b.peer_id])
        assert gid is not None
        await asyncio.sleep(0.4)

        # B should see a membership-change event when C is added.
        events_b: list[tuple] = []
        b.on_group_member_change(
            lambda f, g, action, target, ms:
                events_b.append((f, g, action, target, tuple(ms)))
        )
        ok = await a.add_group_member(gid, id_c.peer_id)
        assert ok is True
        await asyncio.sleep(0.5)

        assert any(
            ev[0] == id_a.peer_id and ev[1] == gid and ev[2] == "add"
            and ev[3] == id_c.peer_id and id_c.peer_id in ev[4]
            for ev in events_b
        ), f"B did not receive a member_change for the add: {events_b}"
        # B's local view now includes C.
        b_group = b._groups.get_by_id(gid)
        assert b_group is not None
        assert id_c.peer_id in b_group.members

    async def test_remove_member_excludes_them_from_future_fanouts(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group(
            "trio-grp", [id_b.peer_id, id_c.peer_id])
        assert gid is not None
        await asyncio.sleep(0.4)

        events_c: list[tuple] = []
        c.on_group_member_change(
            lambda f, g, action, target, ms:
                events_c.append((f, g, action, target, tuple(ms)))
        )
        # A removes B.
        ok = await a.remove_group_member(gid, id_b.peer_id)
        assert ok is True
        await asyncio.sleep(0.5)

        # C learned about it.
        assert any(
            ev[2] == "remove" and ev[3] == id_b.peer_id
            for ev in events_c
        ), f"C did not receive a member_change for the remove: {events_c}"
        # C's local view now excludes B.
        c_group = c._groups.get_by_id(gid)
        assert c_group is not None
        assert id_b.peer_id not in c_group.members

    async def test_leave_async_notifies_remaining_members(self, trio):
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group(
            "exit-grp", [id_b.peer_id, id_c.peer_id])
        assert gid is not None
        await asyncio.sleep(0.4)

        events_a: list[tuple] = []
        events_c: list[tuple] = []
        a.on_group_member_change(
            lambda f, g, action, target, ms:
                events_a.append((f, g, action, target, tuple(ms)))
        )
        c.on_group_member_change(
            lambda f, g, action, target, ms:
                events_c.append((f, g, action, target, tuple(ms)))
        )

        ok = await b.leave_group_async(gid)
        assert ok is True
        await asyncio.sleep(0.5)

        # A and C learned that B left.
        for events, who in [(events_a, "A"), (events_c, "C")]:
            assert any(
                ev[2] == "remove" and ev[3] == id_b.peer_id
                for ev in events
            ), f"{who} did not see B's leave: {events}"

    async def test_member_change_from_outsider_is_rejected(self, trio):
        """Authorization check: a non-member can't rewrite our local
        view by sending a forged group_member_change."""
        a, b, c, id_a, id_b, id_c = trio
        gid = await a.create_group("closed", [id_b.peer_id])
        assert gid is not None
        await asyncio.sleep(0.4)

        # C was never invited. C shouldn't be able to rewrite A's
        # membership by sending a member_change.
        forged = {
            "group_id": gid,
            "group_name": "closed",
            "action": "add",
            "target": id_c.peer_id,
            "members": [id_a.peer_id, id_b.peer_id, id_c.peer_id],
        }
        # Drive the handler directly with `from_id = c` to simulate
        # the dispatch arriving over the wire from C.
        await a._handle_group_member_change(forged, id_c.peer_id)

        # A's view of the group is unchanged.
        a_group = a._groups.get_by_id(gid)
        assert a_group is not None
        assert id_c.peer_id not in a_group.members
