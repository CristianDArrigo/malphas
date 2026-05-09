# iter-055 — TM-01 partial: group membership eventual consistency

**Date:** 2026-05-09
**Trigger:** scheduled follow-up to iter-053 (THREAT_MODEL.md
TM-01).

## Honest scope

TM-01 is "groups have no MLS / no key rotation on removal". The
*real* fix (PCS at membership-change boundary) is MLS, which is
multi-week and out of scope for an autonomous loop iter. What
this iter delivers is the **operational** half: when membership
changes, every active member's local view converges to the new
list, so a removed peer falls out of every sender's fanout
naturally.

That's not a cryptographic guarantee. It's better than what we
had (silent local-only changes), and it's what reviewers will
expect to see before MLS lands.

THREAT_MODEL.md TM-01 downgraded High → Medium with the partial
status, and the non-guarantees row reworded to spell out
"membership consensus yes / cryptographic PCS no".

## What landed

### Wire format (additive)

New optional `kind`:

  `group_member_change`
    fields: `group_id`, `group_name`, `action` ("add"|"remove"),
            `target` (peer_id), `members` (full new list)

Per PROTOCOL.md §10.2 a 1.0 receiver that doesn't implement this
kind drops it silently — additive, no breakage. Documented in
§8.1 of the spec.

`WIRE_VERSION` stays at 1.

### Code

`src/malphas/node.py`

  `KIND_GROUP_MEMBER_CHANGE` constant.
  `_handle_group_member_change(data, from_id)` — validates that
    the sender is a current member or the creator (defends
    against an outsider who guessed the group_id rewriting our
    local view), reconciles `group.members` to the sender's
    list, and notifies the application.
  `_fanout_group_member_change(group, action, target, exclude=)`
    — sends the notification to every active member except
    ourselves and any excluded peer (typically the target of a
    removal: they don't get the notification through the group
    channel).
  `add_group_member`: after sending the invite to the new joiner,
    fans the change to existing members.
  `remove_group_member` (new, async): removes locally and fans
    the change to remaining members.
  `leave_group_async` (new): notifies remaining members before
    dropping the group from local registry. The synchronous
    `leave_group` is kept for backwards compatibility with
    existing callers.
  `_notify_group_member_change` + `on_group_member_change`
    callback registration.

### Tests

`tests/test_groups.py` — 4 new integration tests on the existing
3-node fixture:

  test_add_member_notifies_existing_members
    A creates {A,B}, then adds C. B receives a member_change
    with action=add, target=C, members containing C. B's local
    view now includes C.

  test_remove_member_excludes_them_from_future_fanouts
    A creates {A,B,C}, then removes B. C receives a
    member_change with action=remove, target=B. C's local view
    now excludes B.

  test_leave_async_notifies_remaining_members
    A creates {A,B,C}, then B calls leave_group_async. A and C
    both receive a member_change with action=remove, target=B.

  test_member_change_from_outsider_is_rejected
    C, who was never invited, sends a forged member_change to A
    claiming "add C to the group". A rejects: the authorization
    check (sender must be a current member or creator) holds.

All 4 pass. Existing 11 group tests still pass (15/15 total).

### Docs

`PROTOCOL.md` §8.1 lists `group_member_change`. §13 reworded to
distinguish the operational `group_member_change` (already
shipped) from the cryptographic `member_ratchet` (still TBD).

`THREAT_MODEL.md` §5 TM-01 downgraded High → Medium "partial",
and the non-guarantees row about group forward secrecy reworded
to "membership consensus yes; cryptographic PCS no".

## Version

1.0.0rc2 → 1.0.0rc3 (additive wire change + TM-01 partial fix).

## Next iter

Two candidates:

- iter-056: TM-08 reproducible builds. Pin hatchling, set
  `SOURCE_DATE_EPOCH`, document the build environment in
  RELEASE.md, ship a Docker build image. Mostly tooling.

- iter-057: protocol test vectors (PROTOCOL.md §14 explicit
  gap). Capture fixed (input_bytes → expected_ciphertext)
  vectors for sealed_sender, ratchet, onion, mnemonic. These
  pin the wire format against silent drift across refactors.

I'll take iter-056 first — it's a release-process gate; until
the build is reproducible we can't credibly ship a stable 1.0.
