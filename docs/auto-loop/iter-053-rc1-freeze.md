# iter-053 — wire freeze + threat model + protocol spec → 1.0.0-rc1

**Date:** 2026-05-09
**Trigger:** user, after the "a che punto è malphas?" honest
assessment, asked to "fai questi 3 e sistema tutti gli zoppichi"
(do the three things I called out + fix all the limps).

The three:

1. write a real threat model
2. freeze the wire format and declare an RC
3. prepare the package an external reviewer would need

Plus: known limps (constant-time audit, group key rotation,
release process, pre-existing CLI test). This iter closes (1)
and (2) fully and lands the deliverables for (3); the limps go
into iter-054+.

## What landed

### Documents

- `THREAT_MODEL.md` — five adversary profiles (A1–A5),
  guarantees / non-guarantees table, attack-scenarios grid,
  TCB inventory, eleven tracked weakness IDs (TM-01 … TM-11),
  operational guidance for users.
- `PROTOCOL.md` — full wire-format spec. Frame layout (§4),
  handshake JSON (§5), onion layering (§6), `auth_type` byte
  values (§7), every `kind` value (§8), sealed-sender
  envelope (§8.2), versioning rules (§10) including the
  freeze policy from `1.0.0-rc1`.
- `REVIEW_REQUEST.md` — self-contained brief for a reviewer:
  what to look at, where, the seven specific questions the
  author has open. Disclosure window 30 days from first
  reply.
- `RELEASE.md` — pre-release checklist, signed-tag procedure,
  reproducible-build gap tracker.

### Code

- `src/malphas/__init__.py`: exposed `WIRE_VERSION = 1` at
  package level so external tooling can compatibility-check
  without importing `node`.
- `src/malphas/node.py`: defined `WIRE_VERSION = 1`,
  embedded it in the handshake JSON as `"v"`, and made the
  receiver lenient on missing (older clients) but strict on
  mismatch (future bump = refuse to talk).
- `pyproject.toml`: bumped to `1.0.0rc1`.
- `README.md`: threat-model section now points to the full
  `THREAT_MODEL.md` and the `1.0.0-rc1` tag.

## Wire-format compatibility check

Pre-1.0 0.11.x clients still connect: they don't send `"v"`,
the new code accepts the missing field. New 1.0.0-rc1 clients
talk to each other with explicit `"v": 1` matched. A future
`WIRE_VERSION = 2` from a 1.x peer will be refused by a 1.0
peer — by design.

## What this iter does NOT close

Tracked for iter-054+:

- TM-01 group MLS / key rotation on member removal
- TM-05 constant-time compare end-to-end audit
- TM-08 reproducible builds
- TM-11 pre-existing CLI test failure
- Test vectors in `tests/test_protocol_vectors.py`
  (PROTOCOL.md §14 explicit gap)
- Pin-store key derivation switch to a separate HKDF info
  string (PROTOCOL.md §13)
- External review itself — the package is now ready to send,
  the human work is downstream.

## Next iter

iter-054 — TM-05 (constant-time audit) is the cheapest and
highest leverage. Ten or so call sites, mechanical fix where
needed, regression test that the comparators are
`hmac.compare_digest`. Then iter-055 — TM-01 group rotation:
drop a `member_ratchet` kind that rotates per-member keys on
add/remove. Then iter-056 — release process (signed tag,
build pipeline, RELEASE.md tightened up).
