# iter-057 — TM-11 cli mock + protocol test vectors

**Date:** 2026-05-09
**Trigger:** scheduled. Closes the last two autonomous-doable
items before only TM-02 (external review) blocks `1.0.0` final.

## TM-11 — closed

`tests/test_cli.py::test_chat_by_label_auto_connects` (and a
handful of other CLI tests touching the chat surface) failed
with `Mock object has no attribute '_groups'` because the
`mock_node` fixture was last updated before `_groups` was added
to `MalphasNode` in 0.9.0.

Fix: the fixture now provides a real `GroupRegistry()` for
`_groups`. Trivially right; the comment in-place flags the
0.9.0 timing so future-me doesn't re-introduce the same gap on
the next attribute the CLI starts reading.

Result: the full CLI suite (132 tests) now passes.

## Protocol test vectors — landed

`tests/test_protocol_vectors.py`, 20 cases. Closes
PROTOCOL.md §14's "None exist yet" gap.

Two vector flavours:

  Deterministic
    Identity derivation (passphrase-only path; same passphrase →
    same peer_id / x25519_pub / ed25519_pub byte-for-byte).
    BIP39: `b"\x00"*16` and `b"\xff"*16` against the canonical
    English wordlist (`"abandon ... about"` and `"zoo ... wrong"`).
    HKDF-SHA256 KAT pinning one exact 32-byte output.
    HMAC-SHA256 sign+verify round-trips.
    derive_hmac_key domain-separation.
    derive_session_key symmetry: A and B compute the same value
    regardless of pub-key ordering.

  Round-trip / invariant
    Sealed sender (random ephemeral key per call): format
    invariants (eph 64 hex, base64 ≥ nonce+tag) + decrypt.
    Sealed sender ephemeral-key freshness: two seals of the
    same plaintext yield distinct from_eph values.
    3-hop onion: wrap → strip routing prefix → peel × 3 →
    plaintext recovered, intermediate hops report next_hop
    correctly.
    AEAD with AAD: round-trip + AAD mismatch raises.
    ECDH agreement symmetry.

Updated `PROTOCOL.md` §14 from "to be added" to a full
description of what's implemented, with the pinned constants
called out explicitly (mnemonic vectors, HKDF KAT) so a
reviewer can grep the file and see them.

## Threat-model status

| ID    | Status                | Closed in  |
|-------|-----------------------|------------|
| TM-01 | Medium partial        | iter-055   |
| TM-02 | Open                  | external review needed |
| TM-03 | Resolved              | rc1        |
| TM-04 | By design             | TOFU window |
| TM-05 | Resolved              | iter-054   |
| TM-06 | Open (low priority)   | future     |
| TM-07 | Open (low priority)   | future     |
| TM-08 | Resolved              | iter-056   |
| TM-09 | By design             | receipt omission |
| TM-10 | Low                   | padding granularity |
| TM-11 | Resolved              | iter-057 (this iter) |

After this iter, only **TM-02** (external review) and the two
"low priority" / "by design" items block `1.0.0` final. The
auto-loop has done what an autonomous agent can do; the rest is
a human review cycle.

## Version

1.0.0rc4 → 1.0.0rc5 (additive: same wire, new tests + doc
update; rc number bumps so a reviewer can tell the
test-vector-bearing build apart).
