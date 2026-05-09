# iter-054 — TM-05 constant-time compare audit

**Date:** 2026-05-09
**Trigger:** scheduled follow-up to iter-053 (THREAT_MODEL.md
TM-05).

## What I audited

Greppable comparisons across `src/malphas/`. For each, decided
whether a non-constant-time compare leaks anything an attacker
could exploit.

| Site                                                        | Verdict                  |
|-------------------------------------------------------------|--------------------------|
| `crypto.hmac_verify`: `_hmac.compare_digest(...)`           | already constant-time ✓ |
| `secure_buffer.__eq__`: `_hmac.compare_digest(...)`         | already constant-time ✓ |
| `pinstore.check_and_pin`: `existing == pub_hex`             | **fixed** — now uses `compare_digest` |
| `files.IncomingFile.assemble`: SHA-256 hexdigest compare    | **fixed** — now uses `compare_digest` |
| AEAD verify (Poly1305 in `crypto.decrypt`)                  | constant-time inside `cryptography.hazmat` ✓ |
| Ed25519 / X25519 `verify(...)` in `cryptography.hazmat`     | constant-time inside `cryptography.hazmat` ✓ |
| `node._dispatch` peer_id routing                            | peer_id is a public 40-char identifier — no secret to leak |
| `addressbook.find_by_label`, label/peer_id filters          | labels are user input, peer_ids public; comparison happens after decrypt |
| `discovery` peer_id filters                                 | public identifiers          |
| `onion.peer_id_from_bytes` final-hop marker                 | comparing decrypted plaintext against a public sentinel; leaks only "is this the final hop" which is observable from behaviour anyway |

## Code changes

- `src/malphas/pinstore.py`: pinned-key match now uses
  `hmac.compare_digest`.
- `src/malphas/files.py`: SHA-256 integrity compare now uses
  `hmac.compare_digest`.

## New tests

`tests/test_constant_time.py` — 9 cases:
- Source-grep guards on `pinstore.py`, `files.py`,
  `crypto.hmac_verify` (regression-detect if someone refactors
  back to `==`).
- Behavioural smoke for `hmac_verify` (accept correct, reject
  wrong).
- `PinStore` first-contact / second-contact / key-mismatch.
- `IncomingFile.assemble` matching-hash / mismatched-hash.

All 9 pass. Existing 57 tests across `pinstore`, `files`,
`gui_qt` still pass too.

## THREAT_MODEL.md update

TM-05 closed. The row now reads:

> resolved (iter-054). `pinstore` and `files` integrity check
> now use `hmac.compare_digest`. Other comparisons either go
> through `cryptography.hazmat` (constant-time by construction)
> or compare public identifiers where timing leaks no secret.
> Regression-tested in `tests/test_constant_time.py`.

## Version

1.0.0rc1 → 1.0.0rc2 (additive: same wire, tightened
side-channel posture; rc number bumps so reviewers can tell the
audited build apart).

## Next iter

iter-055 — TM-01 group key rotation on member removal. Plan: a
new optional `member_ratchet` kind that rotates each pairwise
ratchet when a member is added or removed. Receivers in 1.0
that don't yet implement it must ignore unknown kinds (already
specified in PROTOCOL.md §10.2). Wire-compatible.
