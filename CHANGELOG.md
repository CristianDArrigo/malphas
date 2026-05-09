# Changelog

All notable changes to malphas are tracked here. Format roughly Keep-a-Changelog;
versioning is SemVer with the caveat that wire-format-breaking changes always bump minor or major.

## [0.7.0] — 2026-05-09 — WIRE-BREAKING

### Security

- **Per-user Argon2 salt** closes finding **B2** from the iter-001
  review. Until 0.6.x, the Argon2 salt was the hardcoded constant
  `b"malphas-kdf-salt"`, identical for every user — a single
  precomputed rainbow table would target the whole world. Now a
  16-byte random salt is generated once per install and persisted to
  `~/.malphas/salt` (mode 0600, atomic write).
- The salt path is configurable: `malphas --salt <path>`.

### Implementation

- New `malphas.salt_store` module with `load_or_create_salt(path)`:
  reads existing 16-byte file or atomically generates one. Refuses
  to silently overwrite a wrong-length file.
- `identity._derive_seed`, `create_identity`, and
  `create_identity_with_book_key` now take an optional `salt` kw arg.
  `salt=None` falls back to the legacy global constant for
  backward-compatible test paths only — production CLI passes the
  per-user salt explicitly.
- `__main__.py` loads/creates `~/.malphas/salt` before deriving the
  identity (both CLI and web modes).
- New `tests/test_salt_store.py`: 8 unit tests (create, read,
  parent-dir creation, freshness across paths, mode 0600,
  wrong-length error, dir-as-path error, no tmp leftover).
- Mypy strict bucket extended to 16 modules.

### Threat model

Add to "Protected against": "Rainbow tables across users — the KDF
salt is per-user random, not a global constant."

Add to "Not protected against": "Loss of `~/.malphas/salt` — without
the file (and without a BIP39 backup, planned for 0.7.x), the same
passphrase produces a fresh identity that no existing peer recognizes."

### Wire format / identity stability

WIRE-BREAKING. Even with the same passphrase, a 0.7.0 install on a
different machine derives a different identity because the salt is
random per machine. To migrate an identity across machines:
  • Copy `~/.malphas/salt` along with the passphrase, or
  • (Coming in 0.7.1) restore from a BIP39 mnemonic.

## [0.6.0] — 2026-05-09 — WIRE-BREAKING

### Security

- **Sealed sender**: the `from` field in the inner JSON payload is now
  encrypted against the recipient's static X25519 pubkey instead of
  being shipped plaintext. Wire format change:

  ```
  prev (≤0.5.x):  {"from": "<peer_id>", ...}
  now  (0.6.0):   {"from_eph": "<32-byte hex>",
                   "from_sealed": "<base64 ChaCha20-Poly1305>",
                   ...}
  ```

  Threat addressed: post-compromise observation. If an attacker
  recovers the session key of any hop along an onion circuit (or of
  the first hop's TCP session) and replays a captured packet through
  the peeling, today the inner JSON would leak `from`. With sealed
  sender, only the recipient's X25519 private key (still derived from
  the recipient's passphrase, never on the wire) can recover the
  sender's peer_id. The HMAC/Ed25519 outer auth tag still covers the
  whole JSON, so an attacker cannot swap the sealed envelope.

  Approach modeled after Signal's sealed sender, simplified to
  malphas's no-server architecture.

### Internal

- New `malphas.sealed_sender` module with `seal()` and `unseal()`.
  HKDF context `malphas-sealed-sender-v1`, info `from`. Mypy strict
  bucket extended to 15 modules.
- New `tests/test_sealed_sender.py`: 9 unit tests (roundtrip, fresh
  ephemeral per call, fresh nonce per call, wrong recipient, tampered
  eph_pub, tampered ciphertext, malformed inputs).
- `node.py` now seals on every send site (`_try_send`,
  `_send_receipt`, `_try_send_payload`) and unseals via
  `_resolve_sealed_from()` on the receive paths.
- Smoke test: serialized payload bytes no longer contain the sender's
  peer_id.

### Wire format

WIRE-BREAKING. A 0.6.0 client cannot decode a ≤0.5.x message and vice
versa. Upgrade both peers before the cut-over.

## [0.5.8] — 2026-05-09

### Community / repo hygiene

- `CONTRIBUTING.md` — onboarding, local setup, gate stack, style,
  wire-breaking change policy, threat-model-relevant checklist,
  in/out scope notes.
- `.github/PULL_REQUEST_TEMPLATE.md` — type of change, threat-model
  impact, local-checks checklist (incl. CHANGELOG + strict bucket
  bookkeeping).
- `.github/ISSUE_TEMPLATE/bug_report.yml` — structured bug form with
  version/python/OS/transport fields and a "do NOT file security
  issues here" header.
- `.github/ISSUE_TEMPLATE/feature_request.yml` — proposal form that
  routes proposers to `docs/auto-loop/SUMMARY.md` first.
- `.github/ISSUE_TEMPLATE/config.yml` — blank issues disabled;
  routes security to GitHub Security advisories and "how do I …"
  questions to Discussions.

### Wire format

Unchanged.

## [0.5.7] — 2026-05-09

### User-facing

- New `--version` flag on the CLI: `malphas --version` prints
  `malphas <X.Y.Z>` and exits 0.
- `malphas.__version__` is now resolved at runtime from the installed
  package metadata (`importlib.metadata.version("malphas")`). No more
  drift between `pyproject.toml` and a hardcoded constant.

### Engineering

- New `src/malphas/py.typed` marker (PEP 561). Downstream consumers
  that import `malphas` now get full type-checking support against
  our annotated source.
- `[tool.hatch.build.targets.wheel.force-include]` ensures the marker
  ships in built wheels.
- Closes finding **C7** from the iter-001 review (`__init__.py`
  exposed an obsolete hardcoded `__version__`).

### Wire format

Unchanged.

## [0.5.6] — 2026-05-09

### Dev tooling

- New `.github/dependabot.yml` — weekly grouped PRs for pip and
  github-actions ecosystems. Minor/patch bumps grouped per ecosystem
  to keep review noise low.
- New `.pre-commit-config.yaml` — mirrors `scripts/check.sh --quick`:
  ruff (with `--fix`), mypy on the whole package (so strict-bucket
  overrides apply), bandit, plus stock hygiene hooks (trailing
  whitespace, EOF newline, YAML/TOML syntax, merge-conflict markers,
  large file guard at 512 KB).
- README "CI quality gates" subsection now documents the
  `pre-commit install` flow and the dependabot grouping.

### Wire format

Unchanged.

## [0.5.5] — 2026-05-09

### Documentation

- New `docs/auto-loop/SUMMARY.md` — cumulative overview of the entire
  autonomous-loop session (iter 1 through 38). Maps every iter to its
  release, summarizes by area what changed, lists what was deliberately
  NOT touched and why, and proposes next steps for the user. Designed
  as a single re-entry point.
- `docs/auto-loop/INDEX.md` now links to SUMMARY.md as the first stop.

### Wire format

Unchanged.

## [0.5.4] — 2026-05-09

### Engineering

- **Single source of truth for the mypy strict bucket.**
  - The strict bucket lives in one place: `pyproject.toml`
    `[[tool.mypy.overrides]] strict = true`.
  - The lenient bucket (node, transport, api, cli_ui, __main__,
    splash) gets its own override that disables the mypy 2.x
    strict-by-default error codes (`no-untyped-def`,
    `no-untyped-call`, `type-arg`, etc.) ONLY for those modules.
  - The CI workflow and `scripts/check.sh` now invoke a single
    `mypy src/malphas/` instead of listing 14 files. The two no
    longer drift when the bucket is extended — the list moves once,
    in `pyproject.toml`.
  - Verified the strict gating still bites: an untyped function added
    to a strict-bucket module still triggers `no-untyped-def`; the
    same change in a lenient-bucket module does not.
- 21 source files type-check cleanly (14 strict + 6 lenient + 1
  package init) under the consolidated invocation.

### Wire format

Unchanged.

## [0.5.3] — 2026-05-09

### Dev tooling

- New `scripts/check.sh`: single-command local mirror of the CI gate
  stack. Runs ruff → mypy --strict (14 modules) → bandit → pytest
  --cov in fail-fast order. Honors `$PYTHON` env var; auto-detects
  `./.venv/bin/python` if present.
- Flags:
  - `--quick` — skip pytest, intended for pre-commit hooks.
  - `--no-coverage` — run pytest without the coverage gate (faster
    when iterating on a single test).
- README "CI quality gates" subsection now references the script and
  lists all 14 strict modules.

### Wire format

Unchanged.

## [0.5.2] — 2026-05-09

### Engineering

- Mypy strict bucket extended from 11 modules to **14**: now also
  includes `identity`, `onion`, `addressbook`.
- 3 type errors fixed (annotation-only):
  - `addressbook.Contact.to_dict / from_dict`: `dict` → `dict[str, Any]`.
  - `identity.create_identity_with_book_key`: `tuple` → `tuple[Identity, bytes]`.
- 111 focused tests still green. ruff + bandit clean.
- CI workflow updated.

### Wire format

Unchanged.

## [0.5.1] — 2026-05-09

### Engineering

- Mypy strict bucket extended from 8 modules to **11**: now includes
  `discovery`, `receipts`, `ratchet` in addition to `replay`, `crypto`,
  `memory`, `obfuscation`, `pinstore`, `invite`, `files`,
  `secure_buffer`.
- 21 type errors fixed across the three new modules:
  - `ratchet.py`: explicit `assert ... is not None` guards in
    `encrypt`/`decrypt`/`_dh_ratchet`/`_skip_messages` for the
    invariants that the algorithm already maintained at runtime;
    `__init__` annotated `-> None`; `_skipped` indexing now uses a
    locally-bound `remote_pub` reference to satisfy the type checker.
  - `receipts.py`: `Ed25519PrivateKey`/`Ed25519PublicKey` annotations on
    `sign_receipt`/`verify_receipt`/`resolve`; new `ReceiptCallback`
    and `TimeoutCallback` aliases; `_maybe_call` typed and now no-ops
    on a `None` callback.
  - `discovery.py`: `to_dict` returns `dict[str, Any]`; `_mdns_task`
    typed as `asyncio.Task[None] | None`.
- All annotation tightening only; no behavior change. 244 focused tests
  still green. ruff + bandit clean.
- CI workflow updated to mypy-strict the new modules too.

### Wire format

Unchanged.

## [0.5.0] — 2026-05-09 — WIRE-BREAKING

### Wire format

- `peer_id` is now derived as `BLAKE2s(ed25519_pub, digest_size=20)`
  instead of `SHA1(ed25519_pub)`. Both produce a 160-bit identifier
  hex-encoded to 40 characters; storage formats, regexes
  (`[0-9a-f]{40}`), and the on-wire 20-byte raw form are unchanged.
  But the value of every existing peer_id changes — a 0.5.0 peer and a
  0.4.x peer derive different identifiers from the same passphrase.

### Security

- BLAKE2s replaces SHA1 as the peer_id hash. SHA1 was flagged by
  bandit (B324) and was using the construction in a way that, while
  not directly security-critical (the value is an identifier, not a
  capability), still surfaced as a red flag in any review. BLAKE2s is
  collision-resistant by design and faster on small inputs.
- The bandit `B324` and ruff `S324` global skips have been removed.
  The two test sites that benchmark Argon2 against SHA1 keep an
  inline `# noqa` with `usedforsecurity=False`.

### Internal

- New `tests/test_security_argon2_panic.test_peer_id_is_blake2s_not_sha1`
  regression guard.
- `tests/test_security_identity.test_peer_id_is_blake2s_of_ed25519_pubkey`
  replaces the previous SHA1-based invariant test.
- Comments in `discovery.py` and `onion.py` updated.
- Module docstring in `identity.py` rewritten.

### Wire format

Wire-breaking. A 0.5.0 client cannot communicate with a 0.4.x client.
Upgrade both peers before the cut-over.

## [0.4.0] — 2026-05-09 — WIRE-BREAKING

### Wire format

Inner authenticated payload (post-onion-peel, post-padding-strip) is now
prefixed with an explicit one-byte auth-type tag:

```
prev (0.3.x):   tag(32 HMAC | 64 Ed25519) || JSON
                or  b"R" || ratchet_header(40) || ciphertext

now  (0.4.0):   b"H" || tag(32) || JSON
                b"E" || sig(64) || JSON
                b"R" || ratchet_header(40) || ciphertext
```

A 0.4.0 client cannot decode a 0.3.x message and vice versa — there is
no compatibility shim by design. Upgrade both peers before the cut-over.

### Security

- Eliminates the trial-JSON-parse heuristic the previous receiver used
  to discriminate HMAC (32-byte tag) from Ed25519 (64-byte sig). A
  carefully-crafted payload could in principle fool that heuristic
  into picking the wrong path. The explicit prefix removes the
  ambiguity.
- The ratchet path (`b"R"`) was already prefixed and is unchanged at
  the wire level beyond living next to the new prefixes.

### Internal

- New module-level helper `_wrap_authenticated(payload, conn, identity)`
  centralizes the selection (ratchet → HMAC → Ed25519) and prepends
  the right prefix. Three call sites in `node.py` now share one path.
- New constants `AUTH_RATCHET = b"R"`, `AUTH_HMAC = b"H"`,
  `AUTH_ED25519 = b"E"`, `HMAC_TAG_LEN = 32`, `ED25519_SIG_LEN = 64`,
  `RATCHET_HEADER_LEN = 40` replace the previous magic numbers.
- `_deliver` no longer probes JSON at offsets 32 / 64; it dispatches
  directly on the prefix byte.
- 269+ tests still green (full focused suite passed locally).

## [0.3.7] — 2026-05-09

### Documentation

- README: **Threat Model** updated. Replay protection and the
  `SecureBytes`-wrapped Argon2 seed are now in the "Protected against"
  list; the "Not protected against" entry on RAM exposure is qualified
  to make clear that `mlock` covers the seed only, against swap, not
  against `/proc/$pid/mem`.
- README: new **CI quality gates** subsection with the full table
  (ruff, mypy strict, bandit, coverage, hypothesis) and the local
  invocation cheatsheet.
- README: new **Web API endpoints** table covering all 9 REST routes
  plus the `/ws` WebSocket and its three push event types.
- README: **Test suite** table extended with the seven test files
  added during the auto-loop (replay, microfixes, files, cli_files,
  api_files, secure_buffer, fuzz_parsers).
- README: **Project structure** lists the three new modules
  (`replay.py`, `files.py`, `secure_buffer.py`).

### Wire format

Unchanged. Closes the v0.3.x mini-release line; v0.4.0 will open the
wire-breaking changes track.

## [0.3.6] — 2026-05-09

### Features

- **Web API for file transfer** — five new endpoints in `api.py`,
  symmetric to the iter-012 CLI commands:
  - `POST /api/files/send` — multipart upload + `node.send_file`
    dispatch; returns `{file_id}`.
  - `GET  /api/files` — JSON `{pending: [...], completed: [...]}`.
  - `POST /api/files/accept` — register an incoming offer.
  - `POST /api/files/reject` — drop a pending offer.
  - `GET  /api/files/{file_id}/download` — stream the assembled
    payload, then drop the in-RAM copy (zero-disk policy).
- WebSocket pushes two new message types:
  `{type: "file_offer", from, offer}` and
  `{type: "file_complete", file_id, from, name, size}`.
- `python-multipart>=0.0.9` added to runtime deps (required by FastAPI
  multipart support).
- Filenames in `Content-Disposition` are sanitized — only
  `[A-Za-z0-9._-]` survive, slashes stripped, max 128 chars.

### Internal

- 14 new tests in `tests/test_api_files.py` (httpx + ASGITransport).
- Removed `from __future__ import annotations` from `api.py`: pydantic
  v2 cannot resolve forward-referenced inner classes for body models.
  The other modules retain it.

### Wire format

Unchanged. Web API state lives in-process and is mutually exclusive
with the CLI state (one mode per process invocation).

## [0.3.5] — 2026-05-09

### Engineering

- **Coverage gate** in CI: `pytest --cov --cov-fail-under=65`. Branch
  coverage enabled. Initial threshold deliberately conservative; will
  be tightened once test_api / test_cli / test_functional_node are
  routinely included in the local dev workflow.
- **Bandit** static security scan added to the lint CI job (blocking).
  Configured via `[tool.bandit]` in `pyproject.toml` with skips for the
  patterns that match malphas's design intent (B101 asserts in tests,
  B104 bind 0.0.0.0, B110/B112 fail-closed silent drops, B311 stdlib
  random for jitter, B324 SHA1 as identifier — fix planned for 0.4.0,
  B404/B603/B607 subprocess for Tor HS setup, B105 false positive on
  passphrase overwrite). Currently 0 findings on the source tree.
- New dev deps: `pytest-cov>=5`, `bandit>=1.7`.
- `pyproject.toml`: `[tool.coverage.*]` configured with branch coverage,
  excluding tests, `__main__.py`, and `cli_ui.py` from the coverage
  source set.

### Wire format

Unchanged.

## [0.3.4] — 2026-05-09

### Quality

- New `tests/test_fuzz_parsers.py`: Hypothesis-driven property tests
  on the four parsers that ingest untrusted bytes — `peel_layer`
  (onion), `unpad_payload`, `parse_invite`, and `FileOffer.from_dict`.
  ~1600 randomized examples per CI run.
- Established the contract: each parser may only raise its declared
  exception types; any other escape is treated as a regression.
- The existing implementations cleared the fuzz at first run on
  ~1200 random inputs; no parser fixes required. The tests stay in
  CI as a permanent net.

### Internal

- `hypothesis>=6` added to dev deps.
- `.gitignore`: `.hypothesis/` (cache directory).

### Wire format

Unchanged.

## [0.3.3] — 2026-05-09

### Security

- New `malphas.secure_buffer.SecureBytes`: a wiped-on-drop, mlock-when-
  possible byte buffer for sensitive material. Implementation:
  - `bytearray` storage that can be overwritten in place.
  - Best-effort `libc.mlock` on POSIX so pages aren't paged to swap.
    Failures degrade silently — defense in depth, not a hard guarantee.
  - Zeroization on `wipe()`, `__exit__`, and `__del__`.
  - Constant-time equality.
- `identity._derive_seed` now returns a `SecureBytes`. Both
  `create_identity` and `create_identity_with_book_key` consume the
  seed inside a `with` block so the Argon2 output is wiped before the
  function returns. The derived `book_key` continues to be returned as
  plain `bytes` for compatibility with `AddressBook`/`PinStore`;
  tightening that surface is future work.

### Internal

- 13 new tests in `tests/test_secure_buffer.py` covering construction,
  wipe lifecycle, slicing/iteration semantics, constant-time equality,
  context-manager wipe-on-exit, and graceful mlock failure.
- `malphas.secure_buffer` added to the mypy strict bucket.
- `_derive_seed`'s callers refactored to use the new context-manager
  pattern; one downstream test (`test_security_crypto.test_identity_
  and_book_key_use_different_contexts`) materializes a `bytes(seed)`
  copy before passing to the cryptography library.

### Wire format

Unchanged.

## [0.3.2] — 2026-05-09

### Documentation

- README: new top-level "File Transfer" section between "Read Receipts"
  and "Resilience". Documents constraints, wire format extension,
  default consent policy, full quickstart with `/sendfile` →
  `/accept` → `/savefile`, list of features intentionally out of scope.
- README: `Architecture` diagram updated to show `ReplayCache` and
  `FileTransferManager`, and the jitter on `AutoReconnect`.
- README: `CLI Reference` updated with the five new commands.
- README: TOC reflects the new section.

### Wire format

Unchanged.

## [0.3.1] — 2026-05-09

### Features

- **CLI for file transfer**: five new commands integrate `malphas.files`
  with the interactive CLI:
  - `/sendfile <peer|label> <path>` — send a file to a peer.
  - `/accept <file_id>` — accept a pending incoming offer.
  - `/reject <file_id>` — drop a pending incoming offer.
  - `/savefile <file_id> <path>` — write a completed file to disk.
  - `/files` — list pending and completed transfers.
- Tab completion includes the new commands.
- The CLI shows inline notifications when an offer arrives ("offer from
  alice: photo.jpg (1234 bytes) — /accept abc...") and when a transfer
  completes ("received photo.jpg (1234 bytes) from alice — /savefile
  abc... <path>").

### Internal

- `MalphasCLI._pending_offers` and `_completed_files` track UI state
  per file_id. `_on_file_offer` and `_on_file_complete` are wired to
  the node callbacks.
- 12 new unit tests in `tests/test_cli_files.py`.

### Wire format

Unchanged.

## [0.3.0] — 2026-05-09

### Features

- **File transfer**: P2P chunked file transfer using the existing onion
  pipeline. New `MalphasNode.send_file(dest, path)` returns a `file_id`,
  fires three new payload kinds — `file_offer`, `file_chunk`, `file_ack` —
  and reassembles the stream in RAM on the receiver. SHA-256 integrity
  verified end-to-end. 32 KB chunks, 100 MB cap. Order-independent and
  idempotent (chunks dedup by index).
- New `FileTransferManager` registry on every node, with `auto_accept_files`
  switch, `accept_file_offer` for explicit consent, and `on_file_offer` /
  `on_file_complete` callbacks.

### Internal

- New module `malphas.files`: `OutgoingFile`, `IncomingFile`,
  `FileTransferManager`. 14 tests (12 unit + 2 integration) added.
- `MalphasNode._dispatch_kind` centralized: replay protection now applies
  uniformly across `msg`, `receipt`, `file_offer`, `file_chunk`, `file_ack`.
- `_try_send_payload` generalizes `_try_send` for arbitrary payload kinds
  (auth/ratchet → HMAC → Ed25519 → padding → onion → ship).
- `panic()` wipes in-flight file transfers.
- `malphas.files` added to the mypy strict bucket.

### Wire format

Backward compatible. Older clients silently drop unknown kinds.

## [0.2.4] — 2026-05-09

### Engineering

- Mypy is now wired into CI on a "strict bucket" rollout. Modules that
  type-check cleanly under `--strict` are pinned via per-module overrides
  in `pyproject.toml`; the rest of the tree runs in non-strict mode and
  will be tightened iteration by iteration.
- Strict bucket extended to: `malphas.replay`, `malphas.crypto`,
  `malphas.memory`, `malphas.obfuscation`, `malphas.pinstore`, `malphas.invite`.
- 13 type errors resolved across these modules (no behavior change — pure
  annotations).
- New CI step `Mypy strict bucket` added to the `lint` job.

### Wire format

Unchanged.

## [0.2.3] — 2026-05-09

### Engineering

- `ruff` is now wired into CI as a blocking lint step (Python 3.12). Style,
  bug-prone patterns, security hints, and import order are checked on every
  push and PR.
- 223 auto-fixable findings cleaned up across `src/` and `tests/` (typing
  modernization to PEP 585/604, import sorting, unused imports, f-string
  hygiene). No behavior change.
- Triaged backlog of intentional patterns left in place with documented
  rationale (`S110`, `S324`, `S603`, `S104`, …).
- New CI job `lint` runs in parallel with `test`.

### Wire format

Unchanged.

## [0.2.2] — 2026-05-09

### Security

- Circuit relays are now selected via `secrets.SystemRandom` (OS entropy)
  instead of the stdlib `random` module. Predictable circuits would let an
  attacker bias which relay sees which message.
- Reconnect backoff now applies ±20% jitter (also via `SystemRandom`) to
  avoid the thundering-herd pattern when many peers behind the same NAT
  retry in lockstep.

### Bug fixes

- `MessageStore` TTL is now computed against `time.monotonic()` instead of
  `time.time()`. A backwards NTP correction will no longer leave messages
  alive past their intended expiry.

### Docs

- `identity.py` module docstring no longer claims SHA1-based passphrase
  derivation (Argon2id has been used since 0.1.x).
- New `CHANGELOG.md` and `SECURITY.md`.

### Internal

- New `tests/test_microfixes.py` (5 tests).

### Wire format

Unchanged.

## [0.2.1] — 2026-05-09

### Security

- **Replay protection**: every successfully delivered message is recorded in
  an in-memory replay cache keyed by `(from_peer_id, msg_id)`. Replays of the
  same packet are dropped silently — no second user-visible delivery, no
  second store write, no second receipt. The cache is bounded (10000 entries,
  FIFO eviction) and entries expire on the same TTL as the message store.
  Closes a gap on the HMAC and Ed25519 fallback delivery paths where the
  Double Ratchet's per-message counter does not run.

### Internal

- New module `malphas.replay` (`ReplayCache`).
- `MalphasNode._deliver_message` now drops replays.
- `panic()` wipes the replay cache.
- `_purge_loop` purges expired replay entries every 60 s.
- New `tests/test_replay_protection.py` with 14 tests (8 unit + 6 integration).
- New `docs/auto-loop/` documentation pipeline for autonomous iterations.

### Wire format

Unchanged.

## [0.2.0] — 2026-04-06

### Added

- Double Ratchet (Signal-style) for per-message forward secrecy on top of
  the session ChaCha20-Poly1305 transport encryption.
- Tor v3 hidden service persistent registration via stem + control port.
- Auto-reconnect with exponential backoff for address book peers.
- mDNS optional discovery via zeroconf.
- Cover traffic engine with randomized 10–40 s intervals.

### Changed

- Address book key now derived from a separate HKDF context than the identity
  keypair (cryptographically independent).

### Security

- Argon2id (64 MB / ~200 ms) for passphrase → seed derivation, replacing the
  previous SHA1 + HKDF approach.
- TOFU pin store for Ed25519 identity keys.
- Mutual handshake authentication via Ed25519-signed ephemeral key.
