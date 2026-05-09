# Changelog

All notable changes to malphas are tracked here. Format roughly Keep-a-Changelog;
versioning is SemVer with the caveat that wire-format-breaking changes always bump minor or major.

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
