# Changelog

All notable changes to malphas are tracked here. Format roughly Keep-a-Changelog;
versioning is SemVer with the caveat that wire-format-breaking changes always bump minor or major.

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
