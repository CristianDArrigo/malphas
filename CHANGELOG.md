# Changelog

All notable changes to malphas are tracked here. Format roughly Keep-a-Changelog;
versioning is SemVer with the caveat that wire-format-breaking changes always bump minor or major.

## [1.0.0-rc7] — 2026-06-16

A full independent security audit of the whole tree (crypto, protocol,
anonymity, DoS, at-rest, UI), with every HIGH finding verified against the
code, plus a Qt GUI visual refresh. The core cryptography held; the fixes
close anonymity, MITM, DoS and untrusted-content vectors at the edges.
Regression tests in `tests/test_audit_fixes.py`.

### ⚠️ Breaking — wire format (`WIRE_VERSION` 1 → 2)

The audit motivated two intentional, breaking changes. rc7 nodes do **not**
interoperate with rc6 and earlier — **all peers must update together**. The
version bump makes a mismatch fail cleanly at the handshake (the `v` field is
now mandatory and checked) instead of as an opaque signature error.

- **Handshake signature now covers the static X25519 key.** `eph_sig` signs
  `eph_pub || x25519_pub` (was `eph_pub` only), binding the encryption key to
  the identity. The TOFU store now pins **both** Ed25519 and X25519 (legacy
  ed25519-only pins migrate and back-fill). Closes a first-contact MITM that
  could swap the static X25519 and redirect every sealed-sender envelope to
  the attacker.
- **Double Ratchet binds its cleartext header as AEAD AAD** (`dh_pub`,
  `prev_count`, `msg_num`), authenticating the header alongside the ciphertext.

### Removed

- **`--mode web` (the in-app FastAPI server + PWA) entirely**, along with
  `api.py`, its tests, and the `fastapi`/`uvicorn`/`websockets`/`pydantic`/
  `python-multipart` dependencies. It ran on `DirectTransport` and ignored
  `--tor`, sending all traffic in the clear from the user's real IP — an
  anonymity hole at odds with the whole project. To be redone properly later.
  (The `frontend/` showcase site, deployed separately, is unaffected.)

### Fixed — Anonymity

- `--host` now defaults to `127.0.0.1` (was `0.0.0.0`); exposing the P2P
  listener publicly in direct mode is now an explicit opt-in. Tor mode is
  unaffected (always loopback + onion).
- Qt GUI: the conversation title/subtitle, header/status labels and the
  file-offer dialog now render **PlainText**. A peer-controlled group or file
  name like `<img src="http://x">` no longer triggers a fetch from the real
  IP outside Tor (the same IP-leak class as the rc6 message-bubble fix, on
  the sinks it missed).
- Per-payload `ts` is now integer seconds — sub-second precision leaked a
  clock-skew fingerprint to the receiving/relay hop.
- `--from-mnemonic` is prompted interactively instead of read from `argv`
  (which is world-readable via `/proc` and the process list).

### Fixed — DoS / resource

- Inbound connection cap and a read-loop idle timeout (slowloris / partial-
  frame stalls).
- The file-transfer concurrency cap is now actually enforced; file-resume
  index lists and received `group_name`/`group_id` lengths are bounded.
- Every payload must carry a `msg_id` — `file_offer`/`group_invite` previously
  slipped past the replay guard (notification flooding).

### Fixed — At-rest / input

- `parse_invite` binds `peer_id` to the signed Ed25519 key (a forged peer_id
  in a validly-signed invite could spoof a victim in the add-contact UI).
- The address book is written `0600` (was umask-default, often
  world-readable) — matching pinstore/salt_store.
- The CLI sanitises peer-supplied file and group names before ANSI/`_plain`
  and Rich console sinks (terminal-escape and Rich-markup injection).

### Changed — UI

- Qt GUI visual refresh: cohesive avatar palette, modern borderless bubbles
  with depth, legible system messages, a proper empty state, a corrected
  About dialog (accurate crypto, labelled peer ID), roomy input modals.

## [1.0.0-rc6] — 2026-06-13

A security review of the crypto/protocol layer, plus a round of
connectivity, Tor, GUI and file-transfer fixes shaken out by end-to-end
testing over Tor. Regression tests in `tests/test_security_review_fixes.py`
and the functional/CLI/GUI suites. No wire-format break; on-disk
address-book and pin files auto-upgrade in place (AAD added with a
one-time legacy fallback).

### Fixed — Critical

- **Double Ratchet skip-message DoS** (`ratchet.py`): `_skip_messages`
  now raises once a header asks to skip more than `MAX_SKIP` (raised to
  1000, the Signal default). Previously the loop ran up to the
  attacker-controlled uint32 `msg_num` (~4.29e9) HKDF iterations from a
  single frame, pinning the event loop.
- **Unbounded frame length → pre-auth OOM** (`node.py`): `recv_raw`
  enforces the 16 MiB `MAX_FRAME_BYTES` cap that `PROTOCOL.md §4`
  already documented.
- **Sender spoofing on the ratchet auth path** (`node.py`): the
  unsealed `from_id` must now equal the handshake-authenticated peer of
  the connection that decrypted the message. The sealed sender field is
  sealed to our public key (attacker-chosen), so without this any peer
  with a ratchet session could impersonate any other.
- **Unauthenticated local control API** (`api.py`): every `/api` route
  and the `/ws` socket now require a per-session bearer token; the
  `Host` header is pinned to loopback (DNS-rebinding/CSRF defense). The
  launcher prints the token.

### Fixed — High

- Handshake now verifies `peer_id == BLAKE2s(ed25519_pub)` (`node.py`),
  binding identity to key.
- File-chunk receive buffer is bounded: per-chunk size, running total,
  and `chunk_count == ceil(size/chunk_size)` consistency (`files.py`).
- Read receipts bind the signer to the message's original destination
  (`receipts.py` / `node.py`) — no more forged "read" confirmations.
- Group messages require a locally-known group with the sender as a
  member; group membership changes are creator-authorised (self-leave
  allowed) and apply only the delta instead of trusting the sender's
  whole roster (`node.py`).
- Pin store no longer silently empties on a corrupt/wrong-key file (it
  raises `PinStoreCorruptError` and the launcher refuses to start);
  saves are now durable (`fsync` + atomic rename) (`pinstore.py`).
- Invites carry a signed expiry and are rejected once expired
  (`invite.py`).
- `MSG_PEER_ANNOUNCE` (unsent, untrusted routing-table-poisoning path)
  is dropped; routing table validates peer_id format (`node.py`,
  `discovery.py`).

### Fixed — Medium / Low

- `node.stop()` closes peer connections before awaiting the server's
  `wait_closed()`, fixing a ~30s shutdown hang when a peer was
  connected; `transport.stop()` bounds the wait.
- Address book and pin store use distinct AEAD associated data so a file
  from one cannot be authenticated as the other (legacy files upgrade on
  load).
- Per-payload `ts` freshness window; API upload size cap before disk;
  `host` validation on `/api/peers/connect`; mDNS no longer leaks the
  stable `peer_id` on the LAN and cleans up its zeroconf handle; onion
  address version byte enforced; SOCKS5 unknown ATYP rejected.

### Fixed — connectivity & Tor

- **Onion circuits only relay through CONNECTED peers** (`discovery.py`,
  `node.py`): `select_relay_circuit` could put a peer the node had no live
  connection to as the circuit's first hop, so once 2+ peers were known the
  message was enqueued (a `msg_id` was returned, so it *looked* sent) but
  never delivered. Relays are now chosen only from connected, authenticated
  peers; with none available the circuit degrades to a direct hop.
- **Hidden service: torrc written via sudo** (`transport.py`): the
  `HiddenServiceDir`/`HiddenServicePort` directives were written with a
  plain (non-sudo) `write_text` whose `PermissionError` was silently
  swallowed, so Tor never published the onion. Now appended via `sudo tee`.
- **Hidden service: restart Tor, not reload** (`transport.py`): a
  `systemctl reload` (SIGHUP) does not reliably load changed v3 onion keys,
  leaving the descriptor unpublished/unreachable. Now `systemctl restart`.

### Added — GUI (Qt)

- Per-message delivery status on outgoing bubbles — 🕓 pending → ✓ sent →
  ✓✓ read (blue) → ✕ failed — replacing the old per-message "delivered"
  system line.
- Right-click a peer in the sidebar to **Hide chat** (drop the conversation)
  or **Delete contact** (disconnect, remove from routing/discovery via the
  new `MalphasNode.forget_peer`, and remove from the address book).
- Connecting to a peer is non-blocking: a "Connecting…" spinner instead of
  freezing the window (the old `future.result(timeout=35)` blocked the Qt
  thread). Sending a file is likewise non-blocking.

### Fixed — file transfer

- **Manual accept now works** (`node.py`, `cli_ui.py`, `api.py`): the sender
  waited only 0.3 s for the receiver's readiness signal before streaming
  chunks, so a manually-accepted file (you take seconds to `/accept`) was
  dropped and never completed. The receiver now sends a `file_resume` on
  accept (auto and manual) and the sender waits up to 60 s for it.
- `/accept`, `/reject`, `/savefile` accept the truncated 16-char file_id
  shown in the offer (`cli_ui.py`).
- `/savefile` expands `~`, saves under the original name when given a
  directory, and defaults to `~/` when no path is given; received files keep
  their real name (`cli_ui.py`).

## [1.0.0-rc5] — 2026-05-09

### Resolved — TM-11 CLI test mock + PROTOCOL.md §14 test vectors

Closes the last two autonomously-doable threat-model items.

### Fixed

- `tests/test_cli.py::mock_node` fixture now provides a real
  `GroupRegistry()` for `_groups`. The fixture was last updated
  before 0.9.0 added `_groups` to `MalphasNode`, leaving
  `test_chat_by_label_auto_connects` (and a few other CLI cases
  touching the chat surface) failing with `Mock has no attribute
  '_groups'`. Full CLI suite (132 tests) now passes.

### Added — `tests/test_protocol_vectors.py`

Twenty cases pinning the wire format against silent algorithmic
drift. Two flavours:

- **Deterministic**: identity derivation byte-for-byte (same
  passphrase → same peer_id / pubkeys), BIP39 vectors for
  `0x00*16` and `0xff*16`, HKDF-SHA256 KAT, HMAC-SHA256
  sign+verify, `derive_hmac_key` domain separation,
  `derive_session_key` symmetry under pub-key ordering swap.
- **Round-trip / invariant**: sealed-sender format + decrypt +
  ephemeral-key freshness, 3-hop onion peel chain, AEAD with
  AAD round-trip + AAD-mismatch rejection, ECDH agreement
  symmetry.

### Updated docs

- `PROTOCOL.md` §14 rewritten from "to be added" to a full
  description of what landed, with the pinned constants called
  out (mnemonic vectors, HKDF KAT) so reviewers can grep them.
- `THREAT_MODEL.md` TM-11 marked resolved.

## [1.0.0-rc4] — 2026-05-09

### Resolved — TM-08 reproducible builds

Two invocations of `scripts/build-reproducible.sh` against the
same commit on the same Python minor + hatchling minor now
produce wheels with byte-identical SHA-256. Verified live.

### Added

- `scripts/build-reproducible.sh`: wraps `python -m build` with
  `SOURCE_DATE_EPOCH=<git commit ts>`, `PYTHONHASHSEED=0`,
  `PYTHONDONTWRITEBYTECODE=1`, `LC_ALL=C`, `TZ=UTC`, `umask 022`.
  Prints SHA-256 of every artifact.
- `scripts/verify-reproducibility.sh`: builds twice into separate
  tempdirs and diffs hashes. Exits non-zero on mismatch — the
  regression check.
- `Dockerfile.build`: `python:3.13-slim` + pinned `build==1.5.0`
  + pinned `hatchling>=1.29,<1.30`. Lets a reviewer reproduce a
  release without trusting the host toolchain.

### Pinned

- `pyproject.toml [build-system].requires`:
  `hatchling>=1.29,<1.30` (was unpinned). Comment in-place tells
  maintainers to re-run verification when bumping.

### Updated docs

- `RELEASE.md` §4 rewritten as a closed item with host + Docker
  reproduction commands and the residual-variability notes.
- `THREAT_MODEL.md`: TM-08 marked resolved; non-guarantees row
  about reproducible builds reworded to "Yes (iter-056)".

## [1.0.0-rc3] — 2026-05-09

### Partial — TM-01 group membership consensus

The full fix (MLS-style cryptographic PCS at membership boundary)
is multi-week and stays TBD. This iter ships the operational
half: when group membership changes, every active member's local
view converges to the new list, so a removed peer falls out of
every sender's fanout naturally — no more silent local-only
changes that left removed peers receiving messages from any
sender who hadn't independently noticed.

### Added — wire-additive `group_member_change`

New optional `kind` in §8.1 of `PROTOCOL.md`. Fields:
`group_id`, `group_name`, `action` (`"add"` / `"remove"`),
`target` (peer_id), `members` (full new list). 1.0 receivers
that don't implement it drop it silently per §10.2.
`WIRE_VERSION` stays 1.

### Added — code

- `node.add_group_member`: now also fans `member_change` to
  remaining members after inviting the new peer.
- `node.remove_group_member` (new, async): removes locally and
  notifies remaining members.
- `node.leave_group_async` (new): notifies remaining members
  before dropping the group locally. Synchronous `leave_group`
  retained for backwards compatibility.
- `node.on_group_member_change` callback registration.
- Outsider authorization check: a non-member who guessed the
  `group_id` cannot rewrite our local view; the handler
  validates `from_id` against the current member set or
  creator before applying.

### Added — tests

`tests/test_groups.py` +4 integration tests:
- `test_add_member_notifies_existing_members`
- `test_remove_member_excludes_them_from_future_fanouts`
- `test_leave_async_notifies_remaining_members`
- `test_member_change_from_outsider_is_rejected`

15 / 15 group tests pass.

### Updated docs

- `PROTOCOL.md` §8.1 lists `group_member_change`. §13 separates
  the operational fix (shipped) from the cryptographic
  `member_ratchet` (TBD).
- `THREAT_MODEL.md` TM-01 downgraded High → Medium partial.
  Non-guarantees row about group forward secrecy reworded to
  "membership consensus yes; cryptographic PCS no".

## [1.0.0-rc2] — 2026-05-09

### Resolved — TM-05 constant-time compare audit

Wire-compatible follow-up to rc1. Audited every byte/string
comparison in `src/malphas/`, fixed the two sites that were
using `==` on a value where a timing oracle could fingerprint
contents.

- `pinstore.check_and_pin`: pinned-key match now uses
  `hmac.compare_digest` instead of `==`.
- `files.IncomingFile.assemble`: SHA-256 integrity compare now
  uses `hmac.compare_digest` instead of `!=`.

Other comparisons surveyed and left as-is (rationale in
`tests/test_constant_time.py` docstring): peer_id routing
(public identifier), addressbook label search (user input),
final-hop sentinel in onion peel (public marker), AEAD and
signature verifies (constant-time inside `cryptography.hazmat`).

### Added — `tests/test_constant_time.py`

Nine cases. Two source-grep guards (regression-detect if
someone refactors `compare_digest` away from `pinstore.py`,
`files.py`, or `crypto.hmac_verify`). Seven behavioural smokes
across HMAC verify, pinstore match/mismatch, file assemble
correct-hash / wrong-hash.

### Updated

- `THREAT_MODEL.md` §5: TM-05 marked resolved with reference to
  the iter doc and the test file.

## [1.0.0-rc1] — 2026-05-09

### Wire format frozen — release candidate

After ~four wire-breaking minors in two months (sealed sender,
per-user salt, BIP39, group fanout) the protocol is now declared
**frozen** at `WIRE_VERSION = 1`. Future breaking changes go to
`2.0.0` and through a deprecation window; everything else is
additive (PROTOCOL.md §10).

### Added

- `THREAT_MODEL.md` — five adversary profiles (A1-A5),
  guarantees / non-guarantees table, attack-scenarios grid,
  TCB inventory, eleven tracked weakness IDs (TM-01 … TM-11).
- `PROTOCOL.md` — the authoritative wire-format spec. Covers
  every byte: identity derivation, outer frame, handshake
  JSON, onion layering, `auth_type` byte values, every `kind`
  value, sealed-sender envelope, on-disk formats. Versioning
  rules and freeze policy in §10.
- `RELEASE.md` — pre-release checklist, signed-tag procedure,
  reproducible-build gap tracker.
- `WIRE_VERSION = 1` exposed at `malphas.WIRE_VERSION` and
  `malphas.node.WIRE_VERSION`.
- Handshake JSON now carries `"v": <int>`. Receiver lenient
  on missing (legacy peer, accepted), strict on mismatch
  (future bump = refuse to connect).
- README threat-model section now points at the full
  `THREAT_MODEL.md`.

### Status

This is a release candidate. Use in production at your own risk.

### Known limps tracked for `1.0.0` final

(See THREAT_MODEL.md §5 for the full list with severity.)

- TM-01: group chat lacks MLS / no key rotation on member
  removal. Workaround documented; iter-055 will land a
  `member_ratchet` kind.
- TM-05: constant-time-compare audit not yet end-to-end.
- TM-08: builds not yet reproducible.
- TM-11: one pre-existing CLI test failure
  (`Mock(_groups)`).

## [0.11.8] — 2026-05-09

### Qt GUI — smart auto-scroll

The chat view auto-scrolled to the bottom on every new
message. That's the right behaviour while you're reading
live, but it yanks you out of history if you scrolled up to
re-read something and a new message arrives.

`_add_message` and `_add_system` now check `_is_at_bottom()`
(within 80 px of the maximum, ≈ one bubble) before scrolling.
If you're at the bottom you keep following the conversation;
if you're scrolled up, the new bubble appears below but the
viewport stays put.

Outgoing messages always scroll — when you press Enter you
clearly want to see what you just sent.

### Audit — no other copy-paste bugs from the tk GUI

After the `salt_to_mnemonic / .split()` slip in 0.11.7, did a
sweep across all `MalphasNode` API calls used by `gui_qt.py`
to make sure no async/sync or return-type mismatches were
hiding elsewhere. All clean: `send_message → str | None`,
`send_group_message → bool`, `create_group → str | None`,
`add_group_member → bool`, `leave_group` is sync (used as
sync), `accept_file_offer` is sync (used as sync), `panic`
is sync, `connect_to_peer → bool`. Every call site already
matched.

## [0.11.7] — 2026-05-09

### Fixed — mnemonic dialog: real root cause

The user shared one more screenshot showing the dialog with
*70+ one-character cells*, which finally exposed the actual
bug. The previous "invisible words" symptom and this
"hundreds of single-letter cells" symptom shared the same
root cause:

  `salt_to_mnemonic(data)` returns a single space-separated
  string ("abandon ability able about ..."), not a `list`.

`_action_backup` in `gui_qt.py` was passing the string
straight into `_show_mnemonic_dialog(words)`, which then did
`for i, w in enumerate(words)` — iterating over the
**characters** of the string instead of the words. With a
12-word mnemonic averaging ~6 letters that produced ~80 cells,
each containing a single character, displayed in a 3-column
grid that overflowed the dialog vertically. On smaller
windows the cells got compressed enough that letters fell
outside the rendered region, presenting as "invisible".

The tk GUI (`gui.py`) had the right pattern all along —
`salt_to_mnemonic(data).split()`. The Qt version was missing
the `.split()`. Added it.

Also kept from the round of attempts above: the QFrame +
QLabel cell pattern for reliable bg painting, and the
`QFontDatabase.systemFont(FixedFont)` that dodges font-
family fallback misses. Both are still load-bearing for
correct rendering across PySide6 configurations.

Verified via headless render: 12 words, monospace, raised
cards, 4 × 3 grid.

## [0.11.6] — 2026-05-09

### Sidebar action buttons — colored tones

User feedback: "fai i bottoni nella sidebar più parlanti o
leggermente colorati (panic rosso tenue)".

Each `QPushButton#SideAction` now carries a `tone` property
that QSS attribute selectors style:

  Share   → info     (cyan)
  Add     → success  (green)
  Group   → info     (cyan)
  Backup  → warning  (amber)
  Panic   → danger   (red, exactly as requested)

Borders are tinted ~30 % saturation so the buttons feel
coloured but never shouty. On hover the bg fills with a
darker tint of the same hue and the border + label brighten
to full saturation. Affordance reads at a glance: green for
"add a thing", red for "destroy state", amber for the
recovery flow.

### Fixed — mnemonic dialog showed empty word slots

The 12-word recovery grid was rendering as empty rounded
rectangles. Two QSS issues stacked:

- Inline stylesheet had a stray `}}` (literal two chars from a
  non-f-string concat) instead of the single `}` Qt expected.
  Qt's "Could not parse stylesheet" warning fired silently.
- Without a parsable rule, the cells fell back to the global
  `QDialog QLabel` color which kept text invisible against
  the BG_BASE fallback.

Fix: build the cell stylesheet as a flat string (no f-string
brace escaping pitfalls) and set an explicit `QFont` with a
proper monospace fallback chain so the lookup doesn't go to
the system serif. Words now render: `1.  abandon`,
`2.  ability`, … in a 4 × 3 grid.

## [0.11.5] — 2026-05-09

### Added — Qt GUI smoke tests

`tests/test_gui_qt.py` (17 tests). The tk GUI had 7 smoke
tests guarding it; the Qt port had zero. Without coverage
there, a regression in `gui_qt.py` (a missing import, a
broken QSS f-string, a removed attribute, etc.) would slip
past CI.

The whole module is `pytest.importorskip("PySide6")`-guarded
so it auto-skips when the optional `gui-qt` extra isn't
installed. Tests run under `QT_QPA_PLATFORM=offscreen` so
they work in headless CI.

Coverage:

- helpers: `_short`, `_ts`, `_avatar_color` (determinism +
  palette membership), `_avatar_initial`
- `_qss()` builds clean (no leftover f-string braces, all
  expected anchors present)
- `_load_sigil` returns a non-empty `QPixmap`
- `_sigil_with_halo` produces a properly-padded composite
- `Avatar` constructs and paints
- `BubbleRow` constructs in all three sides (you / them / sys)
- `MalphasQtWindow` constructs in standalone-preview mode
- sidebar row add + key round-trip via UserRole+1
- send button carries a `QGraphicsDropShadowEffect`
  (regression guard for the round-3 polish)
- `_add_message` / `_add_system` book-keeping for unread state

Wire-level behavior (sending messages, draining the
AsyncBridge queue, file transfer) is not asserted here — the
node tests cover those behaviors, and `MalphasQtWindow`
delegates to them.

## [0.11.4] — 2026-05-09

### Qt GUI — visual polish round 3

- Send button gets a single `QGraphicsDropShadowEffect`
  (blur 20, offset 0/4, accent-dim color). Lifts the primary
  CTA one layer above the input bar without per-row overhead.
- Conversation-header avatar reduced 44 → 40 to match
  proportions with the title-and-sub stack; the avatar holder
  shrinks accordingly. All other avatar sites (sidebar rows,
  group headers, single-peer headers) re-tuned to 40 for
  consistency.

## [0.11.3] — 2026-05-09

### Qt GUI — visual polish round 2

- Bubbles now have a subtle 1-px border tinted to their bg
  (BG_DIVIDER for incoming, slightly lighter than ACCENT for
  outgoing). Adds depth without the cost of QGraphicsEffects
  on every row.
- Message entry shaped as a pill (border-radius 22) and gets a
  faint accent border on focus. Send button matched: 96x44 with
  the same pill radius — reads as the primary CTA.
- Search entry on the sidebar lifts its border-radius to 10 and
  also picks up the accent focus ring, so both inputs feel like
  one family.
- Sidebar action buttons (Share / Add / Group / Backup / Panic)
  use a new ghost variant via `QPushButton#SideAction`:
  transparent bg + 1-px divider border + muted label, fills
  with BG_RAISED + brighter label on hover. Less visually
  loud than the default raised buttons, makes the chat the
  hero of the screen.
- Font fallback chain extended for Linux distros that don't
  ship Inter / SF Pro / Segoe UI: Cantarell, Noto Sans, Ubuntu,
  DejaVu Sans now precede Helvetica Neue.

## [0.11.2] — 2026-05-09

### Qt GUI — visual polish round 1

User shared a screenshot of the running app. Three visible bugs +
a polish pass.

Fixed
- Empty conversation header showed a stray empty box where the
  avatar would go. The 44x44 holder was always present; now
  `setVisible(False)` until a conversation is picked.
- Standalone preview's header tried to render `peer_id = "—"`
  which leaked a tiny dash chip into the layout. The sub-label
  is only added when a real `node` is attached.
- All sidebar items showed the red accent strip simultaneously
  because Qt's `:selected` pseudo-state doesn't propagate
  through widgets installed via `setItemWidget`. Active state
  is now applied imperatively by `_add_sidebar_row`, and
  `_select` re-renders the list so the highlight follows the
  click.

Polish
- Sidebar rows wrapped in a styled `QFrame#PeerRow` so each
  item gets `border-radius: 10px`, hover bg, and an active
  3-px accent strip on the left. Group rows show a small
  `GROUP` tag in info-cyan next to the title.
- Bubble corners now asymmetric (16px on three corners, 4px
  on the tail-side corner: bottom-right for "you", bottom-left
  for "them") for that chat-app speech-bubble shape.
- Empty-state sigil now sits on a softly tinted halo
  (`_sigil_with_halo`, paints a `BG_RAISED` circle behind the
  PNG) so the all-black artwork reads against the dark base.
- Header / counter / status / lock / empty-hint labels all
  forced to `background: transparent` so the parent surface
  bleeds through (was leaving subtle ghost boxes around text).
- Tor lock toggled via `setVisible` instead of CSS color
  swap (the property toggle had been leaving the glyph half-
  rendered when off).

Internal
- Sidebar key stored on `QListWidgetItem` via `setData
  (UserRole+1)` (item is unhashable, can't be a dict key).

## [0.11.1] — 2026-05-09

### Qt GUI — full feature parity with the tkinter GUI

The Qt port from 0.11.0 is now a working chat client, not just a
shell. Everything the tk GUI does, the Qt GUI does.

- Asyncio bridge wired. on_message / on_receipt /
  on_pin_violation / on_file_offer / on_file_complete /
  on_group_invite / on_group_message all push events onto a
  queue.Queue, drained on the GUI thread by a 50 ms QTimer.
- Sidebar populated from address-book contacts + unsaved
  discovered peers + groups. Live search filter on label /
  peer_id / group name.
- Per-conversation chat history (self.conversations dict);
  switching peer rehydrates the bubble scrollview.
- Send / receive: direct messages and group messages. Outgoing
  bubble (right, accent red), incoming bubble (left, with hashed
  avatar), system events in centered italic pills.
- File transfer round-trip: QFileDialog for picking outgoing
  file, QMessageBox.question for incoming offer, accept_file_offer
  on yes, getSaveFileName for completed bytes.
- Invite flow: generate (clipboard + info popup), import
  (clipboard parse + self-invite guard + connect + optional save
  to address book via QInputDialog).
- Group ops: create, add member, leave.
- Mnemonic backup: word-grid dialog with copy-to-clipboard.
- About dialog with sigil, version, peer_id, GitHub link.
- Auto-reconnect at launch fans out every saved contact.
- Tor lock indicator: green padlock in header when the node has
  a public .onion; hidden otherwise.
- Status bar refreshed every 1 s with port and active label.

### Fixed in this iter

- Standalone preview (launch_qt_gui() with no node) now also
  populates the conversation header and renders an avatar; the
  earlier guard returned before drawing when book is None.
- Tor lock used a CSS property toggle that left the glyph
  half-rendered when off; switched to plain setVisible.

### Internal

- QListWidgetItem isn't hashable; sidebar key now stored on the
  item via setData(UserRole+1, key) instead of a dict.

## [0.11.0] — 2026-05-09

### Added — PySide6/Qt GUI skeleton

First slice of the move from tkinter to Qt. Wire-format unchanged
(this is a UI swap; not bumped to 1.0 because the Qt port is
incremental and `--mode gui` is still the default).

- New module `src/malphas/gui_qt.py`:
  - `MalphasQtWindow` (QMainWindow): header + sidebar + chat
    surface + input row, all themed via a single QSS string.
  - `BubbleRow` (QFrame): outgoing right / incoming left /
    system centered. Word-wrapped, max 560 px.
  - `_qss()` builds the dark stylesheet from the shared
    `gui_theme` palette tokens — palette is identical between
    the (transitional) tk GUI and the new Qt GUI.
  - Sigil PNG loaded as `QPixmap` (header 32 px, window icon).
- New CLI mode: `--mode gui-qt`. Falls back to a clear error if
  PySide6 isn't installed (`pip install -e ".[gui-qt]"`).
- `_run_gui_qt()` mirrors `_run_gui()`: same passphrase prompt,
  same `MalphasNode` + `AsyncBridge` setup, then enters Qt's
  event loop instead of Tk's mainloop.

### Internal

- `gui_qt` added to the lenient mypy bucket.
- `[project.optional-dependencies] gui-qt`: PySide6 ≥ 6.6,
  qasync ≥ 0.27.

### Not yet wired (subsequent iters)

- Action button handlers (share / add / group / send / file).
- Sidebar populated from `AddressBook` + groups.
- Chat history rehydration on conversation switch.
- Live event drain from `AsyncBridge` event queue.
- File transfer / mnemonic / about dialogs (will use
  `QMessageBox` / `QInputDialog`, no custom widgets).

## [0.10.9] — 2026-05-09

### Reverted

- The custom `gui_dialogs` module is removed. Tk-level hover
  events on a Frame+Label compound widget have an unavoidable
  parent/child Enter/Leave race that produced visible flicker
  even when bindings were collapsed onto a single child. Rather
  than keep ad-hoc workarounds in tk, dialogs revert to
  `tkinter.messagebox` / `tkinter.simpledialog` for now. The
  user-facing chrome will be rebuilt on PySide6 / Qt where
  proper QSS theming and animation handling are available.
- `gui_theme.py` is kept — palette stays identical, will feed
  the Qt port via QSS.

### Added

- `gui-qt` optional extra in `pyproject.toml`:
  `PySide6 >= 6.6` and `qasync >= 0.27` (asyncio integration).
  The Qt port begins in 0.11.x.

## [0.10.8] — 2026-05-09

### Fixed

- **Self-import guard.** Importing your own invite into the
  address book is now blocked at `_action_import` with a clear
  error: pasting your own invite text would have created a
  contact pointing at yourself, which never makes sense.
- **Dialog button hover flicker.** `_Button` in `gui_dialogs`
  bound `<Enter>` / `<Leave>` on both the outer `Frame` *and*
  the inner `Label`. When the cursor crossed from the Frame
  border into the Label, Tk fired `Leave` on the parent and
  `Enter` on the child in quick succession, producing a one-
  frame flash. Bindings now live only on the Label (which fully
  covers the Frame).

## [0.10.7] — 2026-05-09

### GUI — custom dialogs + toasts (no more native popups)

The user pushed back that the GUI still felt "industrial", and
specifically called out the post-action popups. Those were the
last places leaking the OS theme into the dark malphas surface
(`tkinter.messagebox` / `tkinter.simpledialog` render with native
window decorations and gray system colors regardless of palette).

- New module `gui_theme.py` — single source of truth for the
  palette and spacing tokens. Both `gui.py` and the dialog code
  now import from it (no more drift between two copies).
- New module `gui_dialogs.py` — drop-in replacements:
  - `info / warning / error(parent, title, message)`
  - `confirm(parent, title, message) → bool`
  - `prompt(parent, title, label, initial="") → str | None`
  - `toast(parent, message, kind=…, ms=…)` — bottom-right
    auto-dismiss banner for ack-style notifications.
  Each modal is a frameless `Toplevel` with a 3px colored top
  accent (info/warning/error/question), the dark palette, and
  flat hover-aware buttons. `Return` accepts, `Escape` cancels.
- Every `messagebox.*` and `simpledialog.askstring` call in
  `gui.py` migrated to the new dialogs (~25 call sites).
- `filedialog.*` kept native — file pickers should match the OS
  for muscle memory.

### Internal

- `gui_dialogs` and `gui_theme` added to the lenient mypy bucket;
  `call-overload` added to the disable list (Tk type stubs
  over-narrow `Toplevel(master=Misc)`).
- 7/7 GUI smoke tests still green; ruff / mypy / bandit clean.

## [0.10.6] — 2026-05-09

### GUI — lighter palette + larger controls

User feedback: pure-black sigil disappeared against a near-black
background, and a few controls still felt small.

- Palette lifted ~8-12 stops on the L axis:
  - BG_BASE     #0a0a0d → #1f2129
  - BG_SURFACE  #15151a → #262932
  - BG_RAISED   #1c1c22 → #30333d
  - BG_HOVER    #2a2b34 → #3d4150
  - BG_DIVIDER  #2c2c34 → #3a3d47
  - BUBBLE_THEM #26262e → #363944
  - BUBBLE_YOU  #5e1c1c → #7a2828
  - BUBBLE_SYS  #1f2026 → #2a2c35
  - FG_PRIMARY  #ececec → #f0f0f2
  - FG_MUTED    #9a9a9a → #b0b2bb
- Button sizes bumped again:
  - Tor lock indicator           30 → 34 px
  - Sidebar action toolbar       40 → 46 px
  - Conversation header          38 → 44 px
  - Input row paperclip / send   44 → 52 px
  - Mnemonic dialog copy         42 → 48 px
- Sidebar search icon enlarged: canvas 26→34 px, glyph 20→26 px.

## [0.10.5] — 2026-05-09

### GUI — icon legibility

User reported the new vector icons looked tiny. Two-part fix:

- `IconButton` inset reduced from 20% → 8% of the button edge,
  so the glyph now fills ~84% of the canvas (up from ~60%).
- Stroke widths in `gui_icons.py` bumped ~25% (1.6→2.0, 1.8→2.2,
  1.4→1.8, 2.0→2.4) so the lines read crisply at the new size.
- Button sizes bumped at every call site:
  - Tor lock indicator: 24 → 30 px
  - Sidebar action toolbar (share / plus / users): 32 → 40 px
  - Conversation header (user-plus / door-out): 32 → 38 px
  - Input row (paperclip / send): 36 → 44 px
  - Mnemonic dialog copy button: 36 → 42 px
  - Sidebar search-row icon: 16 → 20 px

No layout reflow — the larger icons fit inside the existing
toolbar / header heights.

## [0.10.4] — 2026-05-09

### GUI — chat-app-grade redesign

User-supplied sigil PNG, vector-stroke icons (no emoji), Telegram/
WhatsApp-flavored bubble chat layout.

- **Bundled sigil**: `src/malphas/assets/sigil.png` (450×450 RGBA),
  shipped via hatch `force-include`. Used in header (28px),
  empty-state (180px), mnemonic dialog (110px), About (110px).
- **Vector icons** (`src/malphas/gui_icons.py`): paperclip, send,
  plus, share, users, user-plus, door-out, lock, copy, search,
  alert. Each `draw_*` paints with Canvas primitives — no PNG/SVG/
  Pillow dependency. New `IconButton` widget with hover/ghost/
  accent variants and tooltip support.
- **Chat bubbles** (`MessageBubble` + `ChatPane`): outgoing right
  in deep red, incoming left with circular avatar, system events
  centered in a flat pill. Each bubble carries its own timestamp.
- **Avatars**: deterministic color from `BLAKE2s(peer_id)[:4]`
  over a 10-color palette; initial is first char of label.
- **Sidebar** rebuilt with `SidebarItem` widgets: avatar + title
  + sub + unread dot + 3px accent bar on active. Live search row
  at top, action toolbar (share / plus / users) below.
- **Conversation header**: avatar + title + monospaced sub +
  contextual right actions (add member / leave for groups).
- **Tor lock icon** in header (green when `.onion` is up).
- **Input row**: paperclip left (file), accent paper-plane right.
- **No emoji anywhere** — all glyphs Canvas-drawn.

### Wire format

Unchanged.

## [0.10.3] — 2026-05-09

### GUI

- **Malphas seal logo** drawn via `tkinter.Canvas` primitives (no PNG
  asset). Three concentric rings + inverted equilateral triangle +
  hexagram (Star of Solomon) + descending spear + 4 cardinal dots.
  Used in:
  - the header (small, 32px)
  - the empty-state pane (large, scales with window)
  - the recovery-mnemonic dialog (44px)
  - the About dialog (120px)
- **Custom sidebar** (`SidebarItem`) replaces the ttk `Treeview`:
  - 3px left accent bar on active row (color = malphas red)
  - hover state (bg lightens to `#2a2b34`)
  - active state (bg `#33141a` accent-tinted, accent bar visible)
  - per-row title + monospaced subtitle + unread dot badge on the right
  - mousewheel scrolling, custom scrollbar
- **Empty state**: large seal centered + "malphas" wordmark + tagline,
  rendered on a Canvas that resizes with the chat pane.
- **About dialog** redesigned as a `Toplevel` with the seal at the top.
- **Recovery-mnemonic dialog** gets the seal in the header beside the title.
- **Color palette** rebalanced for more depth:
  - `BG_BASE`    `#0a0a0d` (was `#0e0e10`) — darker
  - `BG_RAISED`  `#22232a` (was `#1d1d22`) — lighter
  - `BG_HOVER`   `#2a2b34` — new
  - `BG_ACTIVE`  `#33141a` — new (accent-tinted)
  - `BG_DIVIDER` `#34343d` — more visible 1px lines
  - `ACCENT_GLOW` `#ff5555` — bright red for button-pressed feedback

### Tor support in `--mode gui`

`malphas --mode gui --tor` now also registers the Tor v3 hidden
service through the asyncio bridge. Before 0.10.3 it only opened
the SOCKS5 proxy outbound; inbound `.onion` traffic was lost.
Mirrors the `_run_cli` flow.

### Wire format

Unchanged.

## [0.10.2] — 2026-05-09

### GUI redesign

The 0.10.0 GUI was functional but visually rough. This is a full
restyle, same widget tree, much better defaults.

- **Three-tier dark palette** (`#0e0e10` → `#16161a` → `#1d1d22`)
  with explicit FG hierarchy (primary / muted / faint) and a single
  accent (malphas red `#d23a3a`) for primary actions and active rows.
- **Header bar** at the top with brand, peer_id snippet, peer/group
  counters, and a connection-status dot.
- **Conversation header** above the chat pane: title (label or group
  name) + monospaced sub-line (group_id or full peer_id).
- **Empty-state overlay** on the chat pane when no conversation is
  selected ("Pick a conversation from the sidebar…").
- **Two-line message layout**: timestamp + sender bold on one line,
  message body indented underneath, blank line between rows. Much
  easier to read than the single-line `[ts] you  text` of 0.10.0.
- **Unread badges** in the sidebar (red dot, bold tag) for
  conversations that received a message while not active.
- **Custom mnemonic dialog** (Toplevel) replaces the cramped
  `messagebox.showinfo` — a 2×6 grid of monospaced words with
  numbers, plus a "copy to clipboard" + "done" button row.
- **Font detection chain**: tries Inter / IBM Plex Sans / Roboto /
  Cantarell / DejaVu Sans for chrome and JetBrains Mono / IBM Plex
  Mono / Fira Code / Source Code Pro / Liberation Mono / Menlo /
  DejaVu Sans Mono for chat body. Falls back to TkDefaultFont.
- **Spacing scale** (4 / 8 / 12 / 16 / 24) applied consistently
  across paddings, margins, and dialog layouts.
- **Sidebar** now has a section heading ("CONVERSATIONS"), a
  scrollbar, and two ghost-style action buttons at the bottom
  (`+ Import invite`, `↗ Generate invite`).
- **Keyboard shortcuts**: Ctrl+E (export), Ctrl+I (import),
  Ctrl+Q (quit), F5 (refresh).
- **Status bar at the bottom**: port + active conversation, distinct
  from the header counters.
- **Thin 1px dividers** instead of widget borders, all in
  `#26262d` for visual coherence.

### Wire format

Unchanged.

## [0.10.1] — 2026-05-09

### Fixed

- **Address book auto-migration from pre-0.7.0**: when v0.7.0 changed
  the Argon2 salt from a global constant to a per-user random value,
  any existing `~/.malphas/book` file became un-decryptable on the
  next run because the derived `book_key` differed. The CLI/Web/GUI
  bootstraps now detect that failure, retry with the legacy salt, and
  if that succeeds re-emit the contacts under the new key. The user
  sees `address book: migrating from pre-0.7.0 fixed-salt format…`
  and the contacts are preserved.
- **Splash version is now dynamic**: `splash.py` resolves the version
  via `importlib.metadata` at print time instead of a hardcoded
  string. The credits panel showed "0.2.0" through ten releases.

### Internal

- New helper `__main__._open_book_with_migration(path, passphrase, salt)`
  centralizes the migration retry. All three modes (CLI, web, GUI)
  now use it.
- `splash._CREDITS_TMPL` is a format string with `{version}`.

### Wire format

Unchanged.

## [0.10.0] — 2026-05-09

### Features

- **Tkinter desktop GUI**, opt-in via `malphas --mode gui`. ttk-styled
  dark theme with a sidebar of peers + groups, a chat pane with
  per-conversation scrollback, an input row, a status bar, and a menu
  bar (File, View, Group, Help).
- Asyncio/Tk integration via `AsyncBridge`: the asyncio event loop
  that drives `MalphasNode` runs in a daemon thread, the Tk thread
  polls a `queue.Queue` every 50 ms to consume node-side callbacks
  without blocking either side.
- GUI actions:
  - Generate / import malphas:// invites via clipboard.
  - Send file (filedialog), accept/reject incoming offer (modal),
    save completed file (filedialog).
  - Create group / add member / leave group from the menu.
  - Backup the 12-word mnemonic in a modal dialog.
  - PANIC button in the File menu (wipes in-memory state and exits).

### Implementation

- New `src/malphas/gui.py` (~530 lines): `AsyncBridge`, `MalphasGUI`,
  `launch_gui()` entry point.
- `__main__.py`: `--mode gui` accepted. New `_run_gui(args)` synchronous
  bootstrap that does the same passphrase / salt / identity setup as
  CLI/web, spins the bridge, calls `launch_gui()`.
- `tests/test_gui.py`: 7 smoke tests (AsyncBridge lifecycle, helpers,
  GUI construction without entering mainloop).
- `malphas.gui` is in the lenient mypy bucket — Tk type hints + dynamic
  Tcl variables aren't worth the strict-bucket plumbing for a UI module.

### Wire format

Unchanged. The GUI is just a new presentation surface over the
existing node API.

## [0.9.0] — 2026-05-09

### Features

- **Group chat (N-way pairwise)**: send a message to a group of up to
  50 peers. The sender encrypts a separate copy per member and ships
  it over the existing 1-to-1 pipeline (sealed sender, replay cache,
  Double Ratchet where available, HMAC/Ed25519 outer auth, onion
  routing). No shared group key, no membership consensus, no add/
  remove ratchet.
- New `MalphasNode` API:
  - `create_group(name, members) -> group_id`
  - `add_group_member(group_id, peer_id) -> bool`
  - `send_group_message(group_id, content) -> bool`
  - `leave_group(group_id) -> bool`
  - Callbacks: `on_group_invite(cb)`, `on_group_message(cb)`.
- New CLI commands:
  - `/group new <name>`
  - `/group add <name> <peer|label|peer_id>`
  - `/group list`
  - `/group members <name>`
  - `/group leave <name>`
- `/chat <group_id|group_name>` switches the active conversation to a
  group; subsequent text is fanned out via `send_group_message`.

### Wire format

Two new JSON payload kinds (backward-compatible — older clients drop
unknown kinds via the existing fail-closed dispatch):

  `group_invite {kind, from_eph+from_sealed, msg_id, nonce, ts,
                 group_id, group_name, members}`
  `group_msg    {kind, from_eph+from_sealed, msg_id, nonce, ts,
                 group_id, group_name, content}`

Each `group_msg` has a unique `msg_id` per pairwise copy so the
replay cache covers them without collisions.

### Implementation

- New `malphas.groups` module (`Group`, `GroupRegistry`,
  `MAX_MEMBERS = 50`). In-memory only; `panic()` wipes.
- `MalphasNode._handle_group_invite` registers the group locally and
  notifies; `_handle_group_msg` notifies and stores in the message
  log with a `[group X]` prefix.
- `tests/test_groups.py`: 7 unit + 4 E2E (3-node fanout trio with
  full mesh).
- Mypy strict bucket extended to 18 modules.

### Out of scope

- Group state persistence cross-process-restart.
- Notifying existing members of a new add (only the invited member
  is notified).
- Forward secrecy at the group level — each pairwise copy gets it
  individually via the existing 1-to-1 ratchet.

## [0.8.0] — 2026-05-09

### Features

- **File transfer resume**: a re-sent `file_offer` for a file_id of
  which the receiver already holds a partial buffer triggers a new
  `file_resume` payload back to the sender. The sender skips the
  chunks already received and ships only the missing ones. For a
  100 MB file dropped at 80%, that's ~20 MB instead of 100 MB on
  the retry.
- New `MalphasNode.resume_file(dest_peer_id, file_id)` API: re-send
  using the existing `OutgoingFile` registered locally, without
  re-reading the source path. Returns the file_id, or None if the
  file_id is not in the outgoing registry (already cancelled or
  never sent from this process).

### Wire format

- New JSON kind `file_resume` with shape:
  `{kind: "file_resume", file_id: <hex>, received_idx: [int, ...]}`.
- Backward-compatible: a 0.7.x receiver doesn't emit `file_resume`,
  so a 0.8.0 sender waits 300 ms then proceeds with a full send.
  A 0.7.x sender never asks for resume, so a 0.8.0 receiver does
  the standard offer/chunk dance.

### Implementation

- `IncomingFile.received_indices() -> list[int]` exposed on the
  files module — used by the receiver to populate the resume signal.
- `MalphasNode._handle_file_offer` now checks `_files._incoming` for
  the offered `file_id`. If a partial buffer exists, it fires off
  a `file_resume` and skips re-registration.
- `MalphasNode._handle_file_resume` records the skip set in
  `_resume_signals[file_id]` and unblocks the corresponding
  `_resume_events[file_id]`.
- `send_file` waits up to 300 ms on the resume Event before
  streaming chunks; honors the skip set during chunkify iteration.
- `panic()` clears `_resume_signals` and unblocks every waiting
  Event so in-flight `send_file()` coroutines complete promptly.

### Tests

- 5 new tests in `tests/test_file_resume.py` (2 unit + 3 E2E).

## [0.7.1] — 2026-05-09

### Features

- **BIP39 12-word mnemonic backup** for the per-user salt. 16 bytes
  of entropy ↔ 12 English BIP39 words. Closes the "Loss of
  ~/.malphas/salt" hole opened in 0.7.0.
- First-run flow now prints the mnemonic prominently, with an
  unmistakable header instructing the user to write it down.
- New `malphas --from-mnemonic "<12 words>"`: restores the salt on
  another machine. If `~/.malphas/salt` is missing it is written;
  if it exists with a different value, startup aborts with an
  error (refusing to overwrite an existing identity by accident).
- New `/backup` CLI command: re-prints the 12 words on demand.

### Implementation

- New `malphas.mnemonic` module: `salt_to_mnemonic(salt)` and
  `mnemonic_to_salt(words)`. Backed by Trezor's `python-mnemonic`
  (`mnemonic>=0.20`) for wordlist + checksum.
- 9 new unit tests in `tests/test_mnemonic.py` (known BIP39 zero-
  entropy vector, roundtrip, word count, bad checksum, word not in
  wordlist, whitespace tolerance, length bounds).
- `MalphasCLI.__init__` takes an optional `salt_path` so `/backup`
  can re-encode the file content on demand.
- Mypy strict bucket extended to 17 modules.
- Runtime dep: `mnemonic>=0.20`.

### Wire format

Unchanged — feature is purely user-facing (recovery flow). 0.7.1
peers interoperate with 0.7.0 peers as long as they share the same
salt + passphrase.

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
