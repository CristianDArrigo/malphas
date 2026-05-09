# malphas — Request for External Review

> A self-contained brief for a cryptographer / security engineer
> asked to review malphas before its first stable release.
> Status: **`1.0.0-rc1`**, 2026-05-09.

---

## 1 · What you are reviewing

A privacy-first peer-to-peer text + small-file messenger written in
Python 3.10+ (~10k LOC excluding tests, ~24k including tests).
Single-author. Six months of development. No prior review.

Repository: `https://github.com/CristianDArrigo/malphas`
Tag (suggested): `v1.0.0-rc1`

---

## 2 · What we want from you

In rough priority order. Cherry-pick whichever fits your time and
expertise; partial reviews are still useful.

1. **Protocol confirm-or-correct**, against [`PROTOCOL.md`](PROTOCOL.md).
   Does the wire format do what the document claims? Are the KDF
   info strings, AEAD nonce policy, and signature-vs-ratchet
   ordering sound?
2. **Threat-model gap analysis**, against
   [`THREAT_MODEL.md`](THREAT_MODEL.md). Are the claimed
   guarantees actually upheld by the implementation? Are the
   "non-guarantees" comprehensive, or are there silent failures we
   missed?
3. **Concrete attack surface walk-through.** Pick one or more of
   the scenarios in §3 of the threat model and try to break them.
   Especially welcome: replay manipulation, sealed-sender
   correlation, demotion attacks on the `auth_type` byte, group
   fanout ghost-membership.
4. **Crypto-primitive misuse audit.** Anywhere we call
   `cryptography.hazmat` and use it badly: nonce reuse, IV reuse,
   AEAD-without-AAD where AAD is needed, raw ECDH secrets used as
   keys without HKDF, etc.
5. **Side-channel surface.** Constant-time compare audit
   (we believe `hmac.compare_digest` is used wherever sensitive,
   but a sweep is the ask). Timing leaks in the dispatch path.
6. **Onion layering.** Verify the onion peel cannot be made to
   reveal layer N+1 from a malicious layer N.
7. **State machine fragility.** Connection lifecycle, ratchet
   re-init on reconnect, replay cache behaviour under reorder /
   duplicate / overflow.

If you find something, **don't open a public issue** — email the
author (see §6) so we can patch before disclosure.

---

## 3 · Where to look

The crypto-relevant modules, with one-line summaries:

| File                          | LOC | Why it matters                                                  |
|-------------------------------|-----|-----------------------------------------------------------------|
| `src/malphas/crypto.py`       | ~120 | Wraps PyCA: HKDF, X25519 ECDH, ChaCha20-Poly1305, HMAC, kdf_chain. |
| `src/malphas/identity.py`     | ~150 | Argon2id → Ed25519 + X25519 + BLAKE2s peer_id.                  |
| `src/malphas/sealed_sender.py`| ~100 | X25519+ChaCha20-Poly1305 wrap of the `from` peer_id.            |
| `src/malphas/ratchet.py`      | ~250 | Double Ratchet (DH + symmetric chains).                         |
| `src/malphas/onion.py`        | ~120 | 3-hop onion encryption.                                         |
| `src/malphas/replay.py`       | ~80  | Sliding-window dedup of (from, msg_id).                         |
| `src/malphas/receipts.py`     | ~150 | Ed25519-signed read receipts.                                   |
| `src/malphas/addressbook.py`  | ~250 | Argon2id-derived key + AEAD'd contact list on disk.             |
| `src/malphas/pinstore.py`     | ~120 | Persisted TOFU pins.                                            |
| `src/malphas/groups.py`       | ~180 | N-way pairwise fanout. **Known weak spot** — TM-01.             |
| `src/malphas/node.py`         | ~1500 | The dispatch core. The biggest review surface.                  |
| `src/malphas/transport.py`    | ~250 | Tor SOCKS5 + v3 hidden service registration.                    |
| `src/malphas/files.py`        | ~250 | Chunked file transfer with resume.                              |
| `src/malphas/invite.py`       | ~100 | Self-signed `malphas://` invite blobs.                          |
| `src/malphas/mnemonic.py`     | ~100 | BIP39 12-word salt backup.                                      |
| `src/malphas/secure_buffer.py`| ~100 | mlocked, zero-on-free byte buffers.                             |

Avoid for crypto review (UI / no security-critical logic):
`gui*.py`, `cli_ui.py`, `splash.py`.

---

## 4 · Questions we have for you

The author's known unknowns. Even partial answers are valuable.

1. **HKDF info strings.** All of them are listed in PROTOCOL.md §3,
   §6, §8.2, §13. Are they sufficient to keep all derived keys in
   different domains? Specifically: are the book key, pin key, and
   session key cryptographically independent given a shared
   `seed64` ancestor?
2. **HMAC vs Ed25519 vs ratchet selection.** §7 of the protocol
   claims a downgrade from `R` to `H` or `E` is impossible because
   the ratchet ciphertext doesn't parse as the alternative formats.
   Can you construct a payload that **does** parse all three ways?
3. **Sealed sender after relay key compromise.** If a Tor relay's
   long-term key were compromised post-hoc, can a stored capture
   leak the `from` peer_id? (We claim no, because each onion layer
   uses an ephemeral key, and the relay never sees the inner
   payload. Confirm.)
4. **Group fanout in the "removed but not yet excluded" window.**
   We document this as a non-guarantee (TM-01). Is there a minimal
   change short of MLS that gets us forward secrecy on member
   removal? (We're considering an explicit `member_ratchet` kind.)
5. **Ratchet skip window.** We allow `MAX_SKIP=100` out-of-order
   messages. Memory exhaustion attack: can a peer flood us into
   keeping 100 keys per ratchet × N ratchets = unbounded? (We
   believe N is bounded by the connection cap, but please confirm.)
6. **Pre-connection signed-only `E` mode.** First message between
   peers can be Ed25519-only because no ratchet has bootstrapped.
   Is this a window where an attacker who knows my Ed25519 pub can
   inject a forged-but-valid first message? (Pin enforcement and
   sealed sender wrap should both prevent it; please verify.)
7. **The pre-existing CLI test failure** (`Mock(_groups)`) — not
   crypto, but does its absence imply a path the rest of the test
   suite doesn't exercise?

---

## 5 · Existing test posture

What we already verify:

- 100+ pytest cases across 28 test files.
- Hypothesis property tests on parsers (onion, sealed_sender,
  files, invite). Run on every CI build.
- Coverage gate enforced (≥ 70% module-level).
- mypy strict on 17 modules including all crypto layers.
- bandit + ruff in CI.

What we **don't** verify (and you should treat as a gap):

- No formal protocol model (Tamarin / CryptoVerif / ProVerif).
- No fuzz harness beyond Hypothesis (no AFL/libFuzzer integration).
- No published test vectors against fixed ciphertexts.
- No external review — that's the ask.

---

## 6 · How to engage

- Repository: `https://github.com/CristianDArrigo/malphas`
- Author: Cristian D'Arrigo (`cristiandarrigo0@gmail.com`)
- Threat-model contact: same.
- Disclosure window we'd like: 30 days from first reply, extendable.

If you find an exploitable issue, please disclose privately first.
We will credit (or not) per your preference.

If you take more than a glance, we'll list you in `CREDITS.md`
under "external review" with whatever attribution you want.

---

## 7 · What "review accepted" looks like

For us to call malphas `1.0.0`, we want:

1. At least one external reviewer with relevant background
   confirming PROTOCOL.md ↔ implementation parity.
2. All review-flagged High-severity findings closed or
   accepted-and-documented in THREAT_MODEL.md.
3. Test vectors landed (PROTOCOL.md §14).
4. A reproducible build process (RELEASE.md, planned).
5. The pending normative changes (PROTOCOL.md §13) merged.

Until then we ship as `1.0.0-rc1`, `1.0.0-rc2`, … and the
threat-model document is the contract.
