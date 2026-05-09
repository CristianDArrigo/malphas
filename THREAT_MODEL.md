# malphas — Threat Model

> Status: **draft 1.0**, written by the author, **not externally
> reviewed**. Intended as the reviewer's starting point and as a
> contract with users about what malphas does and does not protect.

## TL;DR — who should use this

malphas is appropriate for **two-party and small-group conversations
where both endpoints trust each other and want to defeat passive
network surveillance, traffic-graph mapping, and casual targeted
attempts**. It is **not** appropriate for journalists publishing
against a state actor, whistleblowers leaking through a network they
don't control, or any threat model where the cost of a key
compromise is irreversible.

If your adversary can run a cryptanalytic campaign against you —
choose Signal, Cwtch, or a paid security review of a tool with one.
malphas has not had that review yet.

---

## 1 · Adversaries we model

We grade defences against five distinct adversary capability
profiles. Each row in §3 is graded against each profile.

| Code | Adversary                          | Capability                                                                    |
|------|------------------------------------|-------------------------------------------------------------------------------|
| A1   | Casual sniffer                     | Reads packets on a shared LAN / café Wi-Fi. No active modification.           |
| A2   | Network observer (passive)         | Sees all traffic between the two endpoints, indefinitely. Records.            |
| A3   | Active MITM                        | Modifies, drops, replays, reorders packets on the wire.                       |
| A4   | Compromised relay (Tor circuit)    | Runs one hop of a 3-hop Tor circuit. May cooperate with another A4.           |
| A5   | Endpoint compromise (post-hoc)     | Steals the disk image of one party, *after* communications happen.            |

Out of scope: A6 = endpoint compromise during conversation (RAT,
keylogger, screen capture). No software-only messenger defends
against it; if your endpoint is hot, every message you read or send
is exposed.

Out of scope: A7 = Tor network-wide traffic correlation by a global
passive adversary. We use Tor; we inherit Tor's threat model
exactly.

Out of scope: A8 = state-actor cryptanalysis against the underlying
primitives (X25519, Ed25519, ChaCha20-Poly1305, BLAKE2s, Argon2id).
Standard-primitive trust.

---

## 2 · Guarantees and non-guarantees

### What malphas tries to give you

| Property                                | Held against | Notes                                                                  |
|-----------------------------------------|--------------|------------------------------------------------------------------------|
| Confidentiality of message body         | A1–A5        | X25519 ECDH + ChaCha20-Poly1305 AEAD. No one but the recipient reads.  |
| Integrity / authenticity of body        | A1–A4        | Ed25519 signature on the wrapping container; AEAD tag on the payload.  |
| Forward secrecy on direct messages      | A1–A4        | Double Ratchet. Compromise of a session key does not expose past msgs. |
| Sender anonymity vs. relay              | A4           | Sealed sender (v0.6.0). Outer relay sees only `from_eph`, not peer_id. |
| Pinned identity                         | A3           | TOFU on first contact, then pinned. Subsequent key change is rejected. |
| Replay protection                       | A3           | (`from_id`, `msg_id`) cache, sliding 1-hour window, 10k entries.       |
| At-rest confidentiality of address book | A5           | Argon2id + ChaCha20-Poly1305 with per-user salt. Padded JSON.          |
| At-rest confidentiality of ratchet      | —            | Not applicable: ratchet state is in-memory only.                       |
| Network-level unlinkability             | A1–A4        | All traffic over Tor onion service when `--tor` is set.                |
| Cover traffic                           | A2           | Optional padding+jitter packets (off by default). Limited.             |
| Panic wipe of in-memory state           | A6 only      | `panic()` zeroizes all keys + book + ratchets + caches in RAM.         |

### What malphas does **not** guarantee

| Property                                         | Why not                                                                                       |
|--------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Cryptographic group forward secrecy at membership boundary | Groups use N-way pairwise fanout (no MLS). A `group_member_change` (1.0.0-rc3) propagates membership eventually-consistently so a removed peer is dropped from every active member's fanout, but the underlying pairwise ratchets are not rotated at the boundary — that's the TBD half of TM-01. |
| Post-compromise security on groups               | Same. Compromising one member's key gives the attacker access to that member's pairwise channels until each peer rotates. |
| Plausible deniability of conversation            | Ed25519 signatures on the outer envelope are non-deniable. A leak of a signed message proves origin. (Discussion: future OTR-style MAC instead of signature.) |
| Metadata at the IP / Tor circuit level           | We use Tor's circuit pool. A global passive adversary observing both ends can correlate.      |
| Timing-channel resistance                        | Cover traffic is best-effort. Padding aligns to a fixed block, but message arrival timing leaks. |
| Constant-time comparisons everywhere             | We use `hmac.compare_digest` in obvious spots, but a full audit (§5) is pending.              |
| Resistance to denial of service                  | A peer can flood the input queue or send many connection attempts. Bounded by replay window + per-peer connection cap, but no rate limiting beyond that. |
| Recovery if you lose **both** salt + passphrase  | The address book cannot be recomputed. The mnemonic backs up the salt; the passphrase you must remember. |
| Reproducible builds                              | Yes (iter-056). `scripts/build-reproducible.sh` + `Dockerfile.build` produce byte-identical wheels. |
| External cryptographic audit                     | Not yet performed.                                                                            |

---

## 3 · Concrete attack scenarios

Each cell: ✅ defended, ⚠️ partial, ❌ not defended, — = N/A.

| Scenario                                                                                                              | A1 | A2 | A3 | A4 | A5 |
|-----------------------------------------------------------------------------------------------------------------------|:--:|:--:|:--:|:--:|:--:|
| Read message body                                                                                                     | ✅ | ✅ | ✅ | ✅ | ✅ |
| Modify message body in transit                                                                                        | ✅ | — | ✅ | ✅ | — |
| Inject a fake message                                                                                                  | ✅ | — | ✅ | ✅ | — |
| Replay a previously-recorded packet                                                                                    | ✅ | — | ✅ | ✅ | — |
| Map social graph (who-talks-to-whom) by reading the `from` field                                                       | ✅ | ✅ | ✅ | ✅ | — |
| Map social graph by IP correlation                                                                                     | ⚠️ | ⚠️ | ⚠️ | ⚠️ | — |
| Demote crypto by stripping `auth_type` prefix to revert to weaker scheme                                               | ✅ | — | ✅ | ✅ | — |
| Steal address book file                                                                                                | — | — | — | — | ✅ argon2id |
| Steal salt + brute force passphrase offline                                                                            | — | — | — | — | ⚠️ depends on passphrase strength + Argon2 cost |
| Read past messages after a ratchet key compromise                                                                      | — | — | — | — | ✅ Double Ratchet |
| Read future messages after a ratchet key compromise (until reconnect)                                                  | — | — | — | — | ✅ Double Ratchet ratcheting |
| Continue to receive group messages after being removed                                                                 | — | — | — | — | ❌ no MLS |
| Read messages from a group I was never added to                                                                        | — | — | — | — | ✅ |
| Pretend to be peer X to peer Y (key impersonation)                                                                      | ✅ | — | ✅ pin enforced | ✅ pin enforced | — |
| Pretend to be peer X **on first contact** (TOFU window)                                                                 | ❌ | — | ❌ | ❌ | — |
| Submit a malformed onion / sealed-sender frame to crash the daemon                                                      | ✅ hypothesis fuzz | — | ✅ | ✅ | — |
| Tor circuit deanonymization via end-to-end timing                                                                       | — | inherited from Tor | inherited from Tor | inherited from Tor | — |
| Recover a wiped address book after `/panic`                                                                             | — | — | — | — | ✅ memory only |

---

## 4 · Trusted computing base (TCB)

Code and dependencies that, if compromised, defeat the model:

| Component                              | What it provides                              | Trust note                                |
|----------------------------------------|-----------------------------------------------|-------------------------------------------|
| `cryptography` (PyCA)                  | All primitives (X25519, Ed25519, ChaCha20-Poly1305, HKDF, BLAKE2s, Argon2id is via `argon2-cffi`) | Industry-standard, audited.               |
| `argon2-cffi`                          | Argon2id KDF                                  | Used for passphrase → seed.               |
| `mnemonic`                             | BIP39 word list                               | Public dictionary, no secrets.            |
| `stem`                                 | Tor controller                                | Loads the v3 HS key into our running Tor. |
| `cryptography` ed25519 → onion conversion | Derives `.onion` from Ed25519 pub          | Implementation matches Tor's.             |
| The Python interpreter                 | All code runs here                            | Same-process attack surface as any app.   |
| The OS keyring / filesystem permissions | Address-book file mode 0600                  | We rely on OS to enforce.                 |

**Not** in TCB:
- The peer (we never trust an outbound peer beyond replay/auth).
- The Tor relays (we use 3-hop circuits; no single hop sees both ends).
- The disk (encrypted-at-rest where it matters).

---

## 5 · Known weaknesses and pending work

The honest list of things that should be done before a stable
release.

| ID    | Severity | Item                                                                     | Tracked in   |
|-------|:--------:|--------------------------------------------------------------------------|--------------|
| TM-01 | Medium (was High) | Operational consensus on group membership added in iter-055 via additive `group_member_change` kind: add/remove/leave fan a notification to all remaining members so their fanouts converge to the new list. **Cryptographic** PCS at the membership boundary (MLS-style `member_ratchet`) is still TBD. | iter-055 ⚠️ partial |
| TM-02 | High     | No external cryptographic protocol review.                               | REVIEW_REQUEST.md |
| TM-03 | High     | Wire format has been broken 4× in two months. Not stable yet.            | PROTOCOL.md, frozen at `1.0.0-rc1`. |
| TM-04 | Medium   | TOFU window: first connect to a new peer trusts the public key on faith. | by design; documented in invite flow. |
| TM-05 | ~~Medium~~ resolved | Constant-time compares audited (iter-054). `pinstore` and `files` integrity check now use `hmac.compare_digest`. Other comparisons either go through `cryptography.hazmat` (constant-time by construction) or compare public identifiers where timing leaks no secret. Regression-tested in `tests/test_constant_time.py`. | iter-054 ✅ |
| TM-06 | Medium   | Cover traffic optional and basic; doesn't defeat traffic analysis.       | future       |
| TM-07 | Medium   | Ed25519 signatures are non-deniable; signed messages can be leaked.      | future (OTR-style MAC). |
| TM-08 | ~~Medium~~ resolved | Reproducible build verified in iter-056. `scripts/build-reproducible.sh` + `Dockerfile.build` produce byte-identical wheels across runs. `scripts/verify-reproducibility.sh` is the regression check. | iter-056 ✅ |
| TM-09 | Low      | Receipts can be omitted by a malicious endpoint to spoof "not delivered".| documented   |
| TM-10 | Low      | Address book file size leaks an upper bound on contact count via padding granularity. | low impact   |
| TM-11 | ~~Low~~ resolved | iter-057: mock_node fixture in `tests/test_cli.py` now provides a real `GroupRegistry()` for `_groups`. Full CLI suite (132 cases) passes. | iter-057 ✅ |

---

## 6 · Operational guidance

If you actually want the model to hold:

1. **Use a strong passphrase**. Argon2id with `time=3, mem=64MB,
   parallel=4` makes a weak passphrase (< 10 random ASCII chars,
   or any dictionary phrase) breakable on consumer hardware. Use a
   passphrase generator with ≥ 80 bits of entropy (e.g. `diceware`
   7+ words).

2. **Save the mnemonic**. Without the salt, your passphrase alone
   doesn't recover the identity. Lose both, lose the account.

3. **Run with `--tor`**. The default `--mode cli` opens a TCP
   port. That's fine on a LAN you trust, useless on the public
   internet.

4. **Verify the peer_id out-of-band on first contact**. The TOFU
   window is exactly that: trust on first use. Compare the
   40-character peer_id by another channel (in person, signal,
   whatever) before you start sharing anything sensitive.

5. **Trust group membership only as far as you trust your fanout
   list**. Removing a member is a local operation; no cryptographic
   guarantee they actually stop receiving until your client stops
   sending. (TM-01.)

6. **Don't trust the client more than you trust the host machine**.
   `panic()` wipes RAM. The address book on disk is encrypted but
   still on disk. Cold-boot attacks, swap files, and forensic disk
   recovery beat any user-space messenger.

7. **Read-receipt silence is information**. Use the receipt UI to
   notice when a peer stops responding — it could mean delivery
   broke, but also that the recipient has been compromised and a
   third party is reading without sending the receipt back.

---

## 7 · Versioning of this document

This file is part of the wire-format contract. Material changes to
the threat model bump the wire major version (and thus the protocol
RC level). Editorial / clarification changes don't.

| Doc rev | Code rev    | Date       | Change                                              |
|---------|-------------|------------|-----------------------------------------------------|
| 1.0     | 1.0.0-rc1   | 2026-05-09 | Initial public draft.                               |
