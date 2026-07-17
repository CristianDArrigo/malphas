# malphas — Wire Protocol Specification

> **Wire version: `WIRE_VERSION = 2`** (stable since `1.0.0`, 2026-06-16;
> the field set was first frozen at `1.0.0-rc1`, 2026-05-09, and the v2
> handshake/ratchet changes landed in `1.0.0-rc7`)
>
> Status: **stable** (`1.0.0`). The wire format is frozen and binding:
> breaking changes from this point require a major version bump and
> a deprecation window — see §10.
>
> This document is the authoritative description of every byte
> malphas writes to the network and to disk. If the code disagrees
> with this document, **the document wins** until both are updated
> together.

---

## 1 · Notation

- `||` is byte concatenation.
- `[N: name]` is N bytes of the named field.
- `>BI` is `struct.pack` big-endian: 1-byte uint, 4-byte uint.
- `hex(x)` is lowercase hex, no `0x` prefix.
- `b64(x)` is standard base64 with padding.
- `KDF(ikm, salt, info, len) = HKDF-SHA256(ikm, salt, info)[:len]`.

All numeric fields are big-endian unless stated.

---

## 2 · Cryptographic primitives

| Purpose                                | Primitive                                   |
|----------------------------------------|---------------------------------------------|
| ECDH                                   | X25519 (Curve25519)                         |
| Signatures                             | Ed25519                                     |
| AEAD                                   | ChaCha20-Poly1305, 12-byte nonce            |
| HKDF                                   | HKDF-SHA256                                 |
| HMAC (auth path)                       | HMAC-SHA256                                 |
| Hash → peer_id                         | BLAKE2s, 20-byte digest, no key             |
| Passphrase KDF                         | Argon2id, t=3, mem=64 MiB, p=4, hashlen=64 |
| Wordlist                               | BIP39 English (2048 words)                  |
| Onion HS                               | Tor v3 (Ed25519, derived from identity)     |

**Nonces.** Each AEAD encryption uses a fresh 12-byte random nonce
prepended to the ciphertext on the wire. We never reuse a (key,
nonce) pair: keys are per-session or per-message (Double Ratchet),
nonces are random.

**Random source.** `secrets` (CSPRNG) for all keys/nonces.
Non-cryptographic randomness (jitter) uses `random` and is
documented inline.

---

## 3 · Identity derivation

Identity is derived from a **random 32-byte root**, not from the passphrase.
The root is generated once at first run and stored wrapped under a passphrase-
derived Key-Encryption-Key (see §3.1). All long-term keys are HKDF-derived from
the root with distinct domain-separation labels:

```
root32       = 32 random bytes (first run) | restored from mnemonic

ed25519_seed = HKDF-SHA256(root32, salt=b"malphas-identity-root-v2",
                           info=b"ed25519-signing-key", len=32)
x25519_seed  = HKDF-SHA256(root32, salt=b"malphas-identity-root-v2",
                           info=b"x25519-dh-key", len=32)
tor_seed     = HKDF-SHA256(root32, salt=b"malphas-tor-identity-v1",
                           info=b"tor-onion-key", len=32)   # dedicated Tor key

ed25519_priv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
x25519_priv  = X25519PrivateKey.from_private_bytes(x25519_seed)

ed25519_pub  = ed25519_priv.public_key().public_bytes(Raw, Raw)
x25519_pub   = x25519_priv.public_key().public_bytes(Raw, Raw)

peer_id      = hex( BLAKE2s(ed25519_pub, digest_size=20) )    # 40 hex chars
```

Because the root is **random**, `peer_id` and the keys are independent of the
passphrase. This closes the offline oracle of the old scheme (where an attacker
holding the salt could brute-force the passphrase by re-deriving `peer_id`), and
lets the passphrase be rotated without changing identity.

### 3.1 · Identity at rest and recovery

The 32-byte root is the only long-term secret. It is stored at
`~/.malphas/identity` (mode 0600, JSON) wrapped under a passphrase-KEK:

```
kek          = Argon2id(passphrase, salt_16, t=3, m=65536, p=4, hash_len=32)
wrapped_root = ChaCha20-Poly1305(kek, root32, aad=b"malphas-identity-root-kek-v1")

identity file = { "v":1, "kdf":"argon2id", "salt":hex(16), "wrapped_root":hex(nonce||ct) }
```

* **Recovery:** the root is backed up as a **24-word** BIP39 mnemonic. Restore
  with `--from-mnemonic`, then choose any passphrase.
* **Passphrase rotation:** re-wrap the same root under a new KEK (fresh salt).
  Identity is unchanged. Exposed in the app as `/passwd`.

The address-book key is HKDF-derived from the same root, cryptographically
independent of the identity keys:

```
book_key = HKDF-SHA256(root32,
                       salt=b"malphas-addressbook-v1",
                       info=b"addressbook-encryption-key",
                       len=32)
```

---

## 4 · Outer wire frame

Every TCP/Tor stream is a sequence of length-prefixed messages:

```
Frame:
  [1: msg_type] [4: length] [length: payload]
```

`msg_type` (defined in `node.py`):

| Code  | Name              | Direction | Payload                                    |
|-------|-------------------|-----------|--------------------------------------------|
| 0x01  | HANDSHAKE         | C→S       | hello bytes (§5)                           |
| 0x02  | HANDSHAKE_ACK     | S→C       | hello bytes (§5)                           |
| 0x03  | ONION             | both      | onion-wrapped data (§6)                    |
| 0x05  | PING              | both      | empty                                      |
| 0x06  | PONG              | both      | empty                                      |
| 0x07  | PEER_ANNOUNCE     | both      | deprecated; received frames are dropped    |

`length` is unsigned big-endian, capped at 16 MiB (`MAX_FRAME_BYTES`)
and enforced by the reader **before** the payload body is read: a frame
whose declared length exceeds the cap is rejected on the header alone, so
a single crafted length prefix cannot drive an unbounded allocation.

---

## 5 · Handshake

Both sides exchange `MSG_HANDSHAKE` (initiator) /
`MSG_HANDSHAKE_ACK` (responder) carrying:

```json
{
  "v":           2,
  "peer_id":     "<40 hex>",
  "x25519_pub":  "<64 hex>",
  "ed25519_pub": "<64 hex>",
  "eph_pub":     "<64 hex, ephemeral X25519>",
  "eph_sig":     "<128 hex, Ed25519(eph_pub || x25519_pub)>",
  "port":        <int, sender's P2P listen port>
}
```

`v` is mandatory and must equal `WIRE_VERSION` (2 since `1.0.0-rc7`); a
missing or mismatched value is rejected at the handshake.

After both messages:

```
session_key = HKDF-SHA256(
  ECDH(my_eph_priv, their_eph_pub),
  salt = sorted(my_eph_pub, their_eph_pub)[0] || sorted(...)[1],
  info = b"malphas-session-v1",
  len  = 32,
)
hmac_key    = HKDF-SHA256(session_key,
                          salt = b"malphas-hmac-v1",
                          info = b"message-auth",
                          len  = 32)

# The Double Ratchet is seeded from the RAW ECDH shared secret (not
# session_key) via RatchetState.from_shared_secret:
ratchet_root = HKDF-SHA256(shared,
                           salt = b"malphas-ratchet-root-v1",
                           info = b"root-key",
                           len  = 32)
# Per-DH-step root+chain: HKDF-SHA256(dh_output, salt=root_key,
#   info=b"malphas-ratchet-dh-v1", len=64) -> (new_root, chain_key).
# Symmetric chain step: HKDF-SHA256(chain_key, salt=b"malphas-ratchet-v1",
#   info=b"chain"|b"message", len=32). See ratchet.py.
```

The session salt is the two ephemeral X25519 public keys sorted
byte-wise and concatenated (not the peer_ids): this makes both peers
derive the identical key regardless of initiator/responder role, without
needing to agree on peer_id ordering.

Both peers verify `eph_sig` against the claimed `ed25519_pub` over
`eph_pub || x25519_pub` (since `1.0.0-rc7` — previously over `eph_pub`
alone). Covering the static `x25519_pub` binds the encryption key to the
identity: an on-path attacker cannot swap `x25519_pub` to redirect the
peer's sealed-sender envelopes (§8.2) to itself. Both peers then recompute
the BLAKE2s peer_id from `ed25519_pub` and compare with the claimed
`peer_id`. Mismatch ⇒ disconnect. This binds the identity cryptographically
to the Ed25519 key, and the bound identity is what every later
authentication step (HMAC, ratchet, sealed-sender §8.2) is checked against.

If the receiver had a pinned key for this peer_id (PinStore), the new
`ed25519_pub` **and** `x25519_pub` must match the pinned values exactly
(both are pinned since `1.0.0-rc7`; the two keys derive from one identity
seed, so a matching Ed25519 with a different X25519 is an impersonation
signal). Mismatch ⇒ pin violation, disconnect, surface to UI.

---

## 6 · Onion-wrapped frames

`MSG_ONION` payload is a 3-hop onion. The whole packet is prefixed with
`first_hop_id(20) || layer_len(4)`. Each layer on the wire:

```
Layer:
  [32: ephemeral_pub_x25519]
  [4:  encrypted_len]
  [N:  encrypted]                    // ChaCha20-Poly1305, aad = ephemeral_pub,
                                      //  key = HKDF(ECDH(eph, hop_static),
                                      //            salt = sorted(eph_pub, hop_static),
                                      //            info = "malphas-session-v1")
```

The AEAD plaintext of each layer is:

```
  [20: next_hop_id]                  // all-zeroes = final hop
  [4:  inner_payload_len]
  [M:  inner_payload]                // the next layer, or the payload at the final hop
```

`next_hop_id` is carried **inside** the AEAD, not as a cleartext field:
a passive relay cannot read where its layer forwards to. The onion layer
key uses the same derivation as the session key (`derive_session_key`,
`info="malphas-session-v1"`); there is no separate `malphas-onion-v1`
context. The innermost inner_payload at the final hop is the
**authenticated payload** (§7).

Padding (§8) is applied **inside** the AEAD plaintext at every
layer so that all relays see frames of the same size class.

**Relay selection.** A node only relays through peers it currently
holds a **live, authenticated connection** to: the first hop is sent
over an existing connection, never by dialing an unauthenticated
relay on demand. If no connected relays are available the circuit
degrades to a single direct hop to the destination (the onion is
still built, but with zero intermediate relays). Hop count is
therefore best-effort, bounded above by 3 and below by 1.

---

## 7 · Authenticated payload

After peeling all onion layers, the bytes are `[1: auth_type] ||
auth_data`:

| `auth_type` | Hex | Meaning                                     | `auth_data` layout                                      |
|-------------|-----|---------------------------------------------|----------------------------------------------------------|
| `R` (0x52)  | 52  | Double Ratchet ciphertext (preferred)       | `[40: header] [N: ratchet_ciphertext]`                   |
| `H` (0x48)  | 48  | HMAC-authenticated JSON                     | `[32: HMAC-SHA256(hmac_key, json)] [N: json_bytes]`      |
| `X` (0x58)  | 58  | X3DH session opener (forward-secret fallback) | `[32: IK_A] [32: EK_A] [32: SPK_B] [40: header] [N: ratchet_ciphertext]` |
| `E` (0x45)  | 45  | Ed25519-signed JSON (legacy fallback)       | `[64: Ed25519(json)] [N: json_bytes]`                    |

**Selection order at the sender:** ratchet on a live connection → HMAC
on a live connection → **X3DH** when not connected but the peer's signed
prekey is known → Ed25519 only when no prekey is known. The `auth_type`
byte was introduced in v0.4.0; before that there was no prefix and `H`
was implicit.

### 7.0 · X3DH prekey delivery (issue #12)

To deliver to a peer we are not directly connected to (multi-hop) with
forward secrecy and deniability, the sender runs reduced X3DH against the
peer's signed prekey `SPK_B` (published, Ed25519-signed, in the invite):

```
DH1 = X25519(IK_A_priv, SPK_B_pub)
DH2 = X25519(EK_A_priv, IK_B_pub)     # EK_A is a fresh per-session ephemeral
DH3 = X25519(EK_A_priv, SPK_B_pub)
SK  = HKDF-SHA256(0xFF*32 || DH1 || DH2 || DH3,
                  salt=b"malphas-x3dh-v1", info=b"x3dh-shared-secret", len=32)
```

`SK` seeds a Double Ratchet (initiator uses `SPK_B` as the initial ratchet
key). The first message is sent as `X` carrying `IK_A/EK_A/SPK_B`; the
recipient reproduces `SK`, seeds a responder ratchet, decrypts, and keeps
the session so subsequent messages continue as `R`. Deniability holds
because `SK` is symmetric; the Ed25519 signature only authenticates the
prekey, never a message. No one-time prekeys yet (reduced X3DH): first-
message forward secrecy relies on `SPK_B` being ephemeral relative to the
identity; the ratchet provides per-message forward secrecy thereafter.

**Why three:** ratchet gives PFS, HMAC is fast and deniable, Ed25519
is the only option before the ratchet bootstraps. A receiver
**must not** auto-downgrade — accept exactly the prefix that came
in and route to the corresponding verifier.

**Demotion attack:** an attacker stripping `R` to make the receiver
fall back to `E` is defeated because the inner ratchet ciphertext is
not a valid Ed25519-signed JSON, so verification fails.

### 7.1 · Ratchet header

```
[32: dh_pub_x25519]
[4:  prev_count: uint32 BE]
[4:  msg_num:    uint32 BE]
```

See `ratchet.py` for the symmetric/DH ratchet rules. `MAX_SKIP=1000`:
a header whose `msg_num`/`prev_count` would skip more than `MAX_SKIP`
message keys is **rejected** (raises) rather than processed, per the
Signal spec. The attacker-controlled `msg_num` is a uint32, so without
this bound a single header could force ~2³² skipped-key KDF iterations;
the cap keeps skipped-message work bounded.

---

## 8 · Inner JSON payload (kind dispatch)

Decrypted plaintext at the innermost layer is a UTF-8 JSON object.
The `kind` field selects the application protocol:

```json
{
  "kind":        "<string>",
  "from_eph":    "<32-byte hex, sealed-sender ephemeral>",
  "from_sealed": "<base64, sealed peer_id ciphertext>",
  "msg_id":      "<random hex>",
  "ts":          <unix seconds>,
  ... kind-specific fields ...
}
```

`from` is **never** sent in cleartext from v0.6.0 onward. The
recipient decrypts (`from_eph`, `from_sealed`) using their static
X25519 key (§3) to recover the real peer_id. See §9.

### 8.1 · Defined kinds

| `kind`           | Semantics                                                              | Extra fields                                                                                                           |
|------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `msg`            | Direct text message                                                    | `content` (str), `nonce` (hex)                                                                                         |
| `receipt`        | Read receipt over (`msg_id`, `nonce`)                                  | `target_msg_id`, `nonce`, `sig` (Ed25519 over `target_msg_id || nonce || "read"`)                                      |
| `cover`          | Cover-traffic dummy, dropped on receive                                | `len` (int)                                                                                                            |
| `file_offer`     | Initiate a file transfer                                               | `file_id`, `name`, `size`, `sha256`, `chunk_size`                                                                      |
| `file_chunk`     | One chunk of a file                                                    | `file_id`, `index`, `total`, `data` (b64)                                                                              |
| `file_ack`       | Receiver acks a chunk                                                  | `file_id`, `index`                                                                                                     |
| `file_resume`    | Receiver tells sender which indices it already has                     | `file_id`, `received` (list[int])                                                                                      |
| `group_invite`   | Add recipient to a group                                               | `group_id`, `group_name`, `members` (list[peer_id])                                                                    |
| `group_msg`      | Group message (one per member, fanout)                                 | `group_id`, `group_name`, `content`, `nonce`                                                                           |
| `group_member_change` | Membership update (added / removed) — additive in `1.0.0-rc3`     | `group_id`, `group_name`, `action` (`"add"`/`"remove"`), `target` (peer_id), `members` (full new list)                  |

### 8.2 · Sealed-sender envelope

```
ephemeral X25519 keypair generated fresh per message:
  eph_priv, eph_pub

shared = ECDH(eph_priv, recipient_x25519_pub)
key    = HKDF-SHA256(shared, salt=b"malphas-sealed-sender-v1", info=b"from", 32)
ct     = ChaCha20-Poly1305(key, nonce=12 random, plaintext=peer_id_utf8)

from_eph    = hex(eph_pub)
from_sealed = b64(nonce(12) || ct)
```

Recipient inverts using their X25519 private key.

On the ratchet path (`auth_type` `R`, §7) the recovered `from`
peer_id is **bound to the connection's authenticated peer** (§5): if
the unsealed `from` does not equal the handshake-authenticated
identity of the connection the frame arrived on, the message is
dropped and the ratchet state is rolled back. The sealed-sender
`from` is therefore an addressing aid, not an authentication claim —
it cannot be used to impersonate another peer onto a ratchet that was
established with someone else.

---

## 9 · Replay protection

Receiver maintains `ReplayCache(ttl=3600s, max=10000 entries)` keyed
by (`from_id_after_unseal`, `msg_id`). Drops on hit. See §3 of
`THREAT_MODEL.md` for the trade-offs.

---

## 10 · Versioning rules

We follow SemVer with one carve-out: **wire-format-breaking changes
always bump major or minor** (never patch).

| Version   | Wire-compatible with        |
|-----------|-----------------------------|
| 0.6.x     | 0.6.x only (sealed sender)  |
| 0.7.x     | 0.7.x only (per-user salt)  |
| 0.8.x     | 0.7.x ⊕ resume optional     |
| 0.9.x     | 0.8.x ⊕ groups optional     |
| 0.10.x    | 0.9.x ⊕ GUI only            |
| 0.11.x    | 0.10.x ⊕ Qt GUI only        |
| 1.0.0-rc1 | Wire format frozen in intent (`WIRE_VERSION` 1). Frozen *fields* listed in §10.1. |
| 1.0.0-rc7 | `WIRE_VERSION` 2. Final pre-1.0 break carrying the security-audit fixes — does **not** interoperate with the `v1` wire of rc1–rc6. |
| **1.0.0** | **Stable. `WIRE_VERSION` 2, frozen and binding** — breaking changes from here require **2.0.0**. |

### 10.1 · Wire freeze policy

The freeze was declared at `1.0.0-rc1` and is **binding from `1.0.0`**. The
last intentional break was `1.0.0-rc7`: the handshake JSON shape (§5:
`eph_sig` now covers `x25519_pub`) and the Double Ratchet header binding
(now AEAD AAD), with `WIRE_VERSION` bumped 1 → 2 so a mismatch fails cleanly
at the handshake. From `1.0.0`:

- **Frozen fields** (cannot change without a major bump): `peer_id`
  derivation (§3), outer frame layout (§4), handshake JSON shape
  (§5), onion layer layout (§6), `auth_type` byte values (§7),
  every `kind` already listed in §8.1, and the sealed-sender
  envelope shape (§8.2).
- **Additive changes allowed in 1.x patches** (NOT minor): new
  optional `kind` values, new optional fields inside an existing
  `kind` JSON object **only if** receivers ignore unknown fields.
- **Removal of any documented field requires a major bump.**

### 10.2 · Receiver leniency

A 1.x receiver MUST:
- Drop a frame whose `auth_type` is unknown.
- Drop a JSON payload whose `kind` is unknown (no error to peer).
- Ignore unknown fields in a known `kind`.
- Reject any payload missing a required field (§8.1).

---

## 11 · On-disk formats

### 11.1 · `~/.malphas/identity`

```
{ "v": 1, "kdf": "argon2id", "salt": <hex 16>, "wrapped_root": <hex nonce||ct> }
```

Mode 0600. Created at first run. Holds the random 32-byte identity root
wrapped under a passphrase-derived Argon2id KEK (see §3.1). `salt` is the
per-identity KEK salt, not an identity input.

### 11.2 · `~/.malphas/book` (address book)

```
[12: nonce] || ChaCha20-Poly1305(book_key, padded_json)
```

Padded to nearest multiple of `BLOCK_SIZE` (1024 bytes). Mode 0600.
Plaintext layout:

```json
[
  {
    "label":        "...",
    "peer_id":      "<40 hex>",
    "host":         "...",
    "port":         12345,
    "x25519_pub":   "<64 hex>",
    "ed25519_pub":  "<64 hex>"
  },
  ...
]
```

### 11.3 · `~/.malphas/pins`

```
[12: nonce] || ChaCha20-Poly1305(book_key, json, aad=b"malphas-pinstore-v1")
```

Same key as the address book, with domain-separating AAD. (Deriving a
separate pin-store key via HKDF info=`malphas-pin-key` is a future change,
see §13.)

```json
{ "<peer_id>": { "ed25519": "<64 hex>", "x25519": "<64 hex|null>" } }
```

`x25519` is `null` for pins migrated from the pre-`1.0.0-rc7` ed25519-only
format; it is back-filled on the next contact with that peer.

### 11.4 · Tor v3 hidden-service key

The node registers the v3 HS over the Tor **ControlPort** with
`ADD_ONION` (since `1.0.0`'s post-release hardening — earlier versions
wrote key files under `/var/lib/tor` and restarted tor, which needed
sudo). It hands Tor the *expanded* Ed25519 secret key
(`ED25519-V3 = clamp(SHA-512(seed))`, base64) and a `Port=80,127.0.0.1:<p>`
mapping, so the onion is the same deterministic address every launch.
The service is **ephemeral and connection-scoped**: it is bound to the
control connection (`Flags` without `Detach`), so Tor drops it
(`DEL_ONION`) automatically when the node stops or the process dies —
no key files on disk, no `torrc` edits, no tor restart, **no sudo**.

This needs Tor's ControlPort enabled and authenticable: cookie auth
(the user must be able to read the control auth cookie — typically by
membership in the `debian-tor`/`tor` group) or a control password. If
authentication fails, the node logs the reason and runs outbound-only
(it can still dial peers' onions; it just isn't reachable inbound).

The Tor key is a **dedicated** Ed25519 key HKDF-derived from the identity
root (`info="tor-onion-key"`), separate from the messaging identity, so a
Tor/ControlPort compromise cannot forge messaging-identity signatures.
Because it derives from the root, restoring the root (from the mnemonic)
reproduces the same `.onion` across re-installs; it is independent of the
passphrase.

---

## 12 · BIP39 mnemonic backup

```
mnemonic_words = bip39_encode(root_32)        # 24 words from English wordlist
root_32        = bip39_decode(mnemonic_words)
```

Standard BIP39 with 256 bits of entropy ⇒ 24 words. The mnemonic backs up
the identity **root**. The passphrase only encrypts the root at rest and can
be chosen freely on restore (or changed later with `/passwd`). To restore an
identity:

1. Run `malphas --from-mnemonic` and enter the 24 words when prompted.
2. Choose a passphrase (it wraps the restored root; it need not match the old one).

---

## 13 · Pending normative changes for `1.0.0`

These are accepted clarifications that do **not** break wire
compatibility but tighten the spec for future readers:

- §11.3: derive a separate pin-store key via HKDF info string
  `b"malphas-pin-key"` instead of reusing the book key.
  (Does not require migration: the same pinstore can be
  re-encrypted on first 1.0.0 run.)
- §8.1: add `member_ratchet` kind for cryptographic group key
  rotation (MLS-style PCS at membership-change boundary).
  Operational membership consensus already shipped in
  `group_member_change` (§8.1, additive in 1.0.0-rc3); the
  cryptographic rotation is the harder, deferred half of TM-01.

---

## 14 · Test vectors

Implemented in `tests/test_protocol_vectors.py` from `1.0.0-rc5`.
Each vector is one of two flavours:

- **Deterministic** (input → exact expected bytes). Used for
  identity derivation, BIP39 mnemonic, HKDF, HMAC. A refactor
  that silently changes the algorithm breaks these.
- **Round-trip / invariant** (encode → decode → original) for
  paths that involve fresh ephemeral keys or random nonces:
  sealed sender, onion peel, AEAD with AAD. We pin the format
  invariants (lengths, prefixes, base64 validity) and verify
  that {encode → decode} returns the original.

Notable pinned constants:

- BIP39 vector `b"\x00" * 16` →
  `"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"`.
- BIP39 vector `b"\xff" * 16` →
  `"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"`.
- HKDF-SHA256 KAT: `hkdf_derive(0x00*32, salt=0x00*32, info=b"vec", len=32)`
  → `85c913f550ac008224038181a831e49bf3d283690d72d4ea0edc6c7018da7f01`.
- `peer_id` is 40 lowercase hex chars (BLAKE2s-160).
- X25519 / Ed25519 public keys are 32 bytes.
- HMAC-SHA256 tag is 32 bytes.
- Sealed-sender `from_eph` is 64 hex chars; `from_sealed` is
  base64 of (12-byte nonce || ChaCha20-Poly1305 tag-included
  ciphertext), so ≥ 28 raw bytes.

If you find an external KAT (a real cross-implementation
known-answer test) you'd like added, the file's docstring is
the contract surface to extend.

---

## 15 · Document version

| Doc rev | Code rev    | Date       | Change                                          |
|---------|-------------|------------|-------------------------------------------------|
| 1.0     | 1.0.0-rc1   | 2026-05-09 | Initial freeze. Reviewer-ready.                 |
| 1.1     | 1.0.0-rc7   | 2026-06-16 | `WIRE_VERSION` 2: handshake `eph_sig` covers `x25519_pub`, both keys pinned, ratchet header bound as AAD. Security-audit fixes. |
| 1.2     | 1.0.0       | 2026-06-16 | Stable release. Wire frozen and binding (no spec change from rc7). |
