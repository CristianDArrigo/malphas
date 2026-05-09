# malphas — Wire Protocol Specification

> **Wire version: `1.0.0-rc1`** (frozen 2026-05-09)
>
> Status: **release candidate**, **not externally reviewed**.
> Breaking changes from this point require a major version bump and
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

```
seed64 = Argon2id(
    password    = passphrase,
    salt        = salt_16,        # per-user, persisted in ~/.malphas/salt
    time_cost   = 3,
    memory_cost = 65536,          # KiB
    parallelism = 4,
    hash_len    = 64,
)

ed25519_seed = seed64[:32]
x25519_seed  = seed64[32:]

ed25519_priv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
x25519_priv  = X25519PrivateKey.from_private_bytes(x25519_seed)

ed25519_pub  = ed25519_priv.public_key().public_bytes(Raw, Raw)
x25519_pub   = x25519_priv.public_key().public_bytes(Raw, Raw)

peer_id      = hex( BLAKE2s(ed25519_pub, digest_size=20) )    # 40 hex chars
```

The salt is 16 random bytes generated at first run, persisted at
mode 0600 to `~/.malphas/salt`. Loss of the salt is loss of
identity (different `seed64`). The salt is recoverable from the
12-word BIP39 mnemonic.

The address-book key is independent:

```
book_key = HKDF-SHA256(seed64, salt=b"", info=b"malphas-book-key", len=32)
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
| 0x07  | PEER_ANNOUNCE     | both      | discovery JSON, deprecated                 |

`length` is unsigned big-endian, max 16 MiB enforced by the reader.

---

## 5 · Handshake

Both sides exchange `MSG_HANDSHAKE` (initiator) /
`MSG_HANDSHAKE_ACK` (responder) carrying:

```json
{
  "v":          1,
  "peer_id":    "<40 hex>",
  "x25519_pub": "<64 hex>",
  "ed25519_pub":"<64 hex>",
  "eph_pub":   "<64 hex, ephemeral X25519>",
  "sig":       "<128 hex, Ed25519(eph_pub || timestamp)>",
  "ts":         <unix seconds>
}
```

After both messages:

```
session_key = HKDF-SHA256(
  ECDH(my_eph_priv, their_eph_pub),
  salt = sha256(my_peer_id || their_peer_id),
  info = b"malphas-session-key",
  len  = 32,
)
hmac_key    = HKDF-SHA256(session_key, b"", b"malphas-hmac-key", 32)
ratchet_root = derive_root_key(session_key, ...)   # see ratchet.py
```

Both peers verify the signature against the claimed `ed25519_pub`,
recompute the BLAKE2s peer_id from `ed25519_pub`, and compare with
the claimed `peer_id`. Mismatch ⇒ disconnect.

If the receiver had a pinned key for this peer_id (PinStore), the
new `ed25519_pub` and `x25519_pub` must match the pinned values
exactly. Mismatch ⇒ pin violation, disconnect, surface to UI.

---

## 6 · Onion-wrapped frames

`MSG_ONION` payload is a 3-hop onion. Each layer:

```
Layer:
  [32: ephemeral_pub_x25519]
  [20: next_hop_id]                  // all-zeroes = final hop
  [4:  encrypted_payload_len]
  [N:  encrypted_payload]            // ChaCha20-Poly1305 over
                                      //  HKDF(ECDH(eph, hop_static),
                                      //       info="malphas-onion-v1")
```

The innermost encrypted_payload at the final hop is the
**authenticated payload** (§7).

Padding (§8) is applied **inside** the AEAD plaintext at every
layer so that all relays see frames of the same size class.

---

## 7 · Authenticated payload

After peeling all onion layers, the bytes are `[1: auth_type] ||
auth_data`:

| `auth_type` | Hex | Meaning                                     | `auth_data` layout                                      |
|-------------|-----|---------------------------------------------|----------------------------------------------------------|
| `R` (0x52)  | 52  | Double Ratchet ciphertext (preferred)       | `[40: header] [N: ratchet_ciphertext]`                   |
| `H` (0x48)  | 48  | HMAC-authenticated JSON                     | `[32: HMAC-SHA256(hmac_key, json)] [N: json_bytes]`      |
| `E` (0x45)  | 45  | Ed25519-signed JSON (fallback / first msg)  | `[64: Ed25519(json)] [N: json_bytes]`                    |

**Selection order at the sender:** ratchet (if a session is
established) → HMAC → Ed25519. The `auth_type` byte was introduced
in v0.4.0; before that there was no prefix and `H` was implicit.

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

See `ratchet.py` for the symmetric/DH ratchet rules. `MAX_SKIP=100`.

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

### 8.2 · Sealed-sender envelope

```
ephemeral X25519 keypair generated fresh per message:
  eph_priv, eph_pub

shared = ECDH(eph_priv, recipient_x25519_pub)
key    = HKDF-SHA256(shared, b"", b"malphas-sealed-sender-v1", 32)
ct     = ChaCha20-Poly1305(key, nonce=12 random, plaintext=peer_id_utf8)

from_eph    = hex(eph_pub)
from_sealed = b64(nonce(12) || ct)
```

Recipient inverts using their X25519 private key.

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
| 1.0.0-rc1 | All wire format frozen here. Breaking changes from this point require **2.0.0**. |

### 10.1 · Wire freeze policy from `1.0.0-rc1`

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

### 11.1 · `~/.malphas/salt`

```
[16: salt]
```

Mode 0600. Created at first run if absent.

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
[12: nonce] || ChaCha20-Poly1305(book_key, json)
```

Same key as the address book; we use HKDF info=`malphas-pin-key`
in a future version (see §13).

```json
{ "<peer_id>": { "x25519_pub": "...", "ed25519_pub": "..." } }
```

### 11.4 · Tor v3 hidden-service key

Persisted by the `stem` controller under
`~/.malphas/tor/hidden_service/`. Owned by the running Tor process.
Backed up via the BIP39 mnemonic? **No** — Tor HS keys are derived
from Ed25519 separately. Reconstructing from passphrase + salt +
Argon2 → Ed25519 → onion is deterministic, so the .onion address
is stable across re-installs of the same identity.

---

## 12 · BIP39 mnemonic backup

```
mnemonic_words = bip39_encode(salt_16)        # 12 words from English wordlist
salt_16        = bip39_decode(mnemonic_words)
```

Standard BIP39 with 128 bits of entropy ⇒ 12 words. The mnemonic
backs up **only** the salt. The passphrase is unrecoverable by
design. To restore an identity:

1. Recover the salt from the mnemonic.
2. Run `malphas` with `--salt /path/to/restored-salt`.
3. Enter the same passphrase you used originally.

---

## 13 · Pending normative changes for `1.0.0`

These are accepted clarifications that do **not** break wire
compatibility but tighten the spec for future readers:

- §11.3: derive a separate pin-store key via HKDF info string
  `b"malphas-pin-key"` instead of reusing the book key.
  (Does not require migration: the same pinstore can be
  re-encrypted on first 1.0.0 run.)
- §8.1: add `member_ratchet` kind for group key rotation
  (planned for 1.1.0; receivers in 1.0 ignore it = no break).

---

## 14 · Test vectors

To be added in `tests/test_protocol_vectors.py` before `1.0.0`
final. Each test vector is a triple
`(input, expected_bytes, description)` exercising one production
path end-to-end. **None exist yet.** Reviewer: this is a known gap.

---

## 15 · Document version

| Doc rev | Code rev    | Date       | Change                                          |
|---------|-------------|------------|-------------------------------------------------|
| 1.0     | 1.0.0-rc1   | 2026-05-09 | Initial freeze. Reviewer-ready.                 |
