# malphas

```
                                ************
                           *********#**#**#**#*********
                       ****#*****     ***# ***   **#*******
                      ***#***            ******          *******
                   ******              *******#            #**#**
                 *****              *#*******#**              **#**
             **#**          *****              *****          **#**
             ****#         ***                        **#         *****
              ***#****     **                              **         ****
               **### ***** ***                                  ***      *##***
```

**Privacy-first P2P messenger with onion routing and Tor hidden service support.**

No servers. No accounts. No logs. No traces.

---

## Table of Contents

1. [What is malphas](#what-is-malphas)
2. [Threat Model](#threat-model)
3. [Cryptographic Stack](#cryptographic-stack)
4. [Architecture](#architecture)
5. [Installation](#installation)
6. [Quickstart](#quickstart)
7. [CLI Reference](#cli-reference)
8. [How the Network Works](#how-the-network-works)
9. [Tor Hidden Services](#tor-hidden-services)
10. [Identity System](#identity-system)
11. [Address Book](#address-book)
12. [Security Features](#security-features)
13. [Traffic Obfuscation](#traffic-obfuscation)
14. [Read Receipts](#read-receipts)
15. [Limitations](#limitations)
16. [Testing](#testing)
17. [Development](#development)
18. [Disclaimer](#disclaimer)

---

## What is malphas

malphas is a peer-to-peer encrypted messaging system. It has no central servers, no user accounts, no message storage on any infrastructure you do not control, and no logging of any kind.

Messages are encrypted end-to-end with modern cryptographic primitives, routed through an application-layer onion network, and optionally transported over Tor hidden services. The entire message history exists only in RAM for the duration of a session and is wiped when the process exits.

The name comes from malphas — a demon in demonology described as a builder of fortresses and a carrier of secrets. The metaphor is deliberate.

---

## Threat Model

malphas is designed to protect against the following adversaries:

**Protected against:**

- Passive network observers (ISPs, network administrators, traffic loggers) — they see encrypted traffic of uniform size, indistinguishable from cover traffic
- Service providers and infrastructure operators — there are no servers to subpoena
- Remote forensics — no data is written to disk except the encrypted address book
- Man-in-the-middle attacks — all connections are authenticated via Ed25519 signatures
- Brute force attacks on the address book — Argon2id makes offline dictionary attacks computationally prohibitive (64MB RAM + ~200ms per attempt)

**Partially protected against:**

- Traffic correlation attacks — cover traffic and padding reduce but do not eliminate timing correlation; a well-resourced adversary monitoring both endpoints simultaneously may still infer communication patterns
- Tor-level adversaries — global passive adversaries controlling a significant portion of Tor relays could theoretically perform traffic correlation; this is a known Tor limitation, not a malphas-specific weakness

**Not protected against:**

- Physical device compromise while malphas is running — messages in RAM are accessible via memory dump
- Compromised operating system (keyloggers, malware) — any software with kernel access can intercept the passphrase at entry time
- Social engineering of the peer — malphas secures the channel, not the human at the other end
- Legal compulsion of the peer — if your interlocutor is compelled to disclose, malphas cannot help

---

## Cryptographic Stack

Every primitive is from the `cryptography` library (backed by OpenSSL/libssl). No custom cryptography.

| Primitive | Algorithm | Purpose |
|---|---|---|
| Password hashing | Argon2id | Passphrase → master seed (64MB, ~200ms) |
| Key derivation | HKDF-SHA256 | Seed → identity keypairs, address book key |
| Key exchange | X25519 (ECDH) | Ephemeral session key establishment |
| Authenticated encryption | ChaCha20-Poly1305 | All message encryption |
| Signing | Ed25519 | Message authentication, read receipts, Tor identity |
| Onion layer | X25519 + ChaCha20-Poly1305 | Per-hop encryption in circuit |

**Key properties:**

- All session keys are ephemeral — derived fresh from X25519 ECDH for each connection
- Nonces are 12-byte random values generated per encryption operation — no nonce reuse possible
- HKDF info strings differ between identity key derivation and address book key derivation — both derived from the same Argon2id seed but cryptographically independent
- Ed25519 is the same key used for Tor v3 hidden service identity, making the `.onion` address stable and derived from the passphrase

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         APPLICATION                             │
│  CLI (cli_ui.py)          PWA Frontend (frontend/pwa/)          │
│  FastAPI API (api.py)     WebSocket real-time                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                           NODE                                  │
│  MalphasNode (node.py)                                          │
│  ├── MessageStore     in-memory, TTL-based, zero disk           │
│  ├── ReceiptTracker   Ed25519 challenge-response                │
│  ├── PeerDiscovery    Kademlia-inspired routing table           │
│  └── CoverTraffic     randomized dummy packets                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                        TRANSPORT                                │
│  DirectTransport      raw TCP (LAN / public IP)                 │
│  TorTransport         SOCKS5 + hidden service via stem          │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                     ONION ROUTING                               │
│  wrap_onion()    build layered X25519+ChaCha20 onion packet     │
│  peel_layer()    strip one layer, get next hop or plaintext     │
│  Obfuscation     pad to 512-byte blocks, random padding bytes   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                       IDENTITY                                  │
│  Argon2id(passphrase) → 64-byte seed                           │
│  seed[:32] → Ed25519 private key    seed[32:] → X25519 key     │
│  HKDF(seed, "addressbook-encryption-key") → ChaCha20 key       │
│  SHA1(ed25519_pub) → peer_id (40-char hex)                     │
│  ed25519_pub → .onion address (Tor v3 algorithm)               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone <repo>
cd malphas
pip install -e .
```

**With Tor support** (for hidden services):

```bash
# Linux
sudo apt install tor
sudo systemctl start tor

# macOS
brew install tor
brew services start tor
```

**Dependencies installed automatically:**

- `cryptography` — all cryptographic primitives
- `argon2-cffi` — password hashing
- `fastapi` + `uvicorn` — web API (optional, web mode only)
- `stem` — Tor control protocol (optional, Tor mode only)
- `zeroconf` — mDNS peer discovery on LAN (optional)

---

## Quickstart

**Basic (LAN or public IP):**

```bash
# Node A
malphas --port 7777

# Node B (different machine or terminal)
malphas --port 7778
```

At startup malphas shows the ASCII splash, then asks for a passphrase:

```
  your identity is derived deterministically from this passphrase.
  it is never stored. the same passphrase always produces the same identity.

  weak passphrases (e.g. 'admin', 'password') make your peer_id
  precalculable by anyone who knows the algorithm. use at least
  4 random words or a long unpredictable phrase.
  example: corvo-vetro-martello-1987-luna

  passphrase:
```

**With Tor (recommended for remote peers):**

```bash
# Requires Tor running: sudo apt install tor && sudo systemctl start tor
malphas --tor --port 7777
```

malphas registers a Tor v3 hidden service and displays your `.onion` address. No port forwarding needed — it works behind any NAT.

**Web mode (PWA):**

```bash
malphas --mode web --api-port 8080
# open http://127.0.0.1:8080
```

### Connecting via invite (recommended)

The easiest way to connect two peers is the invite system:

```
# Alice generates her invite:
/export
  malphas://eyJ0eXBlIjoiaW52aXRl...

  Alice sends this URL to Bob via any channel (Signal, email, in person).
  The URL contains her public keys, host:port, and .onion address (if --tor).

# Bob imports Alice's invite:
/import malphas://eyJ0eXBlIjoiaW52aXRl...
  peer_id    a0f8e7d83391a0c9dd9f9b3ba97f7a490dafae91
  host       192.168.1.10:7777
  onion      abc...xyz.onion
  connect? [Y/n] y
  save to address book? [y/N] y
  label: alice

# Bob is now connected to Alice. If both use --tor, the connection
# goes through Alice's .onion address automatically.
/chat alice
hello alice
```

If Alice also wants Bob's credentials (for reconnecting if the session drops), Bob runs `/export` and sends his URL to Alice.

### Connecting via /add (manual)

For manual key exchange without the invite system:

```
# On peer A:
/id
  peer_id     a0f8e7d83391a0c9dd9f9b3ba97f7a490dafae91
  x25519_pub  3f7a...
  ed25519_pub 8b2c...
  port        7777

# On peer B:
/add 192.168.1.10 7777
  peer_id (40-char hex): a0f8e7d83391a0c9dd9f9b3ba97f7a490dafae91
  x25519_pub (64-char hex): 3f7a...
  ed25519_pub (64-char hex): 8b2c...
  save to address book? [y/N] y
  label: alice
```

### Quickstart: two peers over Tor

Step-by-step for two people on different networks who want to chat privately via Tor:

**Both peers** install and launch:

```bash
# Install Tor
sudo apt install tor          # Linux
brew install tor              # macOS

# Enable the control port (needed for hidden service registration)
# Edit /etc/tor/torrc (Linux) or /usr/local/etc/tor/torrc (macOS):
#   ControlPort 9051
#   CookieAuthentication 1
# Then restart Tor:
sudo systemctl restart tor    # Linux
brew services restart tor     # macOS

# Install malphas
git clone https://github.com/CristianDArrigo/malphas.git
cd malphas
pip install -e .

# Launch with Tor
malphas --tor --port 7777
# Enter a strong passphrase (same passphrase = same identity, always)
```

**Peer A** (initiator):

```
/export
→ copies the malphas://... URL and sends it to Peer B
  (via Signal, email, or any other channel)
```

**Peer B** (receiver):

```
/import malphas://...
→ automatically connects to Peer A via .onion
  connect? [Y/n] y
  save to address book? [y/N] y
  label: alice

/chat alice
hello from the other side
```

Messages are now end-to-end encrypted and routed through Tor. Neither peer's IP is exposed to the other. The `.onion` address is permanent — as long as the passphrase stays the same, the address never changes.

If Peer B also wants to be reachable when Peer A is offline and reconnects later, Peer B runs `/export` and sends the URL back to Peer A.

### Multiple peers

Each node can connect to multiple peers simultaneously. With 3+ peers, malphas uses onion routing (messages relay through intermediate peers, each seeing only adjacent hops):

```
/import malphas://...alice...
/import malphas://...bob...
/import malphas://...charlie...
/peers
  0  a0f8e7d83391a0c9...  alice
  1  b3c4d5e6f7081920...  bob
  2  c5d6e7f809102030...  charlie
/chat alice
hello — this message may route through bob or charlie as relay
```

---

## CLI Reference

```
/id                     show peer_id, public keys, and port
/peers                  list peers currently in the routing table
/book                   list address book contacts
/book add <label>       save the active conversation peer to the address book
/book rm <label>        remove a contact from the address book
/add <host> <port>      connect to a peer (prompts for their keys)
/chat <peer_id|label>   open a conversation; if label is in address book, auto-connects
/history                show message history for the active conversation
/export                 generate a signed invite URL to share your credentials
/import <url>           import a peer from an invite URL and connect
/wipe                   wipe all messages from memory (asks for confirmation)
/panic                  EMERGENCY: wipe everything and exit immediately — no confirmation
/help                   show this list
<text>                  send a message to the active conversation
```

---

## How the Network Works

malphas is a fully peer-to-peer network. There are no servers, no directory nodes, no central infrastructure of any kind.

**Routing table:** Each node maintains a Kademlia-inspired in-memory routing table of known peers, indexed by XOR distance from the node's own peer_id. The table is empty at startup and populated only through manual peer addition or peer exchange during handshakes.

**Handshake:** When two nodes connect, they perform a mutual authenticated X25519 ECDH key exchange. Each peer generates an ephemeral X25519 keypair and signs the ephemeral public key with its Ed25519 identity key. The other peer verifies the signature before proceeding — this prevents man-in-the-middle attacks. The shared secret from ECDH is used to derive a symmetric session key (ChaCha20-Poly1305) via HKDF. Neither node's long-term identity key is used for the session key — the session key is forward-secret.

**Circuit:** A circuit is the ordered list of peers a message traverses to reach its destination. Circuits are selected randomly from known peers at send time. With three or more peers available, a typical circuit is: `sender → relay → destination`. Each peer in the circuit sees only its adjacent hops.

**Onion packet format:**

```
wrap_onion builds from innermost (destination) to outermost (first relay):

  For each hop in reverse order:
    eph_priv, eph_pub = generate X25519 keypair
    shared_secret = ECDH(eph_priv, hop.x25519_pub)
    session_key = HKDF(shared_secret, salt=sorted(eph_pub, hop.x25519_pub))
    inner = next_hop_id(20) || inner_len(4) || previous_payload
    payload = eph_pub(32) || encrypted_inner_len(4) || ChaCha20(session_key, inner)

  Final packet = first_hop_id(20) || len(4) || outermost_payload
```

Each relay decrypts its layer, reads the next hop peer_id, and forwards the inner payload. The destination decrypts the final layer and gets the plaintext. No relay can decrypt more than its own layer.

**Peer discovery:** Discovery is manual by design. Peers are added via `/add` with explicit key material. mDNS (via zeroconf) provides automatic discovery on the local network if both peers are on the same subnet. There is no public directory, no DHT, no bootstrap server.

---

## Tor Hidden Services

When launched with `--tor`, malphas registers a Tor v3 hidden service using the node's Ed25519 identity key. The `.onion` address is derived from the Ed25519 public key using the standard Tor v3 algorithm:

```
onion = base32( ed25519_pub(32) || SHA3-256(".onion checksum" || pub || version)[0:2] || 0x03 ) + ".onion"
```

This means:
- The `.onion` address is deterministic — same passphrase always produces the same address
- The `.onion` address is stable across restarts
- No registration required — the address is mathematically derived from the key
- The `.onion` address can be shared as the node's permanent identifier

**Outbound connections** route through the Tor SOCKS5 proxy (default `127.0.0.1:9050`). The SOCKS5 client is implemented from scratch using asyncio with no external dependencies beyond stem for hidden service management.

**Inbound connections** arrive via Tor's introduction/rendezvous mechanism. Tor manages the 6-hop circuit (3 hops from each end meeting at a rendezvous relay). Neither peer's IP is exposed to the other.

**NAT traversal:** Tor hidden services work behind any NAT without port forwarding. This is the primary reason for Tor integration — it eliminates the requirement for at least one peer to have a publicly reachable IP address.

**Layering:** When using Tor, malphas adds its own onion routing layer on top of Tor's. An adversary who compromises the Tor circuit still cannot read malphas-level content, because the application layer uses independent keys.

---

## Identity System

Identity in malphas is entirely derived from a passphrase. Nothing is stored on disk except the encrypted address book.

```
passphrase
    │
    ▼
Argon2id(time=3, memory=64MB, parallelism=4)
    │
    ▼
64-byte seed
    ├─── seed[:32] ───────────────────────────► Ed25519 private key → peer_id = SHA1(ed25519_pub)
    ├─── seed[32:] ───────────────────────────► X25519 private key
    │
    └─── HKDF(info="addressbook-encryption-key") ──► 32-byte ChaCha20 key (address book)
```

**peer_id** is the SHA1 of the Ed25519 public key, expressed as a 40-character lowercase hex string. It is the primary identifier shared with other peers.

**Passphrase security:** Argon2id requires 64MB of RAM and approximately 200ms per derivation attempt. An attacker attempting to brute-force the passphrase from the encrypted address book file faces this cost for every attempt, making dictionary attacks against common passphrases computationally expensive and attacks against strong passphrases effectively impossible.

**Passphrase choice:** Use at least four random unrelated words or a phrase of similar entropy. Common words, names, dates, and dictionary words are weak choices regardless of how they are combined. The passphrase is never transmitted, never stored, and never logged.

---

## Address Book

The address book is stored encrypted on disk at `~/.malphas/book` (configurable via `--book`).

**Encryption:** ChaCha20-Poly1305 with the address book key derived from the passphrase. The key never appears on disk.

**On-disk format:**

```
nonce(12 bytes) || ChaCha20-Poly1305(key, padded_json)
```

The file contains no plaintext fields, no headers, and no identifiable structure. Without the correct passphrase it is indistinguishable from random noise. The padding aligns the plaintext to 4096-byte blocks before encryption, preventing the file size from revealing the exact number of contacts.

**Atomic writes:** The address book is written atomically via a `.tmp` file renamed to the final path, preventing partial writes from corrupting the stored data.

**Memory wipe:** The address book is cleared from memory on `/panic` or on clean shutdown. The file on disk is never deleted automatically — it is encrypted and useless without the passphrase.

---

## Security Features

### /panic — Emergency Wipe

`/panic` immediately clears all sensitive state from memory and terminates the process. No confirmation is required — speed is the point.

Execution order:
1. Active conversation reference cleared
2. Message store wiped (`store.wipe()`)
3. Routing table cleared (`discovery.wipe()`)
4. Pending read receipts cleared (`receipts.wipe()`)
5. All active TCP connections closed
6. Message callbacks cleared (no further processing possible)
7. Address book cleared from memory (file on disk untouched)
8. `gc.collect()` — forces garbage collection
9. `sys.exit(0)` — hard exit

The address book file on disk survives `/panic` intentionally. It is encrypted — without the passphrase it provides no information. Deleting it would permanently destroy the user's contacts.

**When to use:** If physical access to the device is imminent and you need to ensure no message history, peer information, or contact data remains in memory.

### Argon2id Password Hashing

The passphrase is never used directly as a key. It is processed through Argon2id before any key material is derived, with parameters selected to make offline brute force expensive:

- `time_cost = 3` — three passes over the memory
- `memory_cost = 65536` — 64MB of RAM required per attempt
- `parallelism = 4` — four parallel threads

An attacker with a dedicated GPU farm attempting to brute force a four-word passphrase would require years of computation at these parameters. For common passwords (dictionary words, names, dates) the cost remains high but not prohibitive — this is why passphrase choice matters.

### Authenticated Handshake

Every connection begins with a mutually authenticated handshake:

1. Each peer generates an ephemeral X25519 keypair
2. Each peer signs its ephemeral public key with its Ed25519 identity key
3. The other peer verifies the signature against the expected Ed25519 public key
4. ECDH is performed only after authentication succeeds

This prevents man-in-the-middle attacks: an attacker cannot substitute their own ephemeral key without also forging the Ed25519 signature, which requires the victim's private key.

### Message Sender Verification

All incoming messages must be signed by a peer known to the recipient's routing table. Messages claiming to be from an unknown `peer_id` are silently dropped. This prevents message injection attacks where an adversary attempts to deliver forged messages.

### No-Log Policy

malphas writes nothing to disk during operation except the encrypted address book on explicit save. Specifically:

- No message logs
- No connection logs
- No routing table persistence
- No debug output to files
- The Python logging system uses `NullHandler` throughout

The FastAPI web API disables access logs explicitly (`access_log=False`).

---

## Traffic Obfuscation

### Message Padding

All message payloads — real messages, read receipts, and cover traffic — are padded to the nearest multiple of 512 bytes before encryption. The padding bytes are cryptographically random (not zeros), making the padding indistinguishable from content.

```
padded = length_prefix(4) || plaintext || random_bytes(pad_to_512_boundary)
```

A 1-byte message and a 511-byte message produce identical ciphertext sizes. An observer cannot infer message length from packet size.

### Cover Traffic

malphas sends encrypted dummy packets to random known peers at randomized intervals (10–40 seconds, uniformly distributed). Cover packets are indistinguishable from real messages on the wire — same format, same padding, same size. The recipient decrypts the packet, identifies it as cover via a flag in the plaintext, and silently discards it.

Cover traffic is disabled by default in the test suite to avoid timing interference but enabled by default in production.

---

## Read Receipts

When a message is delivered to the destination, the recipient sends a cryptographic read receipt back to the sender.

**Protocol:**

```
Sender generates: msg_id (random 32 hex chars) + nonce (16 random bytes)
Sender embeds both in the message payload
Sender tracks pending receipt: receipts.track(msg_id, nonce, dest_peer_id)

Recipient receives message, decrypts, reads msg_id and nonce
Recipient computes: sign_Ed25519(private_key, msg_id || nonce || "malphas-read-receipt-v1")
Recipient sends receipt back through a reverse circuit

Sender receives receipt, verifies signature against recipient's known Ed25519 public key
If valid: receipt confirmed — only the holder of the recipient's private key could sign this
If timeout (30s): circuit issue or peer offline
```

**What the receipt proves:** That the holder of the recipient's Ed25519 private key processed the message. It does not prove the human read it, but it proves the message reached the correct node.

**What it does not prove:** If the recipient's node is compromised, an attacker could send a valid receipt without the human seeing the message, or vice versa. This is an inherent limitation of any digital messaging system.

---

## Limitations

**No automatic NAT traversal.** malphas intentionally does not implement STUN, ICE, UDP hole punching, or automatic NAT traversal. These mechanisms improve connectivity but require external coordination infrastructure and introduce additional metadata exposure. malphas prioritizes explicit peer connectivity and Tor hidden services over automatic reachability.

**Bootstrap:** The first peer must be found out-of-band. There is no public directory, no DHT accessible from the internet, and no rendezvous server. The bootstrap channel (how you exchange the peer_id and keys with the first contact) is the weakest link in the privacy chain — use Signal, in person, or any channel with better privacy than what you are trying to protect.

**Circuit with few peers:** Onion routing requires at least 2 peers to build a 2-hop circuit, 3 for a full 3-hop circuit. With only 2 peers connected, malphas degrades to a single-hop direct encrypted connection. The content remains protected but there is no sender anonymity.

**Traffic correlation:** A sophisticated adversary monitoring network traffic at both endpoints simultaneously can correlate message timing even through Tor and cover traffic, given enough observations. This is a fundamental limitation of low-latency anonymous communication networks.

**No forward secrecy per message:** Session keys are established once per connection and used for all messages in that session. If a session key is compromised (e.g., via memory dump), all messages from that session are at risk. The Double Ratchet protocol (used by Signal) would provide per-message forward secrecy but is not yet implemented.

**No deniable authentication:** Messages are signed with Ed25519. If message content is obtained by an adversary (e.g., via device compromise), the signature mathematically proves authorship. Signal's deniable authentication (via MAC instead of asymmetric signatures) would prevent this but is not yet implemented.

**Tor self-rendezvous:** A single Tor process cannot connect to its own hidden service, and two Tor processes sharing the same public IP will also fail the rendezvous. Testing hidden service message delivery requires two machines on different networks (different public IPs). This is a Tor architectural limitation, not a malphas issue.

**Memory wiping in Python:** Python strings and bytes objects are immutable. Overwriting a variable only changes the reference — the original bytes may remain in the heap until garbage collection. The passphrase and seed material in RAM cannot be reliably zeroed in pure Python. This is an inherent limitation of the runtime, documented here for completeness.

**Windows:** The core messaging functionality works on Windows. Tor hidden service support and some signal handling edge cases may behave differently — testing on a production Windows environment is recommended before relying on it.

---

## Testing

```bash
# All tests (excludes Tor and slow tests)
pytest tests/ -m "not tor and not slow"

# Security tests only
pytest tests/test_security_*.py -v

# End-to-end integration tests (real TCP, real nodes)
pytest tests/test_integration_e2e.py -v

# API and WebSocket tests
pytest tests/test_api.py -v

# CLI command tests
pytest tests/test_cli.py -v

# Transport tests (includes mocked Tor)
pytest tests/test_transport.py -m "not tor" -v

# Tor tests (requires Tor running on localhost with ControlPort 9051)
sudo systemctl start tor
pytest tests/test_transport.py::TestTorIntegration -v

# Tor hidden service E2E (requires Tor, slow — real .onion delivery)
pytest tests/test_tor_e2e.py -v
```

**Test suite summary:**

| File | Coverage | Tests |
|---|---|---|
| `test_security_identity.py` | Argon2, key derivation, sign/verify | 19 |
| `test_security_crypto.py` | ChaCha20, ECDH, HKDF, session keys | 24 |
| `test_security_onion.py` | Onion isolation, tamper detection, ephemeral keys | 15 |
| `test_security_addressbook.py` | Encryption, no plaintext leak, atomic write, wipe | 18 |
| `test_security_obfuscation.py` | Padding, cover traffic, read receipts | 22 |
| `test_security_argon2_panic.py` | Argon2 properties, /panic behavior | 18 |
| `test_functional_components.py` | Routing table, discovery, message store | 27 |
| `test_functional_node.py` | Node lifecycle, authenticated handshake, connections | 19 |
| `test_integration_e2e.py` | End-to-end delivery, receipts, relay, wire integrity | 18 |
| `test_transport.py` | SOCKS5, DirectTransport, TorTransport, .onion derivation | 28 |
| `test_api.py` | REST endpoints, WebSocket push, input validation | 91 |
| `test_cli.py` | CLI command parsing, interactive flow, callbacks | 115 |
| `test_tor_e2e.py` | Hidden service registration, .onion message delivery | 5 |

**What passing tests guarantee:**

- Message content is encrypted end-to-end and cannot be read by relays
- Tampered onion packets are silently dropped at every hop
- The address book file contains no plaintext when inspected at the byte level
- Wrong passphrase is rejected by the address book decryption
- Handshake is authenticated — invalid Ed25519 signatures are rejected
- Messages from unknown senders are silently dropped
- `/panic` clears all in-memory state before exit
- Argon2id is significantly slower than the previous SHA1 derivation (verified by timing assertion)
- Cover packets are not delivered as messages
- Read receipts from wrong keys are rejected
- REST API validates all inputs and returns correct responses
- CLI commands parse correctly and produce expected state changes
- Tor hidden service registration succeeds with the node's Ed25519 key

---

## Development

**Project structure:**

```
malphas/
├── src/malphas/
│   ├── identity.py      passphrase → keypairs (Argon2id + HKDF)
│   ├── crypto.py        X25519, ChaCha20-Poly1305, HKDF primitives
│   ├── onion.py         layered onion packet construction and peeling
│   ├── transport.py     DirectTransport, TorTransport, SOCKS5 client, .onion derivation
│   ├── node.py          main async node, handshake, routing, panic
│   ├── discovery.py     Kademlia routing table, peer exchange
│   ├── memory.py        in-memory message store with TTL
│   ├── receipts.py      Ed25519 read receipt challenge-response
│   ├── obfuscation.py   padding, cover traffic engine
│   ├── addressbook.py   encrypted persistent contact storage
│   ├── cli_ui.py        interactive terminal interface
│   ├── api.py           FastAPI + WebSocket (web mode)
│   ├── splash.py        ASCII splash screen
│   └── __main__.py      CLI entry point, argument parsing
├── frontend/pwa/
│   ├── index.html       neumorphic PWA (dark/light theme)
│   └── manifest.json    PWA manifest
└── tests/               420 tests across 13 files
```

**Adding a new transport:** Subclass `BaseTransport` in `transport.py` and implement `connect()`, `start_server()`, and `stop()`. Pass an instance to `MalphasNode(transport=...)`.

**Protocol versioning:** HKDF info strings include a version suffix (`-v1`). Breaking protocol changes should increment the version to prevent cross-version interoperability confusion.

---

## Disclaimer

malphas is provided for educational and research purposes. It is a demonstration of applied cryptography and privacy engineering principles.

Use it only on networks and systems you own or have explicit permission to access. The authors assume no responsibility for misuse. You are solely responsible for your actions and for compliance with applicable laws in your jurisdiction.

malphas is not audited. Do not use it in situations where the cost of a security failure is unacceptable without first conducting a professional security audit.

---

*malphas — built by Cristian D'Arrigo*
