# malphas

```
                                              ....---------....
                                     ...--+########+++++++########+--...
                                ..--+###++-------++++++++++++------++###+--..
                             .-+###+---++--.      .+##.  .##-.   .--++---+###+-.
                          .-###+.-++.               +##..###            -++-.-###-.
                        -###--#+.                  .#.+##.##                .+#--###-
                     .+##--#-.                    ###- ..###+                  .-#--##+.
                   -##+-+-.                              ...                     ..-+-+##-
                 -+#--+-.                 .--+++---.......---+++--.                 .-+--#+-
               -+#+-+-.              .-+---..                   ..---+-.              .-+--#+-
             .+#+---.            .-+--.                               .----.            .-+-+#+.
           .-##----++-.        .---.                                     .---.            .-+-##-.
          .+#+---++---.     .-+-.                                           .-+-.           .--+#+.
         .+#---..+++###+. .-+.                                                 -+-.        ..----#+.
       .-#+---     ...-+.-+.                                                     .+-....--+#++.-+-+#-.
       -#+--.      -##-.+-  +##########-.                                          -#.+#-.-#+-  .+-+#-
      -#+-+.         .++.    .+######+.                                             .--...-+-    .+-+#-
     .##-+.         .+.         -##+                                                  .#.##+.     .+-+#.
    .##-+.         .+.          .+#.               ...   ...                           .+--.       .+-##.
   .+#---         -+.           .+#.             -###########-                          .+.         ---#+.
   -#+--         .+.            .+#.            .##.  +#.  .#+                           .+.         --+#-
  .##-+.        .+-          ..--##--------------##+-+###--+#+-----------------.          -+.        .+-##.
  -#+--         --.     .-+###+--##-------------------+#---------------------+#-          .--         --+#-
  +#-+.        .-.    .+##-.    .+#.                  +#.                    -#-   ----.   .-.        .+-#+.
 .##-+         --   .-#+..      .+#.      .--..       +#.       .--..        -#-  -#++#+    --         +-##.
 -#+--        .--  .##-.        .+#.    .-##+##-      +#.      -##+##-       -#-  -#++#+    --.        --+#-
 -#-+.        --. .##.          .+#.    .+#- +#-      +#.     .-#- -#-.      -#-   .##.   ..---        .+-#-.
 +#-+.        --..+#.           .+#.     -####+.      +#.      .####+.       -#-   .##.   -#---        .+-#+.
 +#.#         -- .#+.           .+#.     .+++#-.      +#.      .+#+#+.       -#-   .##.  .+#+--         +-#+.
 +#.#         -- -#-            .+#.    .-#-.+#-      +#.      -#+ -#-       -##############+--         +.##.
 +#.#         -- -#-.           .+#.    -#+. .#+.     +#.     .#+. .++.      -#-....##-...+#+--         +-#+.
 +#-+        .-- -#+.           .+#.   .+#-   +#-     +#.    .-#-   -#-.     -#-   .##.   .++--        .+-#+.
 -#-+.     .-++-..+#.           .+#.   -#-    .+#.    +#.    -#+.   .+#-     -#-   .##.    .-----    ...+-#-.
 -#+--   .+###--- .##.          .+#..-+#+.     -#++-. +#. .-+##-     -##+-.  -#-   +##+-    ---#######.--+#-
 .##-+.-++---..--  .##-.        .+#-##--++.   -#+--#+.+#..+#--+#-   -#+--#+. -#-  -#-.##.   ---++---++.+-+#.
  +#-+...-+++++--.  .+#+.       .+#-#+--++.   -#+--##.+#..##--+#-   -#+--##. -#-  .####-   .-.-#-.    .+-#+.
  -#+--      .-.--.   .+##-.    .+#..++++-     -+++-. +#. .++++-     -+++-.  -#-          .-- -#+.    --+#-
  .##-+.        .+-     .-+####++##-------------------##---------------------+#-          -+.        .+-##.
   -#+--         .-.         ...-##-------------------+#-----------------------.         .+.         --+#-
   .+#---         --.           .+#.                  +#.                               .+.         ---#+.
    .##-+.         .+.          .+#.                  +#.                              .+.         .+-##.
     .#+-+.         .+.         .+#.                  +#.                             .+.         .+-+#-
     .-#+-+.         .+-.       .+#.            #+.   +#.   .#+                     .--.         .--+#-
      .-#+-+.          .+.      .##-            ##+-..+#...-##+                    -+.          .--+#-.
       .-#+---          .-+.   .-##+.           ###+++##+++###+                  .+-.          ---+#-
         .##---.          .-+..#######+.        +#.   +#.   .#+                .+-.          .---##-
          .+#+--.           .-+-------.         --.  -##+-  .--             .-+-.           .--+#+.
           .-#+---.            -+--.                ##---#+              .--+--.          .-+-+#-.
             .+#+-+-.           .--+--.            .#+  .##           .--+-.-#+.        .-+-+#+.
               -##--+-.         -+-..--+--...       +#####-     ...-++-.     -#+.     .-+--##-
                 -##--+-.      .+..-##+-  .-++++---...--..---++++-.         -#-##-. .-+--##-.
                   -##+-+-.  .+#.+##.                                       ++-+#+.-+-+##-
                     .###--#--#-.+#-                                        .--.-#-.###.
                       .-###--#+.-+.                                        .+#--###-.
                          .-###-.-++-                                   .++---###-.
                             .-+##++---++--.                     .--++---++##+-.
                                ..-+####++------+++++++++++++------++####+-..
                                     ..---+######+++++++++++######+---..
                                             ....-----------....
```

**Privacy-first P2P messenger with onion routing and Tor hidden service support.**

No servers. No accounts. No logs. No traces.

---

## Table of Contents

1. [What is malphas](#what-is-malphas)
2. [Design Principles](#design-principles)
3. [Threat Model](#threat-model)
4. [Cryptographic Stack](#cryptographic-stack)
5. [Architecture](#architecture)
6. [Installation](#installation)
7. [Quickstart](#quickstart)
8. [CLI Reference](#cli-reference)
9. [How the Network Works](#how-the-network-works)
10. [Tor Hidden Services](#tor-hidden-services)
11. [Identity System](#identity-system)
12. [Invite System](#invite-system)
13. [Address Book and Key Pinning](#address-book-and-key-pinning)
14. [Security Features](#security-features)
15. [Traffic Obfuscation](#traffic-obfuscation)
16. [Read Receipts](#read-receipts)
17. [Resilience](#resilience)
18. [Limitations](#limitations)
19. [Testing](#testing)
20. [Development](#development)
21. [Disclaimer](#disclaimer)

---

## What is malphas

malphas is a peer-to-peer encrypted messaging system. It has no central servers, no user accounts, no message storage on any infrastructure you do not control, and no logging of any kind.

Messages are encrypted end-to-end with modern cryptographic primitives, authenticated with HMAC for deniability, routed through an application-layer onion network, and optionally transported over Tor hidden services. The entire message history exists only in RAM for the duration of a session and is wiped when the process exits.

The name comes from malphas — a demon in demonology described as a builder of fortresses and a carrier of secrets. The metaphor is deliberate.

---

## Design Principles

Every design decision in malphas follows from a small set of principles, stated here so the rationale behind specific choices is clear throughout the document.

**No trust in infrastructure.** There are no servers, no relays you don't control, no DNS, no cloud. Every component runs on the user's machine. The only external dependency is Tor, and that is optional.

**Manual discovery by design.** Peers are never found automatically via public directories or DHTs. Every peer is added by the user through explicit key exchange (`/import` or `/add`). Automatic peer discovery leaks social graph information — who communicates with whom — and malphas treats social graph as sensitive metadata.

**Zero disk writes during operation.** The only file written to disk is the encrypted address book (and the encrypted key pin store), both on explicit user action. No message logs, no connection logs, no routing table persistence, no debug output. RAM is the only storage medium for ephemeral data.

**Deniability over non-repudiation.** Messages are authenticated with HMAC-SHA256 (symmetric), not Ed25519 (asymmetric). Both peers can produce the same HMAC tag, so neither can mathematically prove the other authored a message. If a device is seized, the messages in RAM (if any survive) cannot be cryptographically attributed to a specific author. Read receipts are the intentional exception — they use Ed25519 because proving delivery is the point.

**Fail closed.** Invalid signatures, tampered packets, unknown senders, key mismatches — all are silently dropped. No error messages, no retries, no fallback. An attacker gains no information from a failed attack.

---

## Threat Model

malphas is designed to protect against the following adversaries:

**Protected against:**

- Passive network observers (ISPs, network administrators, traffic loggers) — they see encrypted traffic of uniform size, indistinguishable from cover traffic
- Service providers and infrastructure operators — there are no servers to subpoena
- Remote forensics — no data is written to disk except the encrypted address book and key pin store
- Man-in-the-middle attacks — all connections are authenticated via Ed25519 signatures on ephemeral keys, and keys are pinned on first contact (TOFU)
- Impersonation after first contact — key pinning detects if a peer's Ed25519 key changes, which indicates either a passphrase change or an attacker
- Brute force attacks on the address book — Argon2id makes offline dictionary attacks computationally prohibitive (64MB RAM + ~200ms per attempt)
- Proof of authorship — deniable authentication (HMAC) prevents cryptographic attribution of messages to a specific sender

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
| Password hashing | Argon2id | Passphrase to 64-byte master seed (64MB, ~200ms) |
| Key derivation | HKDF-SHA256 | Seed to address book key, session to HMAC key |
| Key exchange | X25519 (ECDH) | Ephemeral session key establishment |
| Authenticated encryption | ChaCha20-Poly1305 | All message and storage encryption |
| Signing | Ed25519 | Handshake authentication, read receipts, invites, Tor identity |
| Message authentication | HMAC-SHA256 | Deniable message authentication (derived from session key) |
| Onion layer | X25519 + ChaCha20-Poly1305 | Per-hop encryption in circuit |

**Key properties:**

- All session keys are ephemeral — derived fresh from X25519 ECDH for each connection
- Nonces are 12-byte random values generated per encryption operation — no nonce reuse possible
- Ed25519 is the same key used for Tor v3 hidden service identity, making the `.onion` address stable and derived from the passphrase
- The HMAC key for deniable message authentication is derived from the session key via HKDF with a dedicated context string (`malphas-hmac-v1`), making it cryptographically independent from the encryption key
- The address book key is derived from the Argon2id seed via HKDF with a context string different from the identity derivation — both derived from the same seed but cryptographically independent

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         APPLICATION                             │
│  CLI (cli_ui.py)                                                │
│  prompt_toolkit + rich    FastAPI + WebSocket (api.py)           │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                           NODE                                  │
│  MalphasNode (node.py)                                          │
│  ├── MessageStore     in-memory, TTL-based, zero disk           │
│  ├── MessageQueue     in-memory outbox for offline peers        │
│  ├── ReceiptTracker   Ed25519 challenge-response                │
│  ├── PeerDiscovery    Kademlia-inspired routing table           │
│  ├── PinStore         TOFU key pinning, encrypted on disk       │
│  ├── CoverTraffic     randomized dummy packets                  │
│  └── AutoReconnect    exponential backoff for book peers        │
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

### Automated setup (Linux, recommended)

The setup script installs Tor, configures ControlPort, sets permissions, and installs malphas:

```bash
git clone https://github.com/CristianDArrigo/malphas.git
cd malphas
sudo bash scripts/setup.sh
```

### Manual setup

```bash
git clone https://github.com/CristianDArrigo/malphas.git
cd malphas
pip install -e .
```

**With Tor support** (for hidden services):

```bash
# Linux
sudo apt install tor
# Enable ControlPort in /etc/tor/torrc:
#   ControlPort 9051
#   CookieAuthentication 1
sudo systemctl restart tor
sudo chmod o+r /run/tor/control.authcookie

# macOS
brew install tor
# Enable ControlPort in /usr/local/etc/tor/torrc
brew services restart tor
```

**Note:** launching with `--tor` requires root or `debian-tor` group membership, because malphas writes hidden service key files to `/var/lib/tor/`. The setup script handles this automatically.

**Dependencies installed automatically:**

- `cryptography` — all cryptographic primitives
- `argon2-cffi` — password hashing
- `prompt_toolkit` — CLI input with readline, tab completion, history
- `rich` — CLI output formatting (panels, tables, colors)
- `fastapi` + `uvicorn` — web API (optional, web mode only)
- `stem` — Tor control protocol (optional, Tor mode only)
- `zeroconf` — mDNS peer discovery on LAN (optional)

---

## Quickstart

### Basic (LAN or public IP)

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

### Connecting via invite (recommended)

The invite system is the simplest way to connect two peers. An invite is a signed `malphas://` URL containing all public credentials needed to establish a connection.

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

/chat alice
hello alice
```

If Alice also wants Bob's credentials (for reconnecting if the session drops), Bob runs `/export` and sends his URL back.

### Two peers over Tor

Step-by-step for two people on different networks who want to chat privately:

**Both peers** install and launch:

```bash
sudo apt install tor                    # install Tor
# Edit /etc/tor/torrc: uncomment ControlPort 9051 and CookieAuthentication 1
sudo systemctl restart tor              # restart with control port

git clone https://github.com/CristianDArrigo/malphas.git
cd malphas && pip install -e .

malphas --tor --port 7777               # launch with Tor
# enter a strong passphrase
```

**Peer A** runs `/export` and sends the `malphas://...` URL to Peer B.

**Peer B** runs `/import malphas://...`, confirms, and is connected via Peer A's `.onion` address. Messages are end-to-end encrypted and routed through Tor. Neither peer's IP is exposed.

For bidirectional reachability (so A can reconnect to B if the session drops), B also runs `/export` and sends the URL to A.

### Multiple peers and onion routing

Each node can connect to multiple peers simultaneously. With 3+ peers, malphas builds multi-hop onion circuits — messages relay through intermediate peers, each seeing only adjacent hops:

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

The relay peers see encrypted onion layers — they know the previous hop and the next hop, but not the sender, the destination, or the content.

### Connecting via /add (manual key exchange)

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

---

## CLI Reference

The CLI uses prompt_toolkit for readline input (arrow keys, history, tab completion) and rich for formatted output. The prompt is fixed at the bottom of the terminal; messages and notifications scroll above it without interrupting input.

```
/id                        show peer_id, public keys, port, .onion
/peers                     list peers currently in the routing table
/book                      list address book contacts
/book add <label>          save the active conversation peer to the address book
/book rm <label>           remove a contact from the address book
/add <host> <port>         connect to a peer (prompts for their keys)
/chat <peer_id|label>      open a conversation; auto-connects from address book
                           accepts partial peer_id (min 4 hex chars) for quick match
/history                   show message history for the active conversation
/export                    generate a signed invite URL to share your credentials
/import <url>              import a peer from an invite URL and connect
/trust <peer_id|label>     reset the pinned key for a peer (after passphrase change)
/github                    open the project page in the browser
/wipe                      wipe all messages and queued messages from memory
/panic                     EMERGENCY: wipe everything and exit immediately
/help                      show this list
<text>                     send a message to the active conversation
```

**Tab completion:**
- First level: all commands
- `/chat <tab>`: address book labels and connected peer IDs
- `/book rm <tab>`: address book labels

**Status bar** (bottom of terminal): peer count, active conversation, pending receipts, Tor status.

---

## How the Network Works

malphas is a fully peer-to-peer network. There are no servers, no directory nodes, no central infrastructure of any kind.

**Routing table.** Each node maintains a Kademlia-inspired in-memory routing table of known peers, indexed by XOR distance from the node's own peer_id. The table is empty at startup and populated only through manual peer addition (`/add`, `/import`) or address book auto-connect. There is no public directory, no DHT, no bootstrap server.

**Handshake.** When two nodes connect, they perform a mutually authenticated key exchange:

1. Each peer generates an ephemeral X25519 keypair
2. Each peer signs its ephemeral public key with its Ed25519 identity key
3. The other peer verifies the signature — this prevents man-in-the-middle attacks
4. The peer's Ed25519 key is checked against the key pin store (TOFU) — a mismatch rejects the connection
5. X25519 ECDH derives a shared secret, which HKDF expands into a session key (ChaCha20-Poly1305) and an HMAC key (HMAC-SHA256)

The session key provides confidentiality and integrity for the transport layer. The HMAC key provides deniable authentication for the application layer (messages). Neither the session key nor the HMAC key can be derived from the identity keys — they are forward-secret.

**Circuit.** A circuit is the ordered list of peers a message traverses. Circuits are selected randomly from known peers at send time. With 3+ peers, a typical circuit is `sender → relay → destination`. Each peer sees only its adjacent hops.

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

Each relay decrypts its layer, reads the next hop peer_id, and forwards the inner payload. The destination decrypts the final layer and gets the authenticated plaintext. No relay can decrypt more than its own layer.

### Connection lifecycle: what both peers see

Understanding what happens on both sides of a connection is important for reasoning about the system's behavior.

**Alice publishes her invite. Bob imports it.**

```
Alice                                          Bob
  |                                              |
  |  /export                                     |
  |  → generates malphas://... URL               |
  |  → sends URL to Bob (Signal, email, etc)     |
  |                                              |
  |                         /import malphas://...|
  |                         Bob's node connects  |
  |                         to Alice's host:port |
  |                         (or .onion via Tor)  |
  |                                              |
  |  ←──────── TCP connection established ──────→|
  |                                              |
  |  ←───────── mutual handshake ───────────────→|
  |  both peers exchange:                        |
  |    peer_id, x25519_pub, ed25519_pub,         |
  |    ephemeral key + Ed25519 signature         |
  |                                              |
  |  Alice's node adds Bob                       |
  |  to routing table (automatic)                |
  |                         Bob's node adds Alice|
  |                         to routing table     |
  |                                              |
  |  ←────── both can now send messages ────────→|
```

After the handshake, **both peers know each other's credentials** and can send messages in both directions over the same TCP connection. The handshake is symmetric in knowledge — neither peer needs to have the other's invite beforehand.

**What each peer has after the connection:**

| | Alice (was imported) | Bob (did the import) |
|---|---|---|
| Peer in routing table | Yes (automatic from handshake) | Yes (automatic from handshake) |
| Peer in address book | No (unless Bob does `/book add`) | Yes (if he chose to save during `/import`) |
| Can send messages | Yes | Yes |
| Can reconnect after drop | Only if Bob is in her book | Yes (auto-reconnect from book) |

**The asymmetry is in persistence, not in capability.** During the session, both peers are equal. The difference emerges when the connection drops:

- **Bob** saved Alice in his address book during `/import`. When he restarts malphas, auto-connect tries to reach Alice. If she's online, they reconnect automatically.
- **Alice** never received Bob's credentials in a persistent form. When the connection drops, Bob disappears from her routing table (which is in-memory only). She cannot reconnect to Bob unless he connects to her again.

**To make the relationship fully symmetric**, Bob sends his `/export` URL to Alice during the conversation, and Alice does `/import`. Now both have each other in their address books, and either can reconnect independently.

**For the journalist-source scenario**, this asymmetry is a feature: the journalist publishes her invite, the source connects when they choose to. The journalist never needs to know how to reach the source — the source is always the initiator. This protects the source's identity even from the journalist's address book.

---

## Tor Hidden Services

When launched with `--tor`, malphas registers a Tor v3 hidden service using the node's Ed25519 identity key. The `.onion` address is derived from the Ed25519 public key using the standard Tor v3 algorithm:

```
onion = base32( ed25519_pub(32) || SHA3-256(".onion checksum" || pub || version)[0:2] || 0x03 ) + ".onion"
```

This means:
- The `.onion` address is deterministic — same passphrase always produces the same address
- The `.onion` address is stable across restarts — it is mathematically derived from the key
- No registration required — the address exists as soon as the key exists
- The `.onion` address serves as the node's permanent identifier

**Outbound connections** route through the Tor SOCKS5 proxy (default `127.0.0.1:9050`). The SOCKS5 client is implemented from scratch using asyncio.

**Inbound connections** arrive via Tor's introduction/rendezvous mechanism (6-hop circuit). Neither peer's IP is exposed.

**NAT traversal.** Tor hidden services work behind any NAT without port forwarding. This is the primary reason for Tor integration — it eliminates the requirement for a publicly reachable IP.

**Defense in depth.** When using Tor, malphas adds its own onion routing layer on top of Tor's. An adversary who compromises the Tor circuit still cannot read malphas-level content, because the application layer uses independent keys.

### Hidden service implementation

malphas uses persistent hidden services (files on disk in `/var/lib/tor/malphas_hs/`) rather than ephemeral hidden services via stem's `create_ephemeral_hidden_service`.

This is a deliberate choice driven by extensive testing. The ephemeral approach (ADD_ONION via the Tor control protocol) accepts custom Ed25519 keys without error but silently fails to publish the descriptor on multiple Tor versions (tested on 0.4.2.7, 0.4.6.10, 0.4.8.16). The hidden service appears registered locally but is never reachable from the Tor network. This failure is silent — no error is returned by stem or by Tor's control protocol.

The persistent approach writes the key files directly to disk in the format Tor expects:

```
/var/lib/tor/malphas_hs/
    hs_ed25519_secret_key   — header(32) + expanded_private_key(64) = 96 bytes
    hs_ed25519_public_key   — header(32) + public_key(32) = 64 bytes
    hostname                — the .onion address
```

**Critical detail: the Ed25519 expanded key.** Tor does not use the raw 32-byte Ed25519 seed. It requires the 64-byte expanded private key, computed as `SHA-512(seed)` with clamping (clear bits 0-2 of byte 0, clear bit 7 and set bit 6 of byte 31). Writing the raw seed instead of the expanded key causes Tor to silently generate a different key pair, producing a different `.onion` address than expected — or failing to publish the descriptor entirely. This is not documented in Tor's specification and was discovered through binary analysis of working vs non-working key files.

**Permissions.** Tor runs as user `debian-tor` (or `tor` on some distributions) and requires strict ownership: the hidden service directory must be owned by the Tor user with mode 700, and key files must be mode 600. malphas sets these permissions automatically, but launching with `--tor` requires root or membership in the `debian-tor` group.

**Setup script.** The included `scripts/setup.sh` automates Tor installation, ControlPort configuration, permission setup, and malphas installation:

```bash
sudo bash scripts/setup.sh
```

### Verified behavior

The Tor hidden service integration has been tested end-to-end between a local machine (Tor 0.4.8.16, Ubuntu 25.04) and an Oracle Cloud VPS (Tor 0.4.6.10, Ubuntu 22.04) on different public IP addresses. Messages sent from the local machine via the VPS's `.onion` address were received and decrypted successfully.

Key findings from testing:
- Ephemeral hidden services (ADD_ONION with custom key) do not work reliably across Tor versions
- Persistent hidden services with correctly formatted expanded keys work on the first attempt
- The descriptor typically publishes within 30-60 seconds of Tor reload
- Tor self-rendezvous (connecting to your own .onion from the same machine or NAT) fails on all tested configurations — this is a Tor architectural limitation, not a malphas issue
- Docker containers sharing the same host cannot reach each other's hidden services for the same reason

---

## Identity System

Identity in malphas is entirely derived from a passphrase. Nothing is stored on disk except the encrypted address book and key pin store.

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
    └─── HKDF(info="addressbook-encryption-key") ──► 32-byte ChaCha20 key (address book + pin store)
```

**peer_id** is the SHA1 of the Ed25519 public key, expressed as a 40-character lowercase hex string. It is the primary identifier shared with other peers.

**Passphrase security.** Argon2id requires 64MB of RAM and approximately 200ms per derivation attempt. An attacker attempting to brute-force the passphrase from the encrypted address book file faces this cost for every attempt, making dictionary attacks against common passphrases computationally expensive and attacks against strong passphrases effectively impossible.

**Passphrase choice.** Use at least four random unrelated words or a phrase of similar entropy. The passphrase is never transmitted, never stored, and never logged. The same passphrase always produces the same identity, the same keys, and the same `.onion` address.

---

## Invite System

The invite system provides a secure, convenient way to share credentials between peers.

**`/export`** generates a `malphas://` URL containing:

```json
{
  "type": "invite",
  "v": 1,
  "peer_id": "a0f8e7d8...",
  "x25519_pub": "3f7a...",
  "ed25519_pub": "8b2c...",
  "host": "192.168.1.10",
  "port": 7777,
  "onion": "abc...xyz.onion"
}
```

The JSON is signed with the node's Ed25519 private key and encoded as `malphas://base64url(sig(64) + json)`. The signature proves the invite was generated by the holder of the Ed25519 key — it has not been tampered with in transit.

When running with `--tor`, the invite includes the `.onion` address and `/import` will connect via Tor automatically. The `host:port` remains as a fallback for direct LAN connections.

**`/import malphas://...`** decodes the URL, verifies the Ed25519 signature, displays a summary, and prompts for confirmation before connecting. If the peer is reachable, the user is offered the option to save to the address book.

**Security note.** The invite contains only public keys — it is safe to transmit over any channel. However, the channel used determines who learns that two peers intend to communicate. Use a channel with appropriate privacy for your threat model.

---

## Address Book and Key Pinning

### Address Book

The address book is stored encrypted on disk at `~/.malphas/book` (configurable via `--book`).

**Encryption:** ChaCha20-Poly1305 with the address book key derived from the passphrase via HKDF. The key never appears on disk.

**On-disk format:**

```
nonce(12 bytes) || ChaCha20-Poly1305(key, padded_json)
```

The file contains no plaintext fields, no headers, and no identifiable structure. Without the correct passphrase it is indistinguishable from random noise. The padding aligns the plaintext to 4096-byte blocks using cryptographically random bytes before encryption, preventing the file size from revealing the exact number of contacts.

**Atomic writes.** The address book is written atomically via a `.tmp` file renamed to the final path, preventing partial writes from corrupting the stored data.

### Key Pinning (Trust On First Use)

When a peer connects for the first time, malphas pins their Ed25519 public key in an encrypted store (`~/.malphas/pins`). On subsequent connections, the key is verified against the pin. A mismatch triggers a warning and the connection is rejected:

```
!!! KEY MISMATCH for alice !!!
expected 8b2c1a3f... got 9d4e5f60...
connection rejected. use /trust alice to reset
```

This detects two scenarios:
1. The peer legitimately changed their passphrase (and therefore their keys)
2. An attacker is impersonating the peer

If the peer changed their passphrase intentionally, use `/trust <peer_id|label>` to clear the pin. The next connection will re-pin to the new key.

The pin store is encrypted with the same key as the address book and follows the same zero-plaintext-on-disk principle. Pins are wiped from memory on `/panic`.

---

## Security Features

### Deniable Authentication

Messages are authenticated with HMAC-SHA256 using a key derived from the session key via HKDF. Both peers share the same HMAC key (it is symmetric), so both can produce identical authentication tags. An adversary who seizes a device cannot cryptographically prove which peer authored a specific message — both peers are equally capable of having produced it.

This is a deliberate design choice modeled after Signal's approach to authentication. Ed25519 signatures (asymmetric) would provide non-repudiation — mathematical proof of authorship — which is undesirable in a privacy-focused messenger. If a device is compromised, message content may be exposed, but the cryptographic evidence does not identify the author.

**Exception: read receipts.** Read receipts use Ed25519 signatures intentionally. The purpose of a receipt is to prove that a specific peer received the message. Non-repudiation is the feature, not the bug. The inner Ed25519 signature in the receipt proves the recipient's key processed the message; the outer HMAC wrapping provides deniability at the transport level.

### /panic — Emergency Wipe

`/panic` immediately clears all sensitive state from memory and terminates the process. No confirmation. Execution order:

1. Active conversation reference cleared
2. Message store wiped
3. Routing table cleared
4. Pending read receipts cleared
5. Key pin store wiped from memory
6. Message queue (outbox) cleared
7. All reconnect tasks cancelled
8. All active TCP connections closed
9. Message callbacks cleared
10. Address book cleared from memory (file on disk untouched)
11. `gc.collect()` — forces garbage collection
12. `sys.exit(0)` — hard exit

The address book and pin store files on disk survive `/panic` intentionally. They are encrypted — without the passphrase they are indistinguishable from random noise. Deleting them would permanently destroy the user's contacts.

### Argon2id Password Hashing

The passphrase is never used directly as a key. It is processed through Argon2id with parameters selected to make offline brute force expensive:

- `time_cost = 3` — three passes over the memory
- `memory_cost = 65536` — 64MB of RAM required per attempt
- `parallelism = 4` — four parallel threads

An attacker with a dedicated GPU farm attempting to brute force a four-word passphrase would require years of computation at these parameters.

### Authenticated Handshake

Every connection begins with a mutually authenticated handshake (described in [How the Network Works](#how-the-network-works)). The handshake combines three layers of protection:

1. **Ed25519 signature** on the ephemeral key prevents MITM attacks
2. **Key pinning (TOFU)** detects key changes after first contact
3. **Ephemeral ECDH** provides forward secrecy — compromising identity keys does not expose past session keys

### Message Sender Verification

All incoming messages must be authenticated by a peer known to the recipient's routing table. Messages claiming to be from an unknown `peer_id` are silently dropped. This prevents message injection attacks.

### No-Log Policy

malphas writes nothing to disk during operation except the encrypted address book and pin store on explicit save. Specifically:

- No message logs
- No connection logs
- No routing table persistence
- No debug output to files
- The Python logging system uses `NullHandler` throughout
- The FastAPI web API disables access logs (`access_log=False`)
- Input history (prompt_toolkit) is in-memory only — not persisted

---

## Traffic Obfuscation

### Message Padding

All message payloads — real messages, read receipts, and cover traffic — are padded to the nearest multiple of 512 bytes before encryption. The padding bytes are cryptographically random, making them indistinguishable from content.

```
padded = length_prefix(4) || plaintext || random_bytes(pad_to_512_boundary)
```

A 1-byte message and a 511-byte message produce identical ciphertext sizes.

### Cover Traffic

malphas sends encrypted dummy packets to random known peers at randomized intervals (10-40 seconds, uniformly distributed). Cover packets are indistinguishable from real messages on the wire — same format, same padding, same size. The recipient identifies them via an internal flag and silently discards them.

---

## Read Receipts

When a message is delivered, the recipient sends a cryptographic read receipt back to the sender.

```
Sender generates: msg_id (random 32 hex chars) + nonce (16 random bytes)
Sender embeds both in the message payload

Recipient decrypts, reads msg_id and nonce
Recipient computes: sign_Ed25519(private_key, msg_id || nonce || "malphas-read-receipt-v1")
Recipient sends signed receipt back through a reverse circuit

Sender verifies Ed25519 signature against recipient's known public key
If valid: receipt confirmed (checkmark in CLI)
If timeout (30s): circuit issue or peer offline
```

**What the receipt proves:** that the holder of the recipient's Ed25519 private key processed the message.

**What it does not prove:** that the human read it, or that the node was not compromised.

---

## Resilience

### Automatic Reconnect

When a TCP connection to a peer drops (network error, Tor circuit rebuild, peer restart), malphas automatically attempts to reconnect if the peer is in the address book. The reconnect uses exponential backoff starting at 5 seconds, doubling each attempt up to a 5-minute cap. Reconnect tasks are cancelled on `/panic`.

This is critical for Tor usage, where circuits are periodically rebuilt by the Tor daemon. Without auto-reconnect, every circuit rebuild would require manual reconnection.

### Message Queuing

If a message is sent to a peer that is currently offline but known to the routing table, the message is queued in RAM. When the peer reconnects (via auto-reconnect or manual `/import`), the queue is flushed automatically — all pending messages are delivered in order.

The queue lives entirely in RAM (consistent with the zero-disk-write policy). It is limited to 100 messages per peer to prevent unbounded memory growth. `/panic` and `/wipe` clear all queues.

Messages are encrypted at send time (after reconnection), not at queue time. This ensures they use the current session key, which may differ from the key of the previous session.

---

## Limitations

**No forward secrecy per message.** Session keys are established once per connection and used for all messages in that session. If a session key is compromised (e.g., via memory dump), all messages from that session are at risk. The Double Ratchet protocol (used by Signal) would provide per-message forward secrecy but is not yet implemented.

**No automatic NAT traversal.** malphas does not implement STUN, ICE, UDP hole punching, or UPnP. These mechanisms require external infrastructure and expose metadata. Use Tor hidden services for connectivity behind NAT.

**Bootstrap.** The first peer must be found out-of-band. There is no public directory. The bootstrap channel (how you exchange the invite URL with the first contact) is the weakest link in the privacy chain — use a channel with appropriate privacy for your threat model.

**Circuit with few peers.** Onion routing requires at least 2 peers for a 2-hop circuit, 3 for full 3-hop. With only 2 peers, malphas uses a direct encrypted connection. Content is protected but there is no sender anonymity.

**Traffic correlation.** A sophisticated adversary monitoring both endpoints simultaneously can correlate message timing even through Tor and cover traffic, given enough observations. This is a fundamental limitation of low-latency anonymous communication.

**Tor hidden service requires sudo.** The persistent hidden service writes key files to `/var/lib/tor/malphas_hs/`, which is owned by the Tor user. Launching malphas with `--tor` requires root privileges or membership in the `debian-tor` group. The setup script (`scripts/setup.sh`) configures this automatically.

**Tor self-rendezvous.** A single Tor process cannot connect to its own hidden service. Two machines sharing the same public IP (e.g., Docker containers on the same host, or two processes behind the same NAT) also fail. This is a Tor architectural constraint, not a malphas issue. Testing hidden service delivery requires two machines on genuinely different networks.

**Tor descriptor propagation.** After registering a hidden service, the descriptor must propagate to HSDir relay nodes before the `.onion` address becomes reachable. This typically takes 30-60 seconds but can take longer on freshly started Tor instances. Avoid reloading Tor during a session — each reload triggers descriptor re-publication and temporary unreachability.

**Memory wiping in Python.** Python strings and bytes objects are immutable. Overwriting a variable only changes the reference — the original bytes may remain in the heap until garbage collection. The passphrase and seed material in RAM cannot be reliably zeroed in pure Python.

**Windows.** The core messaging functionality works on Windows. Tor hidden service support requires manual configuration — the setup script is Linux-only.

---

## Testing

```bash
# All tests (excludes Tor-dependent tests)
pytest tests/ -m "not tor and not slow"

# Security tests only
pytest tests/test_security_*.py -v

# End-to-end integration tests (real TCP, real nodes)
pytest tests/test_integration_e2e.py -v

# API and WebSocket tests
pytest tests/test_api.py -v

# CLI command tests
pytest tests/test_cli.py -v

# Key pinning tests
pytest tests/test_pinstore.py -v

# Invite system tests
pytest tests/test_invite.py -v

# Tor tests (requires Tor running with ControlPort 9051)
pytest tests/test_transport.py::TestTorIntegration -v
pytest tests/test_tor_e2e.py -v
```

**Test suite:**

| File | What it verifies | Tests |
|---|---|---|
| `test_security_identity.py` | Argon2, deterministic derivation, key independence, sign/verify | 19 |
| `test_security_crypto.py` | ChaCha20, ECDH, HKDF, session keys, tamper detection, nonce uniqueness | 24 |
| `test_security_onion.py` | Layer isolation, relay cannot read content, tamper rejection, ephemeral keys | 15 |
| `test_security_addressbook.py` | No plaintext on disk, wrong passphrase rejected, padding, atomic write, wipe | 18 |
| `test_security_obfuscation.py` | Padding alignment, cover traffic indistinguishable, receipt verification | 22 |
| `test_security_argon2_panic.py` | Argon2 timing, panic clears all state, unicode/long passphrases | 18 |
| `test_functional_components.py` | XOR distance, routing table, discovery, message store ordering and TTL | 27 |
| `test_functional_node.py` | Handshake, authenticated handshake, delivery, receipts, cover traffic, lifecycle | 19 |
| `test_integration_e2e.py` | Cross-node delivery, bidirectional, relay, receipts, wire crypto, tamper resilience | 18 |
| `test_transport.py` | SOCKS5, DirectTransport, TorTransport, .onion derivation, hidden service | 28 |
| `test_api.py` | REST endpoints, WebSocket push, CORS, Pydantic validation, edge cases | 91 |
| `test_cli.py` | All commands, tab completion, status bar, callbacks, export/import, trust | 128 |
| `test_invite.py` | Generate/parse roundtrip, signature verification, tampered blobs, validation | 17 |
| `test_pinstore.py` | First contact pins, mismatch rejected, trust reset, persistence, handshake integration | 17 |
| `test_tor_e2e.py` | Hidden service registration, .onion stable across restarts | 5 |

**What passing tests guarantee:**

- Message content is encrypted end-to-end and cannot be read by relays
- Tampered onion packets are silently dropped at every hop
- The address book file contains no plaintext when inspected at the byte level
- Wrong passphrase is rejected by the address book decryption
- Handshake is authenticated — invalid Ed25519 signatures are rejected
- Key pinning detects Ed25519 key changes on reconnection
- Messages from unknown senders are silently dropped
- Deniable authentication (HMAC) works for message delivery
- `/panic` clears all in-memory state including pins and queues
- Argon2id is orders of magnitude slower than SHA1 (timing verified)
- Cover packets are not delivered as messages
- Read receipts from wrong keys are rejected
- Invite blobs with tampered signatures are rejected
- REST API validates all inputs and rejects malformed requests
- CLI commands parse correctly and produce expected state changes
- Tor hidden service registration succeeds with the node's Ed25519 key

---

## Development

**Project structure:**

```
malphas/
├── src/malphas/
│   ├── identity.py      passphrase → keypairs (Argon2id + HKDF)
│   ├── crypto.py        X25519, ChaCha20-Poly1305, HKDF, HMAC-SHA256
│   ├── onion.py         layered onion packet construction and peeling
│   ├── transport.py     DirectTransport, TorTransport, SOCKS5, .onion derivation
│   ├── node.py          async node, handshake, routing, reconnect, queue, panic
│   ├── discovery.py     Kademlia routing table, peer management
│   ├── memory.py        in-memory message store with TTL
│   ├── receipts.py      Ed25519 read receipt challenge-response
│   ├── obfuscation.py   padding, cover traffic engine
│   ├── addressbook.py   encrypted persistent contact storage
│   ├── pinstore.py      TOFU key pinning, encrypted persistence
│   ├── invite.py        signed malphas:// invite URLs
│   ├── cli_ui.py        prompt_toolkit + rich interactive terminal
│   ├── api.py           FastAPI + WebSocket (web mode)
│   ├── splash.py        ASCII splash screen
│   └── __main__.py      CLI entry point, argument parsing
├── frontend/showcase/
│   └── index.html       project landing page
├── scripts/
│   └── setup.sh         automated Tor + malphas setup (Linux)
└── tests/               470+ tests across 15 files
```

**Adding a new transport.** Subclass `BaseTransport` in `transport.py` and implement `connect()`, `start_server()`, and `stop()`. Pass an instance to `MalphasNode(transport=...)`.

**Protocol versioning.** HKDF info strings include a version suffix (`-v1`). Breaking protocol changes should increment the version to prevent cross-version interoperability confusion.

---

## Disclaimer

malphas is provided for educational and research purposes. It is a demonstration of applied cryptography and privacy engineering principles.

Use it only on networks and systems you own or have explicit permission to access. The authors assume no responsibility for misuse. You are solely responsible for your actions and for compliance with applicable laws in your jurisdiction.

malphas is not audited. Do not use it in situations where the cost of a security failure is unacceptable without first conducting a professional security audit.

---

*malphas — built by Cristian D'Arrigo*
