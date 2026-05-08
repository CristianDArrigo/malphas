# Iter 001 — Review comportamentale, semantica, sintattica

## Metodologia

- Lettura completa di tutti i moduli `src/malphas/*.py`.
- Lettura header conftest + esempi tests/.
- Confronto con README.md e `docs/plans/2026-04-06-double-ratchet.md`.
- Analisi tre livelli:
  1. **Sintattica**: typo, dead code, naming, layout.
  2. **Semantica**: invarianti, error handling, consistency wire-format ↔ implementazione.
  3. **Comportamentale**: flow runtime, race condition, threat-model gap.

## A. Findings comportamentali (priorità alta → bassa)

### A1. Replay window assente sul path HMAC/Ed25519 — HIGH

`node.py:_deliver` per messaggi non-ratchet non tiene traccia di `(from_id, msg_id)` già visti. Un attaccante che osserva un onion packet in transito (relay malevolo) e lo rispedisce identico al primo hop ottiene la riconsegna del payload al destinatario. Il Double Ratchet protegge tramite contatore `msg_num`, ma il fallback HMAC/Ed25519 no. Dato che il fallback può essere selezionato per ogni messaggio se la ratchet non è ancora pronta o lato ricevente in ricezione, il gap è reale.

Conseguenze: doppia delivery callback a UI, doppia memorizzazione in `MessageStore`, doppia richiesta di receipt → il sender riceve 2 receipt per 1 invio (un solo receipt sopravvive perché `ReceiptTracker.resolve` checka `pr.resolved`, ma il receipt viene comunque ri-firmato e ri-inviato dal destinatario, un costo gratis per l'attaccante).

### A2. Trial-decrypt ratchet — danno collaterale su connessioni multiple — MEDIUM

`node.py:_deliver` scorre `self._connections` e prova decrypt su ogni ratchet, snapshotting/restoring lo state. Funziona ma:
- Costo O(N) per messaggio.
- Se due peer condividono la stessa session key per puro caso (impossibile crypto-wise ma...): comportamento non definito.
- Manca un identificatore di sessione (es. SHA256(session_key)[:8]) nel header onion → forziamo brute force tra peer.

Si potrebbe aggiungere un `session_id` di 8 byte non sensibile davanti al ciphertext per saltare direttamente alla ratchet giusta. Decisione: non urgente, design choice.

### A3. `_send_receipt` doppia firma + doppia HMAC — DESIGN

Il payload del receipt è già firmato Ed25519 inside JSON (`sig` field). Poi viene incapsulato con o ratchet, o HMAC, o Ed25519 outer signature. Il caso "Ed25519 outer + Ed25519 inner" è ridondante. Cosmetico ma tradisce indecisione tra deniable vs non-repudiation.

### A4. `random.sample` in `discovery.select_relay_circuit` — LOW

Documentato nella review precedente. `random` di stdlib è seeded da `os.urandom` ma esposto: in test/process determinismo l'attaccante può predire la rotta. Sostituire con `secrets`.

### A5. Cover traffic distinguibile da "chi ha la chiave" — LOW

`COVER_FLAG = b"\x00COVER\x00"` non è plaintext on-wire (è dentro l'onion cifrato), ma una volta che il destinatario decifra è ovvio. Se il modello di minaccia include "compromesso del ricevente che vuole capire quale traffico è cover", manca offuscamento (es. cover = JSON identico al messaggio reale ma con flag interno). Trade-off vs banda. Non urgente.

### A6. Race su `_connections` durante panic — LOW

`panic()` è sincrono. Se un `_read_loop` sta loopando in parallelo e legge messaggio appena prima del panic, può richiamare callback già rimossi. Effetto pratico: errore silente. Aggiungere flag `self._panicked = True` come early-exit guard sarebbe pulito.

### A7. Re-connect senza backoff jitter — LOW

`_reconnect` raddoppia il delay ma non randomizza. Tanti peer dietro NAT che vanno giù insieme producono thundering herd quando torna su. Aggiungere jitter ±20%.

### A8. `MessageQueue` cresce silenziosamente — LOW

`_message_queue` per peer ha `queue_limit=100`, ma se il limit è raggiunto i messaggi nuovi vengono semplicemente droppati senza notifica all'utente. Il sender pensa che `send_message` ha avuto successo (returns msg_id). UX bug.

### A9. `time.time()` per TTL — non monotonic — LOW

`MessageStore.expires_at = now + ttl` usa `time.time()`. Se il sistema cambia clock all'indietro (NTP), i messaggi non scadono mai. Usare `time.monotonic()` per scadenze, `time.time()` solo per display.

## B. Findings semantici

### B1. SHA1 per peer_id — DOCUMENTED

Già discusso nella review verbale. Non security-critical (è solo identifier) ma:
- Collision di peer_id → un attaccante può generare due passphrase con stesso peer_id e creare confusione su sender/destination. Costo collision SHA1 ~2^61 ≈ fattibile per attore statale.
- Il fix è breaking wire-format → roadmap v0.3.

### B2. Argon2id salt fisso pubblico — DOCUMENTED

`_ARGON2_SALT = b"malphas-kdf-salt"` permette rainbow table globale. Ricochet/Cwtch evitano: chiave random → salvata cifrata. Malphas evita disco → sacrifica salt-per-utente. Compromesso possibile: salt = `BLAKE2s(passphrase[:N])[:16]` oppure salt random salvato in un file `.salt` opzionale.

### B3. `derive_session_key` argomento `role` non utilizzato — SYNTAX

`crypto.py:84` accetta `role: str = ""` ma è no-op. La canonical ordering via sort è corretta (chave bidirezionale single = ChaCha20-Poly1305 con random nonce è OK). Il parametro è dead, rimuovere o documentare apertamente.

### B4. `Identity.x25519_pub_bytes` doppio campo — SYNTAX

`Identity` ha sia `x25519_pub: X25519PublicKey` sia `x25519_pub_bytes: bytes`, calcolato due volte in `create_identity` e `create_identity_with_book_key`. Una è derivabile dall'altra; tenere uno solo.

### B5. `crypto.py:hkdf_derive` — `hkdf` non riusato — STYLE

Crea l'oggetto `HKDF` e poi chiama `.derive`: pattern OK ma `hkdf` non è riutilizzabile (HKDF instance state-bound). Non è un bug, solo segnale.

### B6. Onion AAD = `eph_pub` — bound a layer ma NON al next_hop — SEMANTIC

`onion.py:wrap_onion` cifra `next_hop_id || len || payload` con AAD = `eph_pub`. Quindi `next_hop_id` è within ciphertext, autenticato dal Poly1305 tag. Se un MITM modifica il next_hop_id il tag fallisce. **Però** AAD non binds first_hop_id a packet: i primi 24 byte (first_hop_id + len) sono in chiaro e modificabili. Effetto: relay sbagliato riceve packet, fallirà decrypt → drop. Correctness OK, no info leak. Documentare.

### B7. `node.py:_deliver` trial-decrypt JSON probe — SEMANTIC

Per distinguere HMAC (32B tag) da Ed25519 (64B tag), il codice prova `json.loads(signed[32:])` poi `signed[64:]`. È un probe euristico: se il payload contiene un JSON che inizia a offset 64 ma il tag vero è HMAC, il codice sceglie Ed25519 (sbagliato). Probabilità praticamente zero ma lascia un side channel. Soluzione: prefisso 1-byte `auth_type` (`H`, `E`, `R`).

### B8. Ratchet trial-decrypt non protegge da DoS — SEMANTIC

Un attaccante con accesso al canale può inviare onion packet con prefisso `b"R"` e dati casuali. Per ogni connessione attiva, il ricevente snapshotta lo state, prova il decrypt, restora. Costo non banale con tante connessioni. Mitigazione: tipo (`auth_type`) esplicito + rate limit per IP.

## C. Findings sintattici

### C1. `node.py:447` except generico — `except (asyncio.IncompleteReadError, ConnectionResetError, OSError, Exception)`

`Exception` rende inutile la lista. Sostituire con `except Exception:` o specificare e basta.

### C2. Import locali sparsi

`node.py` importa `struct`, `Ed25519PublicKey`, `cryptography.serialization` dentro funzioni. Non è un bug, è anti-pattern minore. Gli import locali in `_deliver`/`_perform_handshake`/`_snapshot_ratchet` accadono ad ogni chiamata.

### C3. `obfuscation.py:secrets.randbelow(int((max-min)*100))/100.0`

Discretizza l'intervallo a step di 0.01s. Simpler: `random.uniform(min, max)` (basta `random` per timing non-security) o `secrets.randbits(32)/2**32 * (max-min) + min`.

### C4. `_pack_msg`/`_unpack_header` reimplementano struct ad-hoc

5 byte header (`>BI`). OK ma inconsistente con altri moduli che usano helper `pack_u32` da crypto.

### C5. Magic numbers

- `tag_len = 32` o `64` in `_deliver` — usare `HMAC_TAG_LEN = 32`, `ED25519_SIG_LEN = 64`.
- `41` in `signed[1:41]` deserializzazione header ratchet — `HEADER_LEN_RATCHET = 40`.
- `24` in `packet[24:]` per strip first_hop_id+len — `ONION_FIRST_HOP_PREFIX = 24`.

### C6. README discrepanza minore

`/help` non è in `COMMANDS` definita in `cli_ui.py:74` (in realtà sì, l'ho letto male). OK.

### C7. `__init__.py` quasi vuoto

`src/malphas/__init__.py` è 2 righe. OK per pacchetto, ma `__version__` non esposto. Convenzionale: `from importlib.metadata import version; __version__ = version("malphas")`.

### C8. Docstring `Identity` cita SHA1 in commento

`identity.py:1` "SHA1(passphrase) -> seed -> ..." — è errato! Ora è Argon2id. Fix immediato di docstring.

### C9. CLI `__main__.py:104` `print(f" warning: …")` — STYLE

Output usa `print` ma il resto del CLI usa `print_formatted_text` di prompt_toolkit. Inconsistente quando il CLI è già attivo (può rompere il layout).

### C10. `transport.py:start_hidden_service` mescola `subprocess.run` e `asyncio.run_in_executor`

Funziona ma il blocking sotto sudo dura secondi. Aggiungere timeout esplicito globale e log se fallisce silenziosamente.

## D. Test gaps

### D1. Niente test per replay attack su path HMAC/Ed25519

`test_security_*` copre tampering, wrong key, brute force resistance. Non c'è nulla che invii lo stesso onion-packet due volte.

### D2. Niente test per `panic` mentre traffico in volo

`panic()` è testato in isolamento (`test_security_*` parzialmente?). Non c'è scenario "panic durante delivery".

### D3. Coverage gate assente

`pytest --cov` non in CI, niente threshold.

### D4. No fuzz test su `peel_layer`/`unpad_payload`/`parse_invite`

Atheris/Hypothesis assenti. Buon investimento di hardening.

### D5. No property-based test su Double Ratchet

`test_ratchet.py` ha 121 righe, casi happy-path. Mancano: out-of-order delivery con drop, skipped messages > MAX_SKIP, invio dopo `panic` parziale.

## E. Engineering gaps

| Item | Stato | Priorità |
|------|-------|----------|
| mypy strict in CI | mancante | M |
| ruff/black in CI | mancante | M |
| coverage gate ≥80% | mancante | M |
| bandit/semgrep | mancante | M |
| pre-commit hooks | mancante | L |
| CHANGELOG.md | mancante | L |
| ROADMAP.md | mancante (solo plan DR) | M |
| SECURITY.md | mancante | M |
| Reproducible build | mancante (hatchling OK) | L |
| Wheel signing / sigstore | mancante | L |

## F. Selezione obiettivo per Iter 002

Criteri:
1. Self-contained — non breaking il wire format.
2. Testabile con TDD chiaro.
3. Security-relevant — coerente con la natura del progetto.
4. Adatto alla fase corrente (post-DR, pre-roadmap completa).
5. Lavoro fattibile in 1–2 iterazioni del loop.

Candidati:
- A1 Replay protection — **scelto**: gap concreto, TDD chiaro, no breaking change.
- C5 Magic numbers cleanup — troppo cosmetico per il primo target.
- B7 Auth-type tag prefix — breaking wire format.
- D3 Coverage gate — utile ma è infra, non security.

**Decisione: Iter 002 → 004 implementeranno replay protection.**
