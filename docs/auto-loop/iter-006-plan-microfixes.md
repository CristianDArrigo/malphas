# Iter 006 — Plan: micro-fixes batch (no breaking)

## Obiettivo

Risolvere in un solo batch i fix piccoli, no-wire-break, già identificati in iter-001:

- A4 — `secrets`-based circuit selection
- A7 — reconnect jitter ±20%
- A9 — `time.monotonic()` per TTL nei moduli mancanti (MessageStore)
- C8 — fix docstring `identity.py` (SHA1 → Argon2id)

## Acceptance criteria

### A4 — circuit selection deterministically unpredictable

- `discovery.select_relay_circuit` deve usare `secrets.SystemRandom()` invece di `random`.
- Test: chiamare la funzione 100 volte con stessi candidati deve produrre output non costante (smoke), e — più importante — il modulo deve importare `secrets`, non `random`. Il vero test della crypto-randomness non è facile a unit; bastano: smoke su distribuzione + assert struttura.

### A7 — reconnect jitter

- `_reconnect`: dopo `delay = min(delay * 2, max_delay)` aggiungere `delay *= 1 + (random.random() - 0.5) * 0.4` (±20%).
- Garantito tramite review (timing test sarebbe flaky). Documentato nel green log.

### A9 — monotonic TTL

- `memory.MessageStore` usa `time.time()` per `expires_at`. Migrare a `time.monotonic()`. Mantenere `time.time()` per il campo `timestamp` (visualizzato all'utente).
- Test: avanzare manualmente il monotonic clock (mock) e verificare expiry. Oppure semplicemente unit con TTL piccolo.

### C8 — docstring fix

- `src/malphas/identity.py:1-5` corregge la docstring del modulo: ora dice "SHA1(passphrase) -> seed" che è obsoleto. Sostituire con descrizione Argon2id.

## File touchati

- `src/malphas/discovery.py`
- `src/malphas/node.py`
- `src/malphas/memory.py`
- `src/malphas/identity.py`
- `tests/test_microfixes.py` (nuovo)

## Versioning

Patch 0.2.1 → 0.2.2.
