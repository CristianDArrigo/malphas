# Iter 006 — Green: micro-fixes batch

## Cosa è stato fatto

### A4 — `secrets.SystemRandom` per circuit selection

`src/malphas/discovery.py:select_relay_circuit`: sostituito `import random; random.sample(...)` con `secrets.SystemRandom().sample(...)`. Aggiunta nota nel docstring.

### A7 — Reconnect jitter ±20%

`src/malphas/node.py:_reconnect`: dopo il calcolo del backoff esponenziale aggiunto `jitter_factor = 1.0 + (rng.random() - 0.5) * 0.4` con `secrets.SystemRandom`. Mantenuto il floor a 0.1 s. Aggiornata la docstring.

### A9 — Monotonic TTL

`src/malphas/memory.py`:
- `Message.is_expired` ora usa `time.monotonic()`.
- `MessageStore.store` calcola `expires_at = time.monotonic() + ttl`. Mantiene `time.time()` solo per `timestamp` (display).
- `get_conversation` non ricalcola wallclock `now` — non serve.

### C8 — Docstring identity.py

Sostituita la prima riga "SHA1(passphrase) -> seed -> ..." (obsoleta) con descrizione corretta basata su Argon2id.

## Test

`tests/test_microfixes.py` (5 test):

- `test_select_relay_circuit_uses_secrets_systemrandom` — assert su sorgente: `secrets`/`SystemRandom`/no `random.sample(`.
- `test_reconnect_has_jitter` — assert su sorgente: `jitter`/`SystemRandom`.
- `test_message_store_uses_monotonic_for_ttl` — assert su sorgente di `Message.is_expired` e `MessageStore.store`.
- `test_message_store_expiry_with_short_ttl` — TTL=1s, sleep 1.1s, verifica `purge_expired` rimuove l'entry.
- `test_identity_module_docstring_mentions_argon2` — verifica che `Argon2id` sia presente e che la prima riga non riferisca a `SHA1(passphrase)`.

Risultato: 5/5 PASSED in 1.11s.

## Garanzie non testabili

- Il jitter del reconnect non è verificato per timing (timing test → flaky). Garantito tramite review manuale: il fattore moltiplicativo è centrato su 1 con simmetria ±0.2 e rispetta il floor di 0.1 s.
- L'efficacia del `secrets.SystemRandom` rispetto a `random` non è verificabile a unit; documentato nella docstring + test sul sorgente garantisce che il pattern non regredisca nei refactor.

## Versioning

`pyproject.toml`: 0.2.1 → 0.2.2.
