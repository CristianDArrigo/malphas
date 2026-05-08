# Iter 004 — TDD Green: replay protection implementation

## Cosa è stato fatto

### Nuovo modulo `src/malphas/replay.py`

`ReplayCache(ttl, max_entries)` — sliding window di chiavi `(from_id, msg_id)`:

- `seen(from_id, msg_id) -> bool`: True se è un replay (già visto e non scaduto), False se nuovo (e lo registra).
- `purge_expired() -> int`: rimuove gli scaduti, ritorna il count.
- `wipe()`: cancella tutto.
- `__len__`, `__contains__` come comodità.
- Backed by `OrderedDict` per FIFO O(1) e tempo di inserimento monotonic.
- `time.monotonic()` per non essere influenzato da NTP che cambia il clock all'indietro (vedi Iter-001 finding A9 — qui correggo proattivamente).
- TTL non viene refreshato sui replay: un attaccante che continua a replay-are non può tener viva una entry per crowd-out delle altre.

### Integrazione in `src/malphas/node.py`

1. Import `from .replay import ReplayCache`.
2. `MalphasNode.__init__`: `self._replay = ReplayCache(ttl=message_ttl)`.
3. In `_deliver_message`: dopo aver verificato content/msg_id/nonce ma prima di `store.store`/`_notify_message`, chiama `self._replay.seen(from_id, msg_id)`. Se True → drop silenzioso (no callback, no store, no receipt). Coerente con la "fail closed" policy del README.
4. In `_purge_loop`: aggiunto `self._replay.purge_expired()` ogni 60 s.
5. In `panic()`: aggiunto `self._replay.wipe()`.

### Perché in `_deliver_message`

Il check è centralizzato in un unico punto a valle perché `_deliver_message` è chiamato da tutti e tre i path:
- ratchet path (`_deliver` ratchet branch → `_deliver_message`)
- HMAC path (32B tag in `_deliver` → `_deliver_message`)
- Ed25519 path (64B sig in `_deliver` → `_deliver_message`)

Quindi un solo check copre tutto, evitando duplicazione e dimenticanze. I receipt (`_deliver_receipt`) NON sono protetti da replay cache: il `ReceiptTracker.resolve` checka già `pr.resolved` quindi un replay del receipt non causa side effect (al massimo CPU per verifica firma — accettabile).

## File modificati

- `src/malphas/node.py` (4 punti: import, init, deliver, purge, panic)
- `src/malphas/replay.py` (nuovo)
- `tests/test_replay_protection.py` (creato in iter 003)

## Verifica

```bash
.venv/bin/python -m pytest tests/test_replay_protection.py -v
```

Risultato atteso: 14/14 PASSED.

Verifica non-regressione:

```bash
.venv/bin/python -m pytest tests/ -m "not tor and not slow" -q
```

Risultato atteso: tutta la suite verde.

## Decisioni di design rilevanti

- **Choice di `time.monotonic()` invece di `time.time()`**: protegge contro clock skew. Il TTL della cache non deve dipendere da quanto è "vecchio" un timestamp wallclock, ma da quanto tempo reale è passato dall'inserimento.
- **No refresh on replay**: vedi sopra, mitiga DoS-via-replay-flood.
- **Cap a 10000 entries**: ~1 KB/entry overhead worst-case → 10 MB max footprint. Ragionevole per un client desktop.
- **No persistenza disco**: aderente alla policy zero-disk.
- **No log**: aderente alla policy no-logging.

## Trade-off

- Una replay cache eccessivamente piccola può evictare entries genuine sotto load alto, permettendo replay tardivi. 10k entries × 3600 s TTL = ~3 msg/sec sustainable continuamente prima che la cache strizzi entries vere. Se diventerà un problema, si può migrare a Bloom filter.
- Non protegge contro replay cross-passphrase (se l'utente cambia passphrase, il nodo riparte da zero). Acceptable: cambio passphrase è evento raro e cambia anche peer_id.

## Stato

- [x] iter-002 acceptance criteria 1–7 soddisfatti.
- [x] Nessun cambio del wire format.
- [x] Nessuna nuova dipendenza.
- [x] Nessun cambio di firma pubblica esistente.
