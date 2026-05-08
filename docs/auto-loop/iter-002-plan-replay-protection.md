# Iter 002 — Piano: Replay Protection (path HMAC/Ed25519)

## Obiettivo

Aggiungere protezione anti-replay sul cammino di consegna messaggi per impedire ad un osservatore/relay malevolo di re-inviare un onion packet già visto e ottenere doppia consegna al destinatario.

## Scope

**In scope**
- Nuovo modulo `replay.py` con `ReplayCache` (sliding window per `(from_id, msg_id)`).
- Integrazione in `MalphasNode._deliver` (path HMAC e path Ed25519).
- Integrazione opzionale anche sul path ratchet (ridondante con `msg_num` ma tappa il caso "ratchet appena resetata, primo messaggio replay-able durante grace window") — fattibile, decisione: SI per coerenza, NO sui receipt (riceviamo solo 1 receipt valido per msg_id già nello tracker).
- Test `tests/test_replay_protection.py`.

**Out of scope**
- Cambio del wire format.
- Replay protection a livello transport (lo lasciamo gestito dalla session ChaCha20 + auth).
- Persistenza della cache cross-process.

## Requisiti funzionali

1. La stessa coppia `(from_id, msg_id)` consegnata due volte deve produrre callback `on_message` UNA SOLA volta.
2. Il `MessageStore` non deve memorizzare due volte lo stesso `msg_id` per la stessa conversazione.
3. La cache deve auto-scadere dopo `REPLAY_TTL` secondi (default = `message_ttl` del nodo, fallback 3600s).
4. La cache deve avere un cap (`REPLAY_MAX = 10_000`) per evitare DoS via flood di msg_id distinti.
5. Quando la cache è piena, gli entry più vecchi vengono evictati (FIFO).
6. `panic()` deve wipare anche la replay cache.

## Requisiti non funzionali

- Lookup O(1) tramite dict.
- Memoria O(N) dove N ≤ REPLAY_MAX.
- Threadsafe non richiesto (asyncio single-thread).
- Niente disco.
- Niente logging.

## Design

### Modulo `src/malphas/replay.py`

```python
class ReplayCache:
    def __init__(self, ttl: int = 3600, max_entries: int = 10_000): ...
    def seen(self, from_id: str, msg_id: str) -> bool:
        # Returns True if entry was already seen (and updates timestamp).
        # Returns False if new (and records it).
    def purge_expired(self) -> int: ...
    def wipe(self) -> None: ...
    def __len__(self) -> int: ...
```

Implementazione: `OrderedDict[(from_id, msg_id), float]` per FIFO + scadenza.

### Integrazione `node.py`

- `MalphasNode.__init__`: instanzia `self._replay = ReplayCache(ttl=message_ttl)`.
- In `_deliver_message` (path msg) e `_deliver` (path comune prima di consegnare): check `seen(from_id, msg_id)` — se True, drop silenzioso.
- In `_deliver` ratchet path, dopo aver verificato JSON kind/from: stesso check.
- In `_deliver_receipt` non serve (già protetto da `pr.resolved`).
- `_purge_loop` invoca anche `self._replay.purge_expired()` ogni 60s.
- `panic()` chiama `self._replay.wipe()`.

## Acceptance criteria

- [ ] Test "replay HMAC path" passa: stessa onion packet inviata 2 volte, 1 sola callback.
- [ ] Test "replay Ed25519 path" passa.
- [ ] Test "replay ratchet path" passa.
- [ ] Test "ttl expiry" passa: dopo TTL la stessa coppia è di nuovo accettata.
- [ ] Test "max entries" passa: oltre il cap il più vecchio è evictato.
- [ ] Test "panic wipes" passa.
- [ ] Tutti i test esistenti continuano a passare.
- [ ] Nessun cambio del wire format.

## Testability constraint

Tutto il design è puramente unit-testabile (no Tor, no rete reale). Per il path "stessa onion packet" il test usa direttamente `node._deliver(packet)` su un nodo isolato, dopo aver injectato un peer fittizio in `discovery` e una connection handshake-completata.

## Risk assessment

- **R1**: l'integrazione del check ratchet potrebbe rompere casi out-of-order legittimi se due messaggi diversi avessero stesso `msg_id`. Mitigazione: `msg_id` è generato con `secrets.token_hex(16)` (128 bit) → collisione cosmica.
- **R2**: cache piena = DoS riducibile. Mitigazione: cap + TTL.
- **R3**: cambio comportamento sender che invia "intenzionalmente" stesso msg_id (retry). Verifica: nel codice attuale il sender genera fresh `msg_id` ad ogni `send_message` quindi safe.

## File touchati

- `src/malphas/replay.py` — nuovo
- `src/malphas/node.py` — integrazione
- `tests/test_replay_protection.py` — nuovo
- `docs/auto-loop/iter-003-red-replay-protection.md` — log
- `docs/auto-loop/iter-004-green-replay-protection.md` — log

## Versioning

Patch 0.2.0 → 0.2.1 (no API/wire change).
