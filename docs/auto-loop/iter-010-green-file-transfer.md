# Iter 010 — Green: file transfer chunked

## Cosa è stato fatto

### Nuovo modulo `src/malphas/files.py`

API:

- `FileOffer` (dataclass frozen) — `to_dict` / `from_dict` per il wire.
- `OutgoingFile(path, *, chunk_size)` — apre, valida (`size > 0`, `size <= MAX_FILE_BYTES`), calcola SHA-256, genera `file_id` random 16-byte hex; espone `offer()` e `chunkify()` come iterator deterministico.
- `IncomingFile(offer)` — buffer in-memory di chunk; `add_chunk(idx, data) -> bool` (idempotente, ritorna True se complete), `progress()`, `assemble()` (concatena, verifica SHA-256 + size, raise su mismatch), `cancel()` libera la memoria.
- `FileTransferManager` — registry `_outgoing` / `_incoming` con `register_outgoing`, `register_incoming`, `get_incoming`, `cancel`, `wipe`.
- Costanti: `CHUNK_SIZE = 32 KB`, `MAX_FILE_BYTES = 100 MB`.

### Wire format extension (backward compatible)

Tre nuovi `kind` JSON-payload: `file_offer`, `file_chunk`, `file_ack`. I client vecchi droppano silenziosamente i kind sconosciuti grazie alla policy fail-closed esistente in `_dispatch_kind`.

### Refactor `node.py`

- Nuovo dispatch helper centralizzato `_dispatch_kind(data, from_id, peer)` che:
  - applica replay-check su tutti i kind (msg, receipt, file_*) in un unico punto
  - dispatcha a `_deliver_message`, `_deliver_receipt`, `_handle_file_offer`, `_handle_file_chunk`, `_handle_file_ack`
  - droppa `KIND_COVER`
- Sostituito i due punti che dispatchavano direttamente (path ratchet + path HMAC/Ed25519) con la chiamata a `_dispatch_kind`. Niente comportamento osservabile cambiato per i kind esistenti.
- Rimosso il replay check da `_deliver_message` (ora centralizzato).
- Aggiunto `send_file(dest, path) -> file_id | None` — registra outgoing, invia offer, sleep 100 ms, stream dei chunk con spacing 5 ms.
- Aggiunto `_try_send_payload(dest, kind, extras) -> bool` — variante generalizzata di `_try_send` per qualunque kind (auth ratchet → HMAC → Ed25519, padding, onion, primo hop). `_try_send` originale immutato per non rompere niente.
- Aggiunto callback `on_file_offer(callback)` e `on_file_complete(callback)` con relative invocazioni async-aware.
- `accept_file_offer(offer_dict)` per accettazione esplicita lato applicazione.
- `auto_accept_files: bool = False` — flag che bypassa la richiesta di consenso per i test e il futuro CLI `--auto-accept-files`.
- `panic()` chiama `self._files.wipe()`.

### Test `tests/test_files.py`

14 test:
- 3 `OutgoingFile`: chunkify count, sha256 correctness, max size enforcement.
- 6 `IncomingFile`: assemble byte-perfect, dedup, out-of-order, sha256 mismatch raises, progress fraction, cancel frees memory.
- 3 `FileTransferManager`: register outgoing returns id, get_incoming returns registered, wipe clears all.
- 2 integration E2E: small file 1 KB arrives intact end-to-end (con auto-accept), panic wipes incoming.

Risultato: 14/14 PASSED in ~3 s.

## Versioning

Minor 0.2.4 → 0.3.0 — aggiunge una capability sostanziale (anche se backward-compatible al wire). Bump motivato dal cambio del README "what malphas can do".

## Lo scope rimasto fuori

- `/sendfile` / `/accept` / `/reject` / `/savefile` CLI commands → iter successivo.
- Resume di transfer interrotti.
- Compressione.
- File >100 MB.
- Salvataggio automatico su disco.

## Verifica

```
$ .venv/bin/python -m pytest tests/test_files.py -v
14 passed
```
