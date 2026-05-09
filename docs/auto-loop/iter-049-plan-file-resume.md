# Iter 049 — Plan: file transfer resume (v0.8.0)

## Problema

Oggi se la connessione cade a metà di un file transfer (peer offline,
Tor circuit drop, killed process), l'unico ricorso è ri-mandare tutto
da capo: `OutgoingFile.chunkify()` legge da disco, `IncomingFile`
manca dei chunk e l'`assemble()` non parte. Per file da 100 MB su
Tor questo è un costo concreto.

## Soluzione

Aggiungere un nuovo `kind = "file_resume"` che il receiver invia al
sender quando vede un `file_offer` per un `file_id` di cui ha già
una transcrizione parziale in memoria.

```
{kind: "file_resume",
 file_id: <hex>,
 received_idx: [int, int, ...]}
```

Il sender, alla ricezione, skip-pa i chunk_idx già confermati e
manda solo i mancanti.

## Wire format

Backward-compatible: peer 0.7.x ignora `file_resume` come "kind
sconosciuto" (la `_dispatch_kind` policy fail-closed). Sender 0.8.0
che non riceve `file_resume` entro un timeout breve manda tutti i
chunk normalmente. Quindi 0.7.1 ↔ 0.8.0 interoperano *senza* il
beneficio del resume.

## Workflow

### Sender, prima volta

```
malphas> /sendfile bob ./photo.jpg
  ... sending photo.jpg to bob ...
  [ok] file_id  3f7a8e2b...
```

Internamente: send_file invia offer + attende up-to 200ms per un
file_resume (che non arriva al primo tentativo) + invia tutti i
chunk.

### Sender, retry

L'utente nota che il transfer non è andato a buon fine (es. Bob
torna online). Esegue:

```
malphas> /resume 3f7a8e2b...
  ... resuming photo.jpg → bob (47/52 chunks remaining) ...
  [ok] resumed
```

Il sender riusa l'`OutgoingFile` esistente in `_files._outgoing`
(non rilegge il path, usa il file_id), invia il file_offer, riceve
il `file_resume` da Bob con i 5 chunk_idx già visti, skippa quelli,
manda i restanti 47.

### Receiver

```
*** offer from alice: photo.jpg (842341 bytes) [resume of 5/52 chunks]
... receiving …
*** received photo.jpg (842341 bytes) from alice
*** /savefile 3f7a8e2b... <path>
```

Il receiver, su file_offer per un file_id già nel `_incoming`:
- Non re-registra l'incoming (ha già il buffer parziale).
- Invia indietro un `file_resume` con `sorted(self._chunks.keys())`.
- Continua ad accettare i chunk in arrivo.

## Implementazione

### `src/malphas/files.py`

- `IncomingFile.received_indices() -> list[int]` (già implicitamente
  `sorted(self._chunks.keys())`, esponiamo come property/method).
- Niente altro cambia nel modulo files.

### `src/malphas/node.py`

- Nuova costante `KIND_FILE_RESUME = "file_resume"`.
- Nuovo metodo `_handle_file_resume(data, from_id)`:
  - Cerca `OutgoingFile` con quel `file_id` in `_files._outgoing`.
  - Memorizza `received_idx` in un nuovo dict
    `_resume_signals: dict[str, set[int]]`.
  - Se è in corso un `send_file()` in attesa, lo "sveglia" via
    `asyncio.Event` per file_id.
- `_handle_file_offer` modificato:
  - Se `offer.file_id` già in `_files._incoming` → invia
    `file_resume` indietro.
- `send_file(dest, path, file_id=None)`:
  - Accetta `file_id` opzionale. Se None, genera nuovo (path attuale).
  - Se passato, riusa l'`OutgoingFile` con quel id da
    `_files._outgoing` (che deve esistere).
  - Dopo l'offer, attende `_resume_signals[file_id]` con timeout 1s
    (asyncio.Event).
  - Quando manda chunks, skippa idx in `received_idx`.
- `resume_file(dest, file_id) -> bool`: nuovo metodo pubblico,
  helper user-facing. Se OutgoingFile esiste in `_files._outgoing`,
  chiama `send_file(dest, path, file_id=file_id)`. Else False.

### CLI

- `/resume <file_id>`: chiama `node.resume_file(active_peer, file_id)`.
  Richiede peer attivo.

### Web API

- `POST /api/files/{file_id}/resume` con body `{peer_id}`.

### Test

`tests/test_file_resume.py`:
- Unit: `IncomingFile.received_indices()` correttezza.
- E2E:
  - test_resume_skips_received_chunks: B riceve manualmente
    chunk 0 e 2; A invia file_offer + ottiene file_resume; A
    invia solo chunk 1 e 3; B completa.
  - test_resume_without_existing_offer: B non ha incoming; A
    proceed normally.

## Versioning

Minor 0.7.1 → **0.8.0**. Marker: feature additiva, backward-
compatible al wire ma minor-bump per nuova capability significativa.

## Out of scope

- Persistenza receiver-side cross-process-restart.
- Resume su gruppi (Phase 5).
- Notifica progress in real-time.
