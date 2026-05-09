# Iter 049 — Green: file transfer resume (v0.8.0)

## Cosa è stato fatto

### `src/malphas/files.py`

- Nuova `IncomingFile.received_indices() -> list[int]` — sorted view
  dei chunk_idx già ricevuti, usata dal receiver per popolare il
  resume signal.

### `src/malphas/node.py`

- Nuovo `KIND_FILE_RESUME = "file_resume"`.
- Stato per file_id sul sender: `_resume_signals: dict[str, set[int]]`
  + `_resume_events: dict[str, asyncio.Event]`.
- `_handle_file_offer`: se file_id è già in `_files._incoming` con
  buffer parziale, NON re-registra ma manda indietro `file_resume`
  con la lista degli idx ricevuti.
- `_handle_file_resume`: parsing safe (file_id str, received_idx
  list of int); ignora signals per file_id non in `_outgoing`;
  set Event corrispondente per sbloccare un eventuale send_file.
- `send_file(dest, path, file_id=None)`: arma un Event prima
  dell'offer; aspetta `wait_for(timeout=0.3)` un signal di resume;
  se arriva, durante chunkify skippa gli idx in skip set.
- Nuovo `resume_file(dest, file_id)` — API user-facing.
- `panic()` clears `_resume_signals` e set tutti gli `_resume_events`
  così le coroutine pending sblocano subito.
- `_dispatch_kind` aggiornato per `KIND_FILE_RESUME`.

### Tests

`tests/test_file_resume.py` (5 test):
- 2 unit su `IncomingFile.received_indices()`.
- 3 E2E:
  - resume after partial buffer (Bob ha 0 e 2; Alice manda solo 1 e 3).
  - resume_file con file_id sconosciuto → None.
  - panic durante un wait di resume → send_file completa promptly.

64/64 verde sull'aggregato (files + replay + microfixes +
sealed_sender + salt_store + mnemonic + file_resume).

ruff + mypy + bandit clean.

### Wire format

Backward-compatible:
- 0.7.x receiver non emette `file_resume` → 0.8.0 sender aspetta 0.3s
  poi manda full.
- 0.7.x sender non chiede resume → 0.8.0 receiver fa offer/chunk
  standard.

### Versioning

Minor 0.7.1 → **0.8.0**. CHANGELOG senza marker WIRE-BREAKING (è
backward-compatible) ma è un minor bump per la nuova capability
visibile.

## Out of scope (rimane)

- Persistenza receiver-side cross-process-restart (il `_incoming`
  è in RAM, una restart del receiver perde il partial buffer).
- Resume su gruppi (Phase 5).
- Notifica progress in real-time al sender / receiver.

## Bucket strict mypy

Invariato (17). `resume_file` e `_handle_file_resume` sono in
`node.py` che è in lenient bucket — l'integrazione di `node.py`
nello strict bucket resta out of scope per le ragioni note.
