# Iter 021 — Next-target selection

## Stato post 020

10 patch release nel loop. CI gate stack completo: ruff + mypy + bandit
+ coverage. Suite focalizzata 255 test verdi.

## Selezione iter-022

**Web API endpoints `/api/files/*`** per esporre file transfer al lato
HTTP/PWA, simmetrici ai comandi CLI introdotti in iter-012.

Motivazioni:
- L'API Web esiste già (`api.py`) ma non espone niente per file.
- Rende il modulo `files.py` accessibile a futuri client web/PWA/scriptbots.
- Effort M, valore M. Estensione naturale.
- Self-contained (non tocca wire format, non rompe nessuna API).

## Acceptance criteria iter-022

- `POST /api/files/send` — body multipart `peer_id`, `file` (UploadFile).
  Salva temp, chiama `node.send_file`, ritorna `file_id`.
- `GET /api/files` — JSON `{pending: [...], completed: [...]}`.
- `POST /api/files/accept` — body `{file_id}`. Cerca tra le offer
  ricevute via WS, registra incoming.
- `POST /api/files/reject` — body `{file_id}`. Droppa.
- `GET /api/files/{file_id}/download` — stream bytes del file completato.
  Dopo download, droppa la copia in RAM (zero-disk policy).
- WebSocket: aggiungere push events `{type: "file_offer", from, offer}`
  e `{type: "file_complete", file_id, name, size}`.
- Test `tests/test_api_files.py`: usa httpx + FastAPI TestClient su un
  node fittizio.

## Considerazioni

- Lato API state pari a CLI: `_pending_offers`, `_completed_files` per
  process. Con un single-instance API è ok; per multi-process dovrebbe
  vivere nel node, ma il node è single-process per design (coerente con
  la threat model).
- L'AppState va nel `create_app(node, static_dir)` con un dict accessibile
  da tutti gli endpoint. Wire `node.on_file_offer` a un callback che fa
  push WebSocket + memorizza offer pending.

## Versioning

Minor 0.3.5 → 0.4.0? No: niente wire-breaking. Patch 0.3.5 → 0.3.6.
