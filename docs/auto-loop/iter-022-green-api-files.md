# Iter 022 — Green: Web API endpoints `/api/files/*`

## Cosa è stato fatto

### `src/malphas/api.py`

5 nuovi endpoint REST + 2 nuovi WebSocket push events:

- `POST /api/files/send` (multipart) — riceve `peer_id` e `file`
  (UploadFile), salva su tempfile, chiama `node.send_file`, ritorna
  `{file_id}`. 404 se peer sconosciuto, 400 se peer_id malformato,
  503 se `send_file` ritorna None.
- `GET /api/files` — JSON `{pending: [...], completed: [...]}` con
  metadata (peer source, name, size).
- `POST /api/files/accept` (Body json) — registra l'incoming offer
  cercata via WS, chiama `node.accept_file_offer`, rimuove dal pending.
- `POST /api/files/reject` (Body json) — droppa pending offer.
- `GET /api/files/{file_id}/download` — Response con
  `application/octet-stream` + `Content-Disposition`, dropa la copia
  RAM dopo l'invio (single-shot, coerente con la zero-disk policy).

### Stato in-process

Due dict in `create_app`:
- `pending_offers: dict[str, tuple[str, dict]]` — file_id → (from_id, offer).
- `completed_files: dict[str, tuple[str, str, bytes]]` — file_id → (from_id, name, data).

Wire callbacks su `node.on_file_offer` e `node.on_file_complete` →
update state + push WebSocket. Identica logica di `MalphasCLI._on_file_*`.

### WebSocket extension

Helper `_ws_broadcast(message: dict)` per send_json a tutti i client
connessi, con eviction dei dead. I tre push:

- `{type: "message", from, content}` (esistente).
- `{type: "file_offer", from, offer}` (nuovo).
- `{type: "file_complete", file_id, from, name, size}` (nuovo).

### Sanitizzazione filename download

Per evitare directory-traversal o iniezioni nel `Content-Disposition`:

```python
safe_name = re.sub(r"[^A-Za-z0-9._\-]", "_", name)[:128] or "file.bin"
```

Test `test_filename_is_sanitized` verifica che `../etc/passwd` non
sopravvive con `/` nel header.

### Validation: `FileIdRequest`

Pydantic BaseModel con `field_validator` che accetta `[0-9a-f]{16,64}`
(prefix tronchi compatibili con CLI display + full hex 32-char dei
file_id reali).

### Bug encountered & fixed: `from __future__ import annotations`

L'header di `api.py` aveva `from __future__ import annotations` che fa
diventare ogni annotation una stringa forward-ref. Pydantic v2 non
sa risolvere forward-ref per classi nidificate dentro `create_app`,
e gli endpoint Body fallivano con `PydanticUserError`. Rimosso. Le
classi `ConnectRequest` / `SendRequest` esistenti funzionavano già
perché il file originale non aveva il future-import.

### Runtime deps

Aggiunto `python-multipart>=0.0.9` per supporto `UploadFile` /
`Form` di FastAPI.

## Test

`tests/test_api_files.py` — 14 test, tutti verdi in 1.01 s:

- 4 `TestFilesSend`: peer sconosciuto 404, peer_id malformato 400,
  call to send_file con bytes corretti, send_file → None → 503.
- 2 `TestFilesList`: lista vuota, dopo offer pending appare.
- 4 `TestAcceptReject`: 404 su id sconosciuto, accept registra,
  reject droppa, simmetrici.
- 4 `TestDownload`: 404 sconosciuto, 400 malformato, payload corretto
  + drop dopo download (404 al secondo round), filename sanitizzato.

Suite `test_api.py` (91 test) invariata: 91/91 verde.

## Eng quality

- ruff: All checks passed.
- bandit: 0 findings.
- mypy strict bucket invariato (api.py non è nel bucket).

## Versioning

Patch 0.3.5 → 0.3.6.
