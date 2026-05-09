# Iter 014 — Green: README docs for file transfer

## Cosa è stato fatto

### README

- Nuovo capitolo "File Transfer" tra "Read Receipts" e "Resilience".
  Contiene: introduzione (riusa pipeline esistente), constraints (RAM,
  100 MB, 32 KB, SHA-256), wire format extension, default policy
  (no auto-accept), quickstart Alice→Bob completo, sezione `/files`,
  e "What is not implemented".
- TOC aggiornato (16 → 22 voci, con "File Transfer" come 17).
- Architecture diagram esteso:
  - aggiunto `ReplayCache` come componente del NODE.
  - aggiunto `FileTransferManager` come componente del NODE.
  - annotato il jitter su `AutoReconnect`.
- CLI Reference esteso con i 5 comandi `/sendfile`, `/accept`,
  `/reject`, `/savefile`, `/files`.

### CHANGELOG

Entry `0.3.2` con dettagli.

### Versioning

Patch 0.3.1 → 0.3.2 (docs-only).

## Verifica

- `git diff README.md`: solo aggiunte e modifiche al diagramma + CLI ref.
- Nessun cambio di codice → suite test invariata, ruff/mypy invariate.

## Garanzie non testabili

- Coerenza tra README e behavior reale: garantita tramite review
  manuale incrociata con `cli_ui.py` (i comandi citati esistono),
  `files.py` (i constraints citati corrispondono alle costanti del
  modulo: `MAX_FILE_BYTES = 100 MB`, `CHUNK_SIZE = 32 KB`).

## Stato del file transfer mini-release

| Iter | Cosa | Versione |
|------|------|----------|
| 010  | Core `malphas.files` + node integration | 0.3.0 |
| 012  | CLI commands | 0.3.1 |
| 014  | README docs | 0.3.2 |

Mini-release file transfer chiusa. Prossima fase: Web API (iter-015) o
hardening crypto (sealed sender, session_id prefix → 0.4.0).
