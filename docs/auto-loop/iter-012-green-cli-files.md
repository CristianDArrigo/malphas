# Iter 012 — Green: CLI commands for file transfer

## Cosa è stato fatto

### Nuovi comandi in `cli_ui.py`

- `/sendfile <peer|label> <path>` — risolve target via address book o peer_id, valida path, chiama `node.send_file`. Stampa il `file_id` ritornato.
- `/accept <file_id>` — prende l'offerta dal `_pending_offers`, chiama `node.accept_file_offer(offer)` e rimuove dal pending.
- `/reject <file_id>` — droppa l'offerta dal pending.
- `/savefile <file_id> <path>` — scrive su disco i bytes assemblati (presi da `_completed_files`) e rimuove la copia in RAM (zero-disk per la coda interna).
- `/files` — Table rich con due sezioni: pending e ready.

### Stato UI nel CLI

Due dict introdotti in `MalphasCLI`:
- `_pending_offers: dict[str, tuple[str, dict]]` — file_id → (from_id, offer_dict).
- `_completed_files: dict[str, tuple[str, str, bytes]]` — file_id → (from_id, name, data).

### Callback wiring

- `_on_file_offer(from_id, offer)` registra in `_pending_offers` e stampa due righe colorate giallo con istruzioni `/accept` / `/reject`.
- `_on_file_complete(file_id, data)` muove l'entry da pending a completed, stampa due righe verdi con istruzione `/savefile`.

Entrambi registrati in `run()`:

```python
self.node.on_file_offer(self._on_file_offer)
self.node.on_file_complete(self._on_file_complete)
```

### Help + tab completion

- `_print_help()` esteso con i 5 nuovi comandi.
- `COMMANDS` lista (per tab completion) include `/sendfile`, `/accept`, `/reject`, `/savefile`, `/files`.

## Test

`tests/test_cli_files.py` (12 test):

- 4 `TestSendfile`: no-args errors, calls node.send_file con peer risolto, unknown target errors, missing file errors.
- 3 `TestAcceptReject`: accept unknown id errors, accept registers offer, reject drops pending.
- 2 `TestSavefile`: savefile writes bytes correttamente, unknown id errors.
- 1 `TestFilesList`: /files lista pending e completed.
- 2 `TestFileNotifications`: callback `_on_file_offer` registra pending, callback `_on_file_complete` registra completed.

Risultato: **12/12 PASSED in 0.11s**.

Suite estesa di non-regressione (test_cli + test_cli_files + test_files + test_replay + test_microfixes): **177/177 PASSED in 1m54s**.

## Eng quality

- ruff: All checks passed.
- mypy strict bucket (7 moduli): Success.

## Garanzie non testabili a unit

- L'integrazione real-time della UI con `prompt_toolkit` patch_stdout. Garantita tramite review manuale: `_plain` viene usato per le notifiche, coerente con `_on_message` e `_on_receipt`.
- L'esperienza utente delle stampe colorate. Garantita tramite review.

## Versioning

Patch 0.3.0 → 0.3.1 (no API/wire change, solo CLI features).
