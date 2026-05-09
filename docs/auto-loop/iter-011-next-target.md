# Iter 011 — Next-target selection

## Stato post 010

File transfer core completo. Quello che manca per essere usabile in pratica:

1. **CLI integration** — `/sendfile`, `/accept`, `/reject`, `/savefile`.
2. **Web API exposure** — endpoints REST per upload/download dal browser PWA.
3. **Progress UI** — feedback in CLI durante il transfer.
4. **Resume di transfer interrotti** — feature avanzata, posticipato.

## Decisione iter-012

Tier 1: **CLI commands** (iter-012). Effort S, valore alto perché senza CLI il modulo `files` esiste ma non si può usare interattivamente.

Tier 2: **Web API** (iter-013) — abilita la PWA mode, anche se la PWA stessa non è ancora una vera UI.

Tier 3: **Documentation** README + esempi (iter-014).

Tier 4: **Sealed sender** o **session_id prefix** (B7/A2) — wire-breaking, posticipato a 0.4.0.

## Acceptance per iter-012 (CLI commands)

- `/sendfile <peer|label> <path>` parsa argomenti, valida file, chiama `node.send_file`.
- `/accept <file_id>` accetta un'offerta pendente.
- `/reject <file_id>` cancella un'offerta pendente.
- `/savefile <file_id> <path>` salva su disco un file completato.
- `/files` lista i transfer in corso (incoming + outgoing) con progress.
- Messaggi UI quando arriva un'offerta: "*** offer from alice: photo.jpg (1.2 MB) — /accept abc123 or /reject abc123 ***".
- Messaggi UI quando un transfer completa: "*** received photo.jpg (1.2 MB) — /savefile abc123 ./photo.jpg ***".

## Test plan

`tests/test_cli_files.py`:
- Mock node.send_file e verifica che `/sendfile` parsa correttamente.
- Mock il flow on_file_offer e verifica che `/accept` registra incoming.
- `/savefile` scrive il payload corretto su disco.
- Edge: file_id sconosciuto → messaggio errore.

CLI in malphas è basato su prompt_toolkit + rich; testabile via mock di Console + injection di input.
