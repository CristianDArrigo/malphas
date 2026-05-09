# Iter 024 — Green: README consolidation 0.3.x

## Cosa è stato fatto

Allineato il README con tutto il lavoro 0.3.x prima di chiudere la
mini-release e aprire 0.4.0.

### Threat Model

- "Protected against" amplia con due voci nuove:
  - Replay attacks application-layer (sliding window per
    (from_peer_id, msg_id), drop silenzioso del replay).
  - Argon2 seed in swap (SecureBytes mlock'd best-effort + zeroize).
- "Not protected against" qualifica la voce RAM: `mlock` copre solo
  il seed, solo contro swap; `/proc/$pid/mem` legge tutto.

### CI quality gates (nuova subsection)

Tabella con i 5 gate (ruff, mypy --strict, bandit, pytest --cov,
hypothesis), file di config corrispondente, cosa intercettano.
Lista dei moduli nel bucket strict mypy. Cheatsheet di invocazione
locale.

### Web API endpoints (nuova subsection)

Tabella con tutti i 9 REST + WebSocket /ws e i 3 push event types.
Nota sul CORS localhost-only e sul fatto che CLI vs Web sono
mutually-exclusive surface entrypoints.

### Test suite

Tabella estesa con 7 nuove righe per i file aggiunti durante il loop:
test_replay_protection (14), test_microfixes (5), test_files (14),
test_cli_files (12), test_api_files (14), test_secure_buffer (13),
test_fuzz_parsers (8). Totale 80 nuovi test rispetto al README
pre-loop.

### Project structure

Aggiunte 3 righe per i nuovi moduli: `replay.py`, `files.py`,
`secure_buffer.py`.

## Versioning

Patch 0.3.6 → 0.3.7 (docs only). Chiude la mini-release 0.3.x.
Prossima minor v0.4.0 raccoglierà i wire-breaking changes
(sealed sender, session_id prefix, BLAKE2 peer_id).

## File toccati

- `README.md`
- `CHANGELOG.md`
- `pyproject.toml`
- `docs/auto-loop/INDEX.md`
- `docs/auto-loop/iter-024-green-readme-consolidation.md` (questo)

Nessun cambio di codice. Suite test invariata.
