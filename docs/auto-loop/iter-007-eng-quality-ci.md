# Iter 007 — Engineering Quality CI: ruff

## Cosa è stato fatto

### Configurazione `pyproject.toml`

- Aggiunta `ruff>=0.7` alle dev deps.
- Sezione `[tool.ruff]`: `line-length = 100`, `target-version = "py310"`, esclusi `.venv`, `venv`, `frontend/showcase`.
- `[tool.ruff.lint]`: select conservativo `E/F/I/B/UP/S`.
- Ignore esplicito sul backlog triagato (vedi sotto). Ogni rule ignorata ha rationale documentato.
- `per-file-ignores` per `tests/*`: `S101/S105/S106` (assert e secrets in test).

### Auto-fix sicuri applicati

223 issue auto-fixate dalle rule `F401`, `F541`, `F841`, `I001`, `UP006`, `UP045`, `UP035`, `UP037`, `E401`, `E701`. Nessuna regressione (test microfix + replay rimasti verdi).

I cambi sono prevalentemente:
- typing: `Dict[K,V]` → `dict[K,V]`, `Optional[T]` → `T | None`, `List[T]` → `list[T]`, `Tuple[…]` → `tuple[…]`
- import sort
- rimozione import/var inutilizzati

### Backlog ignorato (con rationale)

| Rule | Reason |
|------|--------|
| S110 | try-except-pass è una scelta di design fail-closed (drop silenzioso degli errori di rete) |
| S324 | SHA1 come identificatore non security-critical (B1 in iter-001, già tracciato per v0.3) |
| S603 | subprocess in `transport.py` per setup HS Tor; gli argomenti sono costanti / path interni controllati |
| S104 | bind 0.0.0.0 — necessario per LAN/Tor inbound |
| S108/S306 | path /tmp per staging file chiavi HS, ripuliti subito |
| S112 | try/except/continue sull'eviction stale-peer |
| B017/B904/B905/B007/B011/B023 | catch generici e pattern voluti in test/handler errori |
| F841/F401/E402/E701 | residui che richiedono review caso per caso (cli_ui usa late import per evitare side effects) |

### Workflow CI

`.github/workflows/ci.yml` ora ha **due job paralleli**:

1. `lint` — Python 3.12 + `ruff check src/ tests/` (BLOCKING, no `continue-on-error`).
2. `test` — la matrice 3.10–3.13 invariata.

## Verifica locale

```
$ .venv/bin/ruff check src/ tests/
All checks passed!
```

## File touchati (sommario)

- Nuovo/aggiornato: `pyproject.toml`, `.github/workflows/ci.yml`
- Auto-fix da ruff su: `src/malphas/*.py`, `tests/*.py` (~20 file)

## Versioning

Patch 0.2.2 → 0.2.3 (no API/wire change, solo eng).
