# Iter 008 — Plan: mypy strict gradual rollout

## Obiettivo

Introdurre `mypy --strict` in CI in modo incrementale per evitare di pagare
tutto il debito di tipizzazione in una singola PR.

## Strategia

1. Aggiungere `mypy>=1.10` alle dev deps.
2. Sezione `[tool.mypy]` in `pyproject.toml`:
   - `python_version = "3.10"`
   - `strict = false` globale (so we don't break the world)
   - `[[tool.mypy.overrides]]` per modulo: i moduli "puliti" (nuovi/curati) hanno `strict = true`.
3. CI step `lint` esegue `mypy src/` (warn-only) + `mypy --strict src/malphas/replay.py src/malphas/crypto.py src/malphas/memory.py` (BLOCKING).
4. Iterazioni successive estendono il bucket strict.

## Bucket iniziale

- `src/malphas/replay.py` (nuovo, già pulito)
- `src/malphas/crypto.py` (puro, no I/O, type-friendly)
- `src/malphas/memory.py` (semplice)

## Out of scope

- node.py, cli_ui.py — troppo complessi, andrebbero refactorati prima.
- transport.py — dipende da `stem` che non ha stub completi.

## Acceptance criteria

- `mypy --strict src/malphas/replay.py src/malphas/crypto.py src/malphas/memory.py` esce 0 in locale.
- CI workflow esegue lo step e blocca su regressione.
- Nessun cambio comportamentale; solo annotazioni o cast espliciti.
