# Iter 034 — Green: scripts/check.sh local CI mirror

## Cosa è stato fatto

### `scripts/check.sh`

Wrapper bash unico che esegue il CI gate stack in locale:

1. `ruff check src/ tests/`
2. `mypy --strict <14 strict bucket files>`
3. `bandit -r src/malphas/ -c pyproject.toml -l`
4. `pytest tests/ -m "not tor and not slow" --cov --cov-fail-under=65`

Caratteristiche:
- Fail-fast: il primo gate che fallisce termina lo script.
- Output con header colorato (cyan), check verdi, fail rossi.
  Si degrada a no-color quando `stdout` non è un tty (CI logs, pipes).
- Risolve l'interprete Python tramite priorità:
  1. `$PYTHON` env var, se settato.
  2. `./.venv/bin/python` se esiste ed è eseguibile.
  3. `python3` o `python` da PATH.
- Flag:
  - `--quick` — skip step 4 (pytest). Pensato per pre-commit hooks.
  - `--no-coverage` — pytest senza `--cov-fail-under` per iterazioni
    rapide su singoli test.
  - `-h` / `--help` — stampa la prima parte del docstring del file.
- Bucket strict hardcoded come array bash, sincronizzato con
  `.github/workflows/ci.yml`. Comment con nota di "kept in sync".

### `README.md`

- "CI quality gates" subsection aggiornata: cita lo script come
  primary entrypoint.
- Lista completa dei 14 moduli nel bucket strict (era 8 nel testo
  pre-iter-030).

### Verifica

```
$ scripts/check.sh --quick
===> ruff check src/ tests/
✓ ruff clean
===> mypy --strict (14 modules)
✓ mypy strict bucket clean
===> bandit -r src/malphas/ -c pyproject.toml -l
✓ bandit 0 findings
(skipping pytest — --quick)
✓ all enabled gates passed
```

## Versioning

Patch 0.5.2 → 0.5.3 (dev infra).

## Drift hazard

Il bucket strict è hardcoded in due punti:
- `.github/workflows/ci.yml` (CI)
- `scripts/check.sh` (locale)

Più `pyproject.toml` `[[tool.mypy.overrides]]` per la inferenza implicita.
La drift può accadere quando un'iter aggiunge un modulo al
pyproject ma dimentica i due files yml/sh. Mitigation futura: estrarre
la lista in un file `mypy_strict.txt` e leggerlo da entrambi.
Tracciato per iter futura — non urgente.
