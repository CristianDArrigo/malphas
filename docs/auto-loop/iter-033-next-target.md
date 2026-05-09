# Iter 033 — Next-target selection

## Stato post 032

16 release. mypy strict bucket: 14/19 moduli (73.7%, ~52% stmt).
Suite focalizzata 244+ verde. CI gate stack stabile a 5 stadi.

## Scelta iter-034

Riconoscimento: stiamo entrando nel territorio dei "valore decrescente"
con iter di mypy bucket consecutive. Cambio asse.

Opzioni:

| ID | Topic | Effort | Tipo |
|----|-------|--------|------|
| Op1 | scripts/check.sh — local mirror del CI gate stack | XS | dev infra |
| Op2 | refactor node.py: extract send-path helpers | M | quality |
| F6 | BIP39 backup mnemonic | M | feature |
| W4 | sealed sender (wire-breaking) | M | security |
| W5 | Argon2 per-user salt (semi-breaking) | M | security |

**Scelgo Op1 — scripts/check.sh**.

Motivi:
- Effort minimo, alto valore quotidiano: oggi per replicare la CI in
  locale si invocano 4 comandi separati (`ruff check`, `mypy <14
  files>`, `bandit -r src/ -c pyproject.toml -l`, `pytest --cov`).
  Un singolo `./scripts/check.sh` è quello che il dev humano farebbe
  pre-commit.
- Allinea il workflow locale con il CI senza divergenza.
- Self-contained, niente decisioni di feature/threat-model.

## Acceptance criteria iter-034

- `scripts/check.sh` esiste, è eseguibile (`chmod +x`).
- Esegue, in ordine e fail-fast:
  1. `ruff check src/ tests/`
  2. `mypy <strict bucket files>` (lista presa dinamicamente da
     pyproject.toml o hardcoded come nel CI workflow).
  3. `bandit -r src/malphas/ -c pyproject.toml -l`
  4. `pytest tests/ -m "not tor and not slow" --cov-fail-under=65`
- Stamp di ogni stage con header colorato (es. `===> ruff check`).
- Se invocato con `--quick` salta solo lo step pytest (utile pre-commit).
- README "Development" subsection aggiornata con riferimento allo script.

Versioning: 0.5.2 → 0.5.3 (dev infra).
