# Iter 019 — Next-target selection

## Stato post 018

9 patch release nel loop autonomo. Codebase v0.3.4 con:
- replay protection
- secrets-based circuit
- jitter reconnect
- monotonic TTL
- ruff + mypy CI
- file transfer (core + CLI + docs)
- SecureBytes per Argon2 seed
- Hypothesis fuzz su 4 parser

## Selezione iter-020

Priorità: continuare a aumentare quality/eng senza prendere decisioni
sostanziali di feature design (che richiedono visione utente).

Opzioni:

| ID | Topic | Effort | Tipo | Visibility |
|----|-------|--------|------|------------|
| Q1 | pytest --cov gate ≥80% in CI | S | quality infra | basso |
| Q2 | bandit / semgrep static security scan in CI | S | security infra | basso |
| Q3 | Estendere mypy strict bucket a `node.py` | M | quality | basso |
| Q4 | CodeQL workflow (dispatcher GitHub) | XS | infra | medio |
| Q5 | Dependabot config | XS | infra | basso |
| F1 | Web API endpoints `/api/files/*` | M | feature | alto |
| F2 | Argon2 per-user salt (B2 from iter-001) | M | security | medio |
| F3 | BIP39 backup mnemonic | M | feature | medio |

**Scelgo Q1 + Q2 come bundle**: coverage gate + security static scan.
Sono entrambi piccoli, il bundle ne fa un singolo iter consistente,
e completa il quartetto di CI gates (lint + types + tests + coverage + security).

## Acceptance criteria iter-020

- pytest-cov aggiunto a dev deps.
- `pyproject.toml` `[tool.coverage.*]` configurato (omit venv/tests).
- CI `test` step esegue `pytest --cov=malphas --cov-fail-under=70`.
  Threshold inizial 70% (poi alziamo).
- Step CI `security-scan` con `bandit -r src/` e `pip-audit` — entrambi
  warn-only nella prima iterazione, da promuovere a blocking dopo.
- Documentato il backlog `bandit` ignorato (presumibilmente con rationale
  simile a ruff S-codes).

## Versioning

Patch 0.3.4 → 0.3.5 (eng infra).
