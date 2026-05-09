# Auto-Loop Development Log

Ricorsivo loop autonomo: review → plan → TDD → implement → repeat.

Operatore: Claude (modalità auto, opus 4.7).
Repository: malphas (privacy-first P2P messenger).

## Convenzioni

- Ogni iterazione produce un file `iter-NNN-<phase>.md` con: contesto, decisioni, motivo, output, test.
- Le iterazioni vanno in ordine cronologico, anche tra rami logici diversi.
- Ogni cambio di codice è preceduto da test fail-first; ciò che non è testabile in unit/integration test è "garantito" tramite review manuale documentata.
- Commit per ogni iterazione completata (review/plan/red/green sono separabili).

## Fasi del progetto al T0

- v0.2.0 in `pyproject.toml`.
- Stack: Python 3.10+, FastAPI, prompt_toolkit, cryptography, stem, argon2-cffi.
- Test ~7k linee (~70% del totale). CI base (pytest matrix 3.10–3.13).
- Nessun mypy, ruff, coverage gate, semgrep. No GUI vera. No group chat. No file transfer.

## Iterazioni

| # | File | Topic | Stato |
|---|------|-------|-------|
| 001 | iter-001-review.md | Review comportamentale/semantica/sintattica | done |
| 002 | iter-002-plan-replay-protection.md | Piano: replay protection | done |
| 003 | iter-003-red-replay-protection.md | TDD red: failing tests | done |
| 004 | iter-004-green-replay-protection.md | TDD green: implementation | done |
| 005 | iter-005-next-target.md | Next target selection | done |
| 006a | iter-006-plan-microfixes.md | Plan: micro-fix batch | done |
| 006b | iter-006-green-microfixes.md | Green: micro-fix batch | done |
| 007 | iter-007-eng-quality-ci.md | Eng quality: ruff CI + auto-fix | done |
| 008a | iter-008-plan-mypy.md | Plan: mypy strict gradual rollout | done |
| 008b | iter-008-green-mypy.md | Green: mypy strict bucket | done |
| 009 | iter-009-next-target.md | Next-target selection (file transfer staged) | done |
| 010a | iter-010-plan-file-transfer.md | Plan: file transfer chunked | done |
| 010b | iter-010-green-file-transfer.md | Green: file transfer chunked | done |
| 011 | iter-011-next-target.md | Next-target selection (CLI commands) | done |
| 012 | iter-012-green-cli-files.md | Green: CLI commands for file transfer | done |
| 013 | iter-013-next-target.md | Next-target selection (README docs) | done |
| 014 | iter-014-green-readme.md | Green: README docs for file transfer | done |
| 015 | iter-015-next-target.md | Next-target selection (mlock + secure erase) | done |
| 016 | iter-016-green-secure-buffer.md | Green: SecureBytes (mlock + zeroize) | done |
| 017 | iter-017-next-target.md | Next-target selection (Hypothesis fuzz) | done |
| 018 | iter-018-green-fuzz.md | Green: Hypothesis fuzz on parsers | done |
| 019 | iter-019-next-target.md | Next-target (coverage gate + bandit) | done |
| 020 | iter-020-green-coverage-bandit.md | Green: coverage gate + bandit | done |
