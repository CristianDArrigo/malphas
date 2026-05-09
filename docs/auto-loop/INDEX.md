# Auto-Loop Development Log

> **Tornando dal lavoro?** Leggi prima [`SUMMARY.md`](SUMMARY.md) — è
> un overview di tutta la sessione autonoma in 2 minuti, mappa
> iter→version→topic, sezione "cosa NON è stato toccato" e
> suggerimenti per la prossima sessione.

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
| 021 | iter-021-next-target.md | Next-target (Web API for file transfer) | done |
| 022 | iter-022-green-api-files.md | Green: Web API for file transfer | done |
| 023 | iter-023-next-target.md | Next-target (README consolidation 0.3.x) | done |
| 024 | iter-024-green-readme-consolidation.md | Green: README consolidation 0.3.x | done |
| 025 | iter-025-next-target.md | Next-target (0.4.0 line: auth-type prefix) | done |
| 026 | iter-026-green-auth-prefix.md | Green: auth-type prefix (v0.4.0, wire-breaking) | done |
| 027 | iter-027-next-target.md | Next-target (BLAKE2s peer_id → v0.5.0) | done |
| 028 | iter-028-green-blake2s-peerid.md | Green: BLAKE2s peer_id (v0.5.0, wire-breaking) | done |
| 029 | iter-029-next-target.md | Next-target (mypy strict bucket extension) | done |
| 030 | iter-030-green-mypy-bucket.md | Green: mypy strict — discovery/receipts/ratchet | done |
| 031 | iter-031-next-target.md | Next-target (mypy strict — identity/onion/addressbook) | done |
| 032 | iter-032-green-mypy-bucket-14.md | Green: mypy strict bucket → 14 modules | done |
| 033 | iter-033-next-target.md | Next-target (scripts/check.sh local mirror of CI) | done |
| 034 | iter-034-green-check-script.md | Green: scripts/check.sh local CI mirror | done |
| 035 | iter-035-next-target.md | Next-target (single SoT for strict bucket) | done |
| 036 | iter-036-green-mypy-sot.md | Green: single source of truth — mypy strict bucket | done |
| 037 | iter-037-next-target.md | Next-target (cumulative SUMMARY.md) | done |
| 038 | iter-038-green-summary.md | Green: cumulative SUMMARY.md | done |
| 040 | iter-040-green-dependabot-precommit.md | Green: dependabot + pre-commit | done |
| 042 | iter-042-green-version-pytype.md | Green: __version__ + --version + py.typed | done |
| 044 | iter-044-green-contributor-templates.md | Green: CONTRIBUTING + PR template + issue templates | done |
| 045 | iter-045-roadmap.md | Roadmap: 6 phase user-driven (post hand-off) | done |
| 046a | iter-046-plan-sealed-sender.md | Plan: sealed sender (v0.6.0 WIRE-BREAKING) | done |
| 046b | iter-046-green-sealed-sender.md | Green: sealed sender (v0.6.0 WIRE-BREAKING) | done |
| 047a | iter-047-plan-per-user-salt.md | Plan: per-user Argon2 salt (v0.7.0 WIRE-BREAKING) | done |
| 047b | iter-047-green-per-user-salt.md | Green: per-user Argon2 salt (v0.7.0 WIRE-BREAKING) | done |
