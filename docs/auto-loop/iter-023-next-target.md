# Iter 023 — Next-target selection

## Stato post 022

11 patch release. Versioni 0.2.0 → 0.3.6.

CI gate stack completo: ruff + mypy strict (8 mod) + bandit + coverage (65%).
Test files: 17. Test count focused: 269+ (tutti gli strati).
Surface: CLI + Web API + WS push, simmetriche per messaging e file transfer.

## Selezione iter-024

Opzioni:

| ID | Topic | Effort | Tipo |
|----|-------|--------|------|
| D1 | README aggiornamento per CI gates + Web API file | XS | docs |
| F2 | Argon2 per-user salt | M | security |
| F3 | BIP39 backup mnemonic | M | feature |
| Q3 | mypy strict su `node.py` | L | quality |
| F4 | Resume di transfer interrotti | M | feature |
| F5 | Sealed sender (wire-breaking) | M | security → 0.4.0 |

**Scelgo D1** per consolidare 0.3.x prima di aprire 0.4.0:
- Effort minimo, valore alto.
- Allinea il README con quanto fatto in iter 020 e 022 (CI gates + Web API file).
- Buona pratica: chiudere la mini-release prima di aprirne un'altra.

iter-024 = README updates per:
- Sezione "Testing" (esiste già?) → menzionare ruff/mypy/bandit/coverage/hypothesis.
- Aggiungere blocchetto API HTTP `/api/files/*` nella sezione "API" (se esiste) o aggiungere subsection in "Architecture".
- Threat model aggiornato: replay protection, SecureBytes per Argon2 seed.

## iter-025+ outlook

Dopo iter-024 (chiusura 0.3.x), opening 0.4.0 con Tier 1: **F5 sealed sender**
o **F2 per-user salt**. Wire-breaking, quindi richiede roadmap doc.

Versioning iter-024: 0.3.6 → 0.3.7 (docs only).
