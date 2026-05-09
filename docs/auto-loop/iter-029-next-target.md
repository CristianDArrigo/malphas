# Iter 029 — Next-target selection

## Stato post 028

14 release nel loop autonomo: 0.2.0 → 0.5.0. La linea 0.5.x è aperta;
2 wire-breaking step già fatti (auth-prefix, BLAKE2s peer_id).

## Selezione iter-030

Opzioni residuali wire-breaking:
- W2 session_id prefix in onion ciphertext (effort M)
- W4 sealed sender — cifra `from` field (effort M, sec impact alto)
- W5 Argon2 per-user salt (effort M)

Opzioni non-breaking:
- Q3 mypy strict bucket esteso a `discovery.py`, `receipts.py`,
  `ratchet.py` (effort S–M)
- F6 BIP39 backup mnemonic come opzione `--from-mnemonic` (effort M,
  feature)

**Scelgo Q3 — mypy strict bucket extension**.

Motivi:
- Pausa rispetto ai cambiamenti wire-breaking consecutivi (4 in 6 iter).
- Estende la sicurezza tipi a moduli stabili senza modificare
  comportamento.
- Effort prevedibile.
- Lascia all'utente la decisione su sealed sender / per-user salt
  (entrambi modificano sostanzialmente la threat model).

## Acceptance criteria iter-030

- `mypy --strict src/malphas/discovery.py src/malphas/receipts.py
  src/malphas/ratchet.py` esce 0.
- Aggiunti al bucket in `pyproject.toml` e nel CI workflow.
- Niente cambio di firma pubblica; solo annotation tightening + cast
  espliciti dove serve.
- Suite test invariata.

Versioning: 0.5.0 → 0.5.1 (eng quality, no API/wire change).

## Out of scope iter-030

- node.py — troppo grosso per un singolo iter, frammentato di
  callable e dataclass mutable. Pianificato per dopo.
- transport.py — dipende da `stem` con stub incompleti.
- cli_ui.py — interactive surface, accettiamo non-strict.
- api.py — `from __future__ import annotations` rimosso in iter-022,
  ma comunque richiede mypy nuance per FastAPI decorators.
