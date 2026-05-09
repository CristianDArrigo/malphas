# Iter 031 — Next-target selection

## Stato post 030

15 release. Bucket strict mypy a 11 moduli. CI gate stack stabile.

## Selezione iter-032

Continuo l'estensione del bucket strict a 3 moduli rimanenti
"semplici": `identity.py`, `onion.py`, `addressbook.py`.

Motivi:
- I tre moduli sono stabili, modificati raramente, e già in buono
  stato. Aggiungere strict gate previene regressioni future.
- Effort S–M.
- Nessuna decisione di feature/threat-model che richiederebbe consenso
  utente.
- Lascia `node.py`, `transport.py`, `api.py`, `cli_ui.py`, `__main__.py`
  come "out of strict bucket" — queste hanno integrazione asyncio /
  external libs che richiede mypy nuance e annotation work più ampio.

## Acceptance criteria iter-032

- `mypy --strict src/malphas/identity.py src/malphas/onion.py
  src/malphas/addressbook.py` esce 0.
- Aggiunti al bucket in `pyproject.toml` e nel CI.
- Niente cambio di firma pubblica; solo annotations.

Versioning: 0.5.1 → 0.5.2 (eng quality).
