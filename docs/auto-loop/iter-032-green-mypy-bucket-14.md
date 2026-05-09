# Iter 032 — Green: mypy strict bucket → 14 modules

## Cosa è stato fatto

Bucket strict 11 → 14. Aggiunti:

- `malphas.identity`
- `malphas.onion`
- `malphas.addressbook`

### `addressbook.py` — 2 fix

- `Contact.to_dict() -> dict[str, Any]` (era `dict`).
- `Contact.from_dict(d: dict[str, Any])` (era `dict`).
- Import `from typing import Any`.

### `identity.py` — 1 fix

- `create_identity_with_book_key(passphrase: str) -> tuple[Identity, bytes]`
  (era `tuple` senza parametri).

### `onion.py` — 0 fix

Già pulito sotto strict.

## Verifica

- `mypy --strict` su 14 moduli: Success.
- 111 focused test verdi.
- ruff: clean. bandit: 0 findings.

## Versioning

Patch 0.5.1 → 0.5.2.

## Bucket strict ora (14 moduli)

| Module | Stmt approx |
|--------|-------------|
| replay | 44 |
| crypto | 61 |
| memory | 55 |
| obfuscation | 64 |
| pinstore | 52 |
| invite | 44 |
| files | 122 |
| secure_buffer | 100 |
| discovery | 119 |
| receipts | 82 |
| ratchet | 88 |
| identity | 68 |
| onion | 44 |
| addressbook | 111 |

Totale ~1054 stmt sotto strict.

## Out of strict bucket (5 moduli)

- `node.py` — 660+ stmt; richiede annotation work massiva (callbacks, asyncio.Task generics, dict[str, Any] in vari posti).
- `transport.py` — dipende da `stem` con stub incompleti.
- `api.py` — FastAPI decorators + Pydantic inner classes hanno tricks.
- `cli_ui.py` — 700+ stmt, prompt_toolkit sub-types.
- `__main__.py` — argparse boilerplate.
- `splash.py` — banale, ma inutile farlo strict.

Strict coverage: 14/19 = 73.7% dei moduli. ~1054/2000 stmt = 52% delle
righe di src strict-checked.
