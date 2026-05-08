# Iter 008 — Green: mypy strict gradual rollout

## Cosa è stato fatto

### Configurazione `pyproject.toml`

- `mypy>=1.10` aggiunto alle dev deps.
- `[tool.mypy]`: `python_version = "3.10"`, `strict = false`, `ignore_missing_imports = true`, `warn_unused_ignores`, `warn_redundant_casts`, `exclude` su frontend/venv/build.
- `[[tool.mypy.overrides]]` con `strict = true` sui moduli nel bucket iniziale: `malphas.replay`, `malphas.crypto`, `malphas.memory`.

### Annotation fixups

7 errori risolti:

- `crypto.py:kdf_chain` — return type `tuple` → `tuple[bytes, bytes]`.
- `crypto.py:unpack_u16/unpack_u32` — wrapping con `int(...)` per la conversione esplicita (struct.unpack restituisce `Any`).
- `memory.py` — `dict` → `dict[str, deque[Message]]`, `list[dict]` → `list[dict[str, Any]]`, `to_dict() -> dict` → `dict[str, Any]`, `__init__` annotato `-> None`.

Nessun cambio comportamentale; solo annotazioni.

### CI workflow

Aggiunto step `Mypy strict bucket` nel job `lint`, blocking. Esegue `mypy src/malphas/replay.py src/malphas/crypto.py src/malphas/memory.py`.

## Verifica

```
$ .venv/bin/mypy --strict src/malphas/replay.py src/malphas/crypto.py src/malphas/memory.py
Success: no issues found in 3 source files
```

Test (suite parziale relevante): 70/70 PASSED.

## Bucket di strict expansion

Iterazioni successive del loop possono aggiungere ai prossimi bucket:

- 008b: `obfuscation.py`, `pinstore.py`, `invite.py` (semplici, no I/O complesso).
- 008c: `addressbook.py`, `discovery.py`, `receipts.py`.
- 008d: `ratchet.py` (dipende da `cryptography`, type stubs incompleti).
- 008e: `transport.py` (dipende da `stem` — può rimanere `strict = false` con override mirati).
- 008f: `node.py`, `cli_ui.py`, `api.py` — richiedono lavoro significativo.

## Versioning

Patch 0.2.3 → 0.2.4.
