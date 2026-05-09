# Iter 030 — Green: mypy strict bucket extension

## Cosa è stato fatto

Bucket mypy strict esteso da 8 → 11 moduli. Aggiunti:

- `malphas.discovery`
- `malphas.receipts`
- `malphas.ratchet`

### `ratchet.py` — 6 errori risolti

Type checker non riusciva a dimostrare gli invarianti che il runtime
manteneva. Aggiunto:

- `__init__(self) -> None`.
- `assert self._dh_pub is not None` in `encrypt` (paired con `_send_chain_key`).
- `assert self._recv_chain_key is not None` in `decrypt` post-skip.
- `assert self._dh_priv is not None` e `assert self._root_key is not None` in `_dh_ratchet`.
- `assert self._remote_dh_pub is not None` in `_skip_messages`, con
  rebind a variabile locale per soddisfare il type narrowing.

### `receipts.py` — 11 errori risolti

- `Ed25519PrivateKey` / `Ed25519PublicKey` annotations sui parametri
  `ed25519_priv`/`ed25519_pub`/`sender_pub`.
- `ReceiptCallback = Callable[[str, str, bool], Any]` e
  `TimeoutCallback = Callable[[str, str], Any]` come alias.
- `__init__(self, ...) -> None`.
- `_task: asyncio.Task[None] | None`.
- `_maybe_call(self, cb, *args)` typed e no-op se `cb is None`.
- `sign_receipt` ritorno wrappato in `bytes(...)` per dichiarare il
  tipo (cryptography returns `bytes` ma typestub a volte è `Any`).

### `discovery.py` — 4 errori risolti

- `to_dict() -> dict[str, Any]` (era `dict`).
- `PeerDiscovery.all_peers() -> list[dict[str, Any]]`.
- `_mdns_task: asyncio.Task[None] | None` (era `asyncio.Task | None`).

## Configurazione

- `pyproject.toml` `[[tool.mypy.overrides]]` esteso.
- `.github/workflows/ci.yml` step `Mypy strict bucket` aggiornato
  con i 3 nuovi file.

## Verifica

- `mypy --strict <11 moduli>`: Success.
- 244 focused test verdi.
- ruff: All checks passed.
- bandit: 0 findings.

## Versioning

Patch 0.5.0 → 0.5.1.

## Bucket strict ora

| # | Module | LoC stmt approx |
|---|--------|-----------------|
| 1 | malphas.replay | 44 |
| 2 | malphas.crypto | 61 |
| 3 | malphas.memory | 55 |
| 4 | malphas.obfuscation | 64 |
| 5 | malphas.pinstore | 52 |
| 6 | malphas.invite | 44 |
| 7 | malphas.files | 122 |
| 8 | malphas.secure_buffer | 100 |
| 9 | malphas.discovery | 119 |
| 10 | malphas.receipts | 82 |
| 11 | malphas.ratchet | 88 |

Totale ~830 stmt sotto strict. Out of bucket: `node`, `transport`,
`api`, `cli_ui`, `__main__`, `splash`, `addressbook`, `identity`, `onion`.
Le ultime tre sono candidate naturali per la prossima estensione.
