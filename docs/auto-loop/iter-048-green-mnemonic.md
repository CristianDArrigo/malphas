# Iter 048 — Green: BIP39 12-word mnemonic (v0.7.1)

## Cosa è stato fatto

### `src/malphas/mnemonic.py` (nuovo)

```python
salt_to_mnemonic(salt: bytes) -> str    # 16 bytes → 12 words
mnemonic_to_salt(words: str) -> bytes   # 12 words → 16 bytes
```

- Backed by `mnemonic>=0.20` (Trezor python-mnemonic).
- English wordlist, 2048 parole.
- Valida word count (deve essere 12), checksum BIP39 (4 bit derivati
  via SHA-256), parole appartenenti alla wordlist.
- Tollera whitespace extra (`" ".join(words.split())`).
- Vector noto: `b"\x00" * 16` → `"abandon × 11 + about"`.

### Integrazione `__main__.py`

- Nuovo flag `--from-mnemonic "<12 words>"`. Decodifica → salt;
  scrive in `args.salt` se assente, **rifiuta** se esiste con valore
  diverso (fail-loud per evitare di sostituire un'identità esistente).
- Helper `_resolve_salt(args)` rimpiazza `load_or_create_salt(args.salt)`:
  - Stessa semantica del v0.7.0 quando `--from-mnemonic` non è
    passato.
  - Sul "fresh generation" (path non esisteva prima della call),
    stampa la mnemonic con un box visivo di warning.

### Integrazione `cli_ui.py`

- `MalphasCLI.__init__` accetta `salt_path: Path | None = None`.
- Nuovo command `/backup`: rilegge il file salt, decodifica in
  mnemonic, stampa le 12 parole numerate.
- Tab completion include `/backup`.

### Test

`tests/test_mnemonic.py` (9 test):
- BIP39 zero-entropy known vector
- roundtrip 20 random salts
- word count = 12
- wrong salt length raises
- wrong word count raises
- bad checksum raises
- word not in wordlist raises
- whitespace tolerance
- exact-12 boundary (11 / 13 → ValueError)

E2E smoke: roundtrip salt → words → salt verificato out-of-test.

Suite focalizzata: 59/59 verde.

### CI

- `mnemonic>=0.20` aggiunto a `dependencies` in `pyproject.toml`.
- Strict bucket esteso: 17 moduli (aggiunto `malphas.mnemonic`).

### Threat model

README "Not protected against":
- "Loss of `~/.malphas/salt`" → riformulato come "Loss of
  `~/.malphas/salt` AND of the BIP39 backup".

## Versioning

Patch 0.7.0 → **0.7.1**. Non wire-breaking — feature additiva
puramente user-facing. Un peer 0.7.1 e uno 0.7.0 con stesso
salt+passphrase interoperano regolarmente.

## Closes

Phase 3 della roadmap user-driven. Chiude (parzialmente) il rischio
"Loss of ~/.malphas/salt" introdotto in Phase 2 con un meccanismo di
recovery user-managed.
