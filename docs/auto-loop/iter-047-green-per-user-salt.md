# Iter 047 — Green: Argon2 per-user salt (v0.7.0, WIRE-BREAKING)

## Cosa è stato fatto

### `src/malphas/salt_store.py` (nuovo)

`load_or_create_salt(path: Path) -> bytes`:
- Se `path` esiste come file da 16 byte → leggi.
- Altrimenti → mkdir parent, `secrets.token_bytes(16)`, write atomic
  via `*.salt-tmp` + `os.replace()`, mode 0600 (`O_EXCL | O_CREAT`).
- Errori: file con lunghezza sbagliata o `path` directory →
  `ValueError`.

### `src/malphas/identity.py`

- `_derive_seed(passphrase, salt=None)` — accetta salt opzionale,
  fallback a `_ARGON2_SALT_LEGACY` (vecchio constant) se None.
- `create_identity(passphrase, salt=None)` e
  `create_identity_with_book_key(passphrase, salt=None)` — propagano.
- Validation: salt deve essere esattamente 16 byte, altrimenti
  `ValueError`.

### `src/malphas/__main__.py`

- Default: `~/.malphas/salt`.
- Flag `--salt <path>` per override (utility per multi-identity setups).
- Sia `_run_cli` sia `_run_web` fanno `load_or_create_salt(args.salt)`
  prima di derivare l'identità.

### Test

`tests/test_salt_store.py` (8 unit):
- creates_when_missing
- creates_parent_dir
- reads_existing_unchanged
- two_calls_at_fresh_paths_differ
- file_mode_0600
- wrong_length_raises
- path_is_directory_raises
- no_tmp_leftover

E2E + identity tests: 89/89 verde post-cambio (i test pre-esistenti
usano `create_identity("...")` senza salt → fallback legacy → identità
deterministica per i test).

## Threat model

README aggiornato:
- "Protected against" — Rainbow tables across users.
- "Not protected against" — Loss of `~/.malphas/salt`.

## Compatibility note

Wire-breaking semantico: anche con la stessa passphrase, due install
diversi (con salt diversi) producono identità diverse. Migrazione di
un'identità tra macchine richiede di copiare `~/.malphas/salt` (oppure,
da Phase 3, restore via BIP39 mnemonic).

## Versioning

Minor 0.6.0 → **0.7.0**. CHANGELOG con marker WIRE-BREAKING.

## Closes

Iter-001 finding **B2** (Argon2 salt fisso pubblico).

## Bucket strict mypy

16 moduli ora: replay, crypto, memory, obfuscation, pinstore, invite,
files, secure_buffer, discovery, receipts, ratchet, identity, onion,
addressbook, sealed_sender, **salt_store**.
