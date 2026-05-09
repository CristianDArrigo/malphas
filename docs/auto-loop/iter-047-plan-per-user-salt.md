# Iter 047 — Plan: Argon2 per-user salt (v0.7.0, WIRE-BREAKING)

## Problema (B2 da iter-001)

Oggi `_ARGON2_SALT = b"malphas-kdf-salt"` è hardcoded e identico per
ogni utente. Conseguenza: un attaccante può precomputare una rainbow
table contro questo unico salt e attaccare *tutti* gli utenti
malphas in parallelo. Non è il rischio principale (Argon2 è
memory-hard) ma è una bandiera rossa.

## Soluzione

Salt random 16-byte salvato in `~/.malphas/salt`.

- Al primo run, `malphas` genera 16 byte casuali, scrive in
  `~/.malphas/salt` mode 0600, usa il valore in Argon2.
- Run successivi rileggono lo stesso file → identità stabile.
- Senza il file, la passphrase produce un'identità diversa.

Trade-off: rompiamo la "pure passphrase = identity" promise. Mitigato
in Phase 3 dove la BIP39 mnemonic include sia la passphrase che il
salt come materiale recoverabile.

## Backward compatibility

Niente. Salt diverso → seed Argon2 diverso → keypair diversi → peer_id
diverso → wire format diverso semanticamente. Wire-breaking 0.7.0.

## Test compatibility

I test E2E e unit che usano `create_identity("alice")` dovrebbero
continuare a funzionare deterministicamente. Soluzione:
`create_identity(passphrase, salt=None)` con `salt=None` → fallback al
salt legacy `b"malphas-kdf-salt"`. La CLI passa esplicitamente il
salt letto da disco.

I test che si assicurano "stessa passphrase → stesso peer_id" continuano a
girare. Aggiungiamo nuovi test per:
- Stessa passphrase, salt diversi → identità diverse.
- File salt mancante → genera + scrive.
- File salt esistente → ricarica → stessa identità.
- Permessi 0600 sul file salt.

## Implementazione

### `identity.py`

- `_derive_seed(passphrase, salt=None)`: usa il fallback salt se
  `salt is None`, altrimenti usa quello passato.
- `create_identity(passphrase, salt=None)`: idem.
- `create_identity_with_book_key(passphrase, salt=None)`: idem.

### Nuovo modulo `malphas.salt_store`

- `load_or_create_salt(path: Path) -> bytes`:
  - Se `path` esiste: leggi, valida (deve essere esattamente 16 byte),
    ritorna.
  - Se non esiste: crea parent dir, genera 16 byte random, scrivi
    con mode 0600 (atomic via `.tmp` + rename), ritorna.
  - Errori: ValueError con messaggio chiaro (es. file corrotto).

### `__main__.py`

- Default salt path: `~/.malphas/salt`.
- Flag `--salt-path` per override (utility per setups multi-identity).
- Pre-passphrase: chiama `load_or_create_salt(args.salt)` e passa il
  byte string a `create_identity_with_book_key`.

### Threat model README

Aggiungere a "Protected against": "Rainbow tables across users — the
KDF salt is per-user random, not a global constant."

Aggiungere a "Not protected against": "Loss of `~/.malphas/salt` —
without the file (and without a BIP39 backup, see v0.7.x), the same
passphrase produces a fresh identity that no existing peer recognizes."

## Acceptance criteria

- [ ] `malphas.salt_store` con `load_or_create_salt(path)`.
- [ ] `_derive_seed(passphrase, salt=None)`, default fallback compat.
- [ ] `create_identity` e `create_identity_with_book_key` propagano
      `salt`.
- [ ] `__main__.py` legge `~/.malphas/salt` con `--salt-path`.
- [ ] File creato con mode 0600.
- [ ] Tutti i test E2E esistenti continuano a passare (usano fallback).
- [ ] Nuovi test su `salt_store` (≥4 unit).
- [ ] README threat model aggiornato.
- [ ] CHANGELOG `0.7.0` con marker WIRE-BREAKING.

## Versioning

Minor 0.6.0 → 0.7.0.
