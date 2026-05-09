# Iter 028 — Green: BLAKE2s peer_id (v0.5.0, wire-breaking)

## Cosa è stato fatto

### `src/malphas/identity.py`

- Sostituito `hashlib.sha1(ed_pub_bytes).hexdigest()` con
  `hashlib.blake2s(ed_pub_bytes, digest_size=20).hexdigest()` in:
  - `create_identity` (1 site)
  - `create_identity_with_book_key` (1 site)
  - `peer_id_from_pubkey` helper
- Module docstring riscritto: ora cita BLAKE2s + nota sul fatto che
  storage formats / regex restano invariati.
- Comment field nella dataclass `Identity.peer_id` aggiornato.

### `src/malphas/discovery.py`, `src/malphas/onion.py`

- Commenti `# SHA1` → `# BLAKE2s digest_size=20`.
- Bit count `ID_BITS = 160` invariato (digest_size=20 = 160 bit).

### Bandit & Ruff config

- Rimosso `B324` da `[tool.bandit].skips` — il source non usa più SHA1.
- Rimosso `S324` da `[tool.ruff.lint].ignore`.
- I 2 test che misurano timing Argon2id usano `hashlib.sha1` come
  baseline non-security e portano `usedforsecurity=False` + `# noqa: S324`.

### Test

- Nuovo `test_security_argon2_panic.test_peer_id_is_blake2s_not_sha1`
  — regression guard che blocca un eventuale ritorno a SHA1.
- `test_security_identity.test_peer_id_is_sha1_of_ed25519_pubkey`
  rinominato a `test_peer_id_is_blake2s_of_ed25519_pubkey` con la
  nuova invariant.
- `test_security_argon2_panic.test_not_sha1` (sul SEED) aggiornato
  con `usedforsecurity=False` per il `hashlib.sha1` di confronto
  baseline (non viola la security policy: il valore non viene usato
  per nulla di security-relevant).
- README threat model + architecture diagram aggiornati.
- SECURITY.md "Known limitations" voce SHA1 → strikethrough con nota
  v0.5.0.

### Verifica

- 270 test focused passati post-cambio.
- ruff: All checks passed.
- bandit: 0 findings.

## Versioning

Minor 0.4.0 → **0.5.0**. Wire-breaking: il valore di peer_id cambia per
ogni utente. Un client 0.5.0 e un client 0.4.x derivano peer_id diversi
dalla stessa passphrase, quindi non si trovano nei rispettivi address
book. Migrazione: nuova passphrase o re-emission inviti.

## Prossimi target nella linea 0.5.x e oltre

- W2 session_id prefix in onion ciphertext
- W4 sealed sender (cifra `from`)
- W5 Argon2 per-user salt
