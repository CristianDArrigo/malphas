# Iter 027 — Next-target selection (v0.4.x line)

## Stato post 026

13 release nel loop autonomo: 0.2.0 → 0.4.0. Wire-breaking line aperta.

## Selezione iter-028

Prossimo nella linea 0.4.x. Rimangono:

- W2: session_id prefix in onion ciphertext (effort M)
- W3: BLAKE2s peer_id (effort S)
- W4: sealed sender (effort M, alta priorità)
- W5: Argon2 per-user salt (effort M)

**Scelgo W3 — BLAKE2s peer_id**.

Motivi:
- Tappa la bandiera rossa SHA1 (B1 in iter-001, bandit B324 ancora skipped).
- Il più semplice dei 4 — modifiche concentrate in `identity.py`.
- Peer_id resta hex 40-char (BLAKE2s digest_size=20 → 40 hex). I regex
  in api.py / cli_ui.py / wire format restano invariati.
- Wire-breaking ovviamente: peer_id derivato cambia su tutto il
  network.

## Acceptance criteria iter-028

- `identity.py:create_identity` e `create_identity_with_book_key`
  usano `hashlib.blake2s(ed_pub_bytes, digest_size=20).hexdigest()`
  invece di `hashlib.sha1(...).hexdigest()`.
- `peer_id_from_pubkey` aggiornato.
- Test `test_security_argon2_panic.test_not_sha1` aggiornato per
  asserire che il peer_id NON è il SHA1 (era già il caso).
- Aggiungere test `test_peer_id_uses_blake2s` esplicito.
- Rimuovere `B324` dagli skip in `[tool.bandit]`.
- Rimuovere `S324` dagli ignored di ruff.
- Aggiornare commenti: `# 40-char hex SHA1` → `# 40-char hex BLAKE2s`.
- Aggiornare docstring `identity.py`.
- Aggiornare README threat model section che parla di SHA1.

Versioning: 0.4.0 → 0.5.0 (minor bump per wire-breaking peer_id).

## Out of scope iter-028

- W2/W4/W5 — iter successive.
- Cambiare `discovery.ID_BITS = 160` — BLAKE2s con digest_size=20 = 160 bit, invariato.
- Cambiare `onion.PEER_ID_LEN = 20` — invariato.
