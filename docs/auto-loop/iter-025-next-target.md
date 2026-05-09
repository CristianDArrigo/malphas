# Iter 025 — Next-target selection (opens 0.4.0)

## Stato post 024

12 release patch nel loop. v0.3.x chiusa con README consolidation.

## Apertura 0.4.0 — wire-breaking changes

Le opzioni residue dal review iter-001 sono tutte wire-breaking. Le
raccolgo in una "0.4.x line" e procedo una alla volta.

| ID | Topic | Effort | Severity | Rationale |
|----|-------|--------|----------|-----------|
| W1 | auth-type prefix (1 byte: R/H/E) | S | M | tappa il trial JSON parsing in `_deliver`, side-channel B7 |
| W2 | session_id prefix in onion ciphertext | M | M | elimina trial-decrypt O(N) sui ratchet, A2 |
| W3 | BLAKE2s peer_id (sostituisce SHA1) | M | L | rimuove bandiera rossa B1 / bandit B324 |
| W4 | sealed sender (cifra field `from`) | M | H | nasconde sender se rotta una sessione |
| W5 | Argon2 per-user salt | M | M | rimuove rainbow table globale risk |

## Selezione iter-026

**W1 — auth-type prefix**.

Motivi:
- Più piccolo dei wire-breaking. Buon punto d'ingresso per la 0.4.0 line.
- Tappa un side-channel concreto (trial JSON parsing): l'attuale
  `_deliver` prova `json.loads(signed[32:])` e poi `signed[64:]` —
  un payload appositamente costruito potrebbe ingannare il parser.
- Riduce il trial-decrypt ratchet costo (anche se non lo elimina:
  il discriminatore tra connection diverse rimane O(N)).
- TDD-friendly: aggiorni il pack/unpack, aggiorni il test, deploy.

## Acceptance criteria iter-026

Wire format prima:

```
inner = (32B HMAC tag | 64B Ed25519 sig | b"R" + 40B header) || JSON
```

Wire format dopo:

```
inner = b"H" + 32B HMAC tag + JSON
inner = b"E" + 64B Ed25519 sig + JSON
inner = b"R" + 40B ratchet header + ciphertext
```

Cambi:
- `node._try_send` e `_try_send_payload`: emettono `b"H" + tag + payload` o `b"E" + sig + payload`. Il path ratchet già usa `b"R"`.
- `node._deliver`: rimuove il trial JSON parsing, dispatcha direttamente sul primo byte del payload deciphered.
- Test esistenti che ispezionano i bytes intermedi vanno rivisti (probabilmente solo `test_security_*` sull'onion / payload).

Versioning: 0.3.7 → 0.4.0 (minor bump perché wire-breaking).

CHANGELOG entry deve essere chiaro che 0.4.x non parla con 0.3.x.

## Out of scope iter-026

- W2/W3/W4/W5 — tracciate per iter successive nella linea 0.4.x.
- Compatibility shim: nessuno, è un cut-over hard.
