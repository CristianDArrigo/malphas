# Iter 046 — Plan: sealed sender (v0.6.0, wire-breaking)

## Problema

Oggi il `from` field nel payload JSON è in chiaro post-decrypt. Un
attaccante che ottiene la session key di una connessione (per esempio
compromettendo un endpoint dopo aver registrato traffico) vede chi sta
parlando con chi nei messaggi catturati.

Inoltre, il primo hop di un onion circuit possiede un session-key
TCP layer 2 con il sender. Se quel relay venisse compromesso e
l'attaccante avesse già visto il payload onion-incapsulato, potrebbe
peelare la session-layer encryption e arrivare al payload interno.
Lo strato onion successivo è cifrato separatamente, ma il primo
"slot" del payload include i metadati che sopravvivono al peeling
finale — tra cui il `from`.

## Soluzione: sealed sender

Cifrare il `from` field con la chiave del **destinatario finale**,
non del peer di sessione. Solo il destinatario finale può
de-cifrarlo. Un attaccante che recupera session keys lungo la
strada vede solo bytes opachi al posto del `from`.

Schema:

```
sender produces:
    eph_priv, eph_pub = X25519 ephemeral
    shared = ECDH(eph_priv, dest.x25519_pub)
    from_key = HKDF(shared, salt=b"malphas-sealed-sender-v1",
                    info=b"from", length=32)
    sealed_from = ChaCha20-Poly1305(from_key, real_from_peer_id_bytes,
                                     aad=eph_pub)

payload JSON (changed fields):
    OLD: {"kind": "msg", "from": "<peer_id>", ...}
    NEW: {"kind": "msg",
          "from_eph": "<eph_pub hex>",
          "from_sealed": "<sealed_from b64>",
          ...}
    ("from" is removed; receiver fills it in after decrypt.)

receiver:
    shared = ECDH(my_x25519_priv, eph_pub)
    from_key = HKDF(...)
    real_from = ChaCha20-Poly1305-decrypt(from_key, sealed_from, aad=eph_pub)
    # then proceed with HMAC/Ed25519 verification using the resolved peer
```

L'HMAC/Ed25519 outer signature (la cui esistenza è già nel wire
format 0.4.0+) firma il payload JSON intero, **incluso** `from_eph`
e `from_sealed`. Quindi un attaccante non può sostituire il sealed
field senza invalidare l'auth tag.

## Cosa NON cambia

- L'HMAC continua a usare la session key del peer di trasmissione
  (la prima connessione TCP). Il destinatario, dopo aver decifrato
  `from_sealed`, scopre `real_from`, lookup-a la `sender_conn`
  basata su `real_from`, e verifica l'HMAC con quella conn.
- L'onion routing è invariato.
- I peer_id su address book / pin store sono in chiaro lì dove
  servono (è materiale dell'utente locale, non wire).

## Impatti su moduli

- **`crypto.py`**: nessun cambio (ChaCha20-Poly1305 + HKDF + X25519
  ECDH già disponibili).
- **`node.py`**:
  - In ogni `_try_send` / `_try_send_payload` / `_send_receipt`:
    il payload JSON viene costruito SENZA `from`, ma con
    `from_eph` + `from_sealed` derivati su X25519 pub del
    destinatario.
  - In `_deliver`: prima di processare il dispatch, decifrare
    `from_sealed` per ottenere `real_from`; poi usarlo come
    `from_id` per il resto del flow.
- **Wire format**: due nuovi field; rimosso `from`.

## Test plan

- Unit: `test_sealed_sender.py`:
  - `seal(from_id, eph_priv, dest_pub) → (eph_pub, sealed_bytes)` returns roundtrip ok.
  - `unseal(sealed, eph_pub, my_priv) → from_id` matches.
  - Tampered `eph_pub` → ValueError on unseal.
  - Tampered `sealed_bytes` → ValueError.
  - Wrong recipient priv → ValueError.
- Integration: stesso pattern dei test E2E esistenti, ma con due
  paranoia check:
  - Un osservatore della session key del primo hop NON vede `from`
    plaintext nel payload paddato. Il payload contiene solo
    `from_eph` (32B random + HKDF) e `from_sealed` (ciphertext
    indistinguibile da random).
  - Reuse delle E2E `test_replay_protection`/`test_files`/etc:
    devono restare verdi una volta che sia sender che receiver
    parlano il nuovo wire format.

## Refactor preventivo

Estraggo il pattern di seal/unseal in un modulo dedicato
`malphas.sealed_sender` con due funzioni pure.

## Versioning

Minor 0.5.8 → **0.6.0**. Wire-breaking. CHANGELOG con marker.

## Acceptance criteria

- [ ] Modulo `malphas.sealed_sender` con `seal(from_id, dest_x25519_pub)` e `unseal(eph_pub, sealed, my_x25519_priv)`.
- [ ] Strict bucket mypy include il nuovo modulo.
- [ ] `node.py` smette di emettere `from` plaintext; sostituito con
      `from_eph` + `from_sealed`.
- [ ] `_deliver` decifra `from_sealed` prima di procedere.
- [ ] Tutti i test E2E esistenti rimangono verdi (sender e receiver
      parlano la nuova wire).
- [ ] Nuovo `test_sealed_sender.py` con almeno 5 unit test.
- [ ] Smoke test: payload paddato non contiene mai il `peer_id`
      plaintext del sender.
