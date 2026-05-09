# Iter 046 — Green: sealed sender (v0.6.0, WIRE-BREAKING)

## Cosa è stato fatto

### `src/malphas/sealed_sender.py` (nuovo)

```python
seal(from_peer_id: str, dest_x25519_pub: bytes) -> tuple[str, str]
unseal(eph_pub_hex: str, sealed_b64: str, my_x25519_priv) -> str
```

- Genera ephemeral X25519 keypair, ECDH con la pub statica del
  destinatario, HKDF-SHA256 con salt `malphas-sealed-sender-v1` /
  info `from` → 32-byte key per ChaCha20-Poly1305.
- AAD = eph_pub (lega il ciphertext alla chiave effemera).
- Roundtrip ok, freschezza nonce per chiamata, tamper detection
  (qualsiasi bit-flip su eph_pub o sealed → ValueError).

### Integrazione `node.py`

- 3 send-sites (`_try_send`, `_send_receipt`, `_try_send_payload`):
  rimossa l'emissione `"from": peer_id`. Aggiunti `from_eph` +
  `from_sealed`. Pre-condizione: `dest_peer ∈ discovery` (altrimenti
  return False/None senza tentare il send).
- 2 receive-sites (ratchet path + HMAC/Ed25519 path): sostituito
  `data.get("from", "")` con il nuovo helper modulo-livello
  `_resolve_sealed_from(data, my_x25519_priv)`. L'helper:
  1. estrae `from_eph` e `from_sealed`,
  2. unseal con la priv del nodo,
  3. inietta `data["from"] = real_from` per non rompere
     `_dispatch_kind` (che legge `from` e usa anche
     `data.get("from", "")` per la replay cache).
  Ritorna `""` su qualunque malformazione → drop silenzioso
  coerente con la fail-closed policy.

### Test

`tests/test_sealed_sender.py`, 9 test:
- roundtrip
- eph_pub fresh per call
- sealed_b64 fresh per call (random nonce)
- wrong recipient fails
- tampered eph_pub fails
- tampered sealed fails
- invalid eph_pub hex
- invalid sealed b64
- short eph_pub

Tutti verdi.

E2E: `test_replay_protection` (14), `test_files` (14),
`test_microfixes` (5), `test_sealed_sender` (9) → 42/42 verdi
post-refactor. Le E2E confermano che il roundtrip sender→receiver
funziona attraverso il nuovo wire format.

### Smoke check anti-leak

```python
$ alice.peer_id = "e49c090e9ec911b11767a5d12d7432c38b2f5c83"
$ payload = {"kind": "msg", "from_eph": ..., "from_sealed": ..., ...}
$ alice.peer_id.encode() not in json.dumps(payload).encode()
True
```

Il peer_id reale del sender non appare mai nel payload.

## CI

- ruff: clean.
- mypy: 22 file (strict bucket esteso a 15: `replay`, `crypto`,
  `memory`, `obfuscation`, `pinstore`, `invite`, `files`,
  `secure_buffer`, `discovery`, `receipts`, `ratchet`, `identity`,
  `onion`, `addressbook`, **`sealed_sender`**).
- bandit: 0 findings.

## Wire format

**WIRE-BREAKING.** Un peer 0.6.0 non riconosce più `"from"`
plaintext (legge solo `from_eph` + `from_sealed`); un peer ≤0.5.x
emette ancora `"from"` plaintext che il ricevente 0.6.0 ignora →
`from_id == ""` → drop silenzioso.

Migrazione: aggiornare ambo le parti.

## Versioning

Minor 0.5.8 → **0.6.0**. CHANGELOG con marker WIRE-BREAKING.

## Threat model

Aggiornato il README "Threat Model" con nuova voce in "Protected
against": "Post-compromise sender disclosure".
