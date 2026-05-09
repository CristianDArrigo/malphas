# Iter 026 — Green: auth-type prefix (v0.4.0, wire-breaking)

## Cosa è stato fatto

### Costanti modulo `node.py`

```python
AUTH_RATCHET = b"R"
AUTH_HMAC    = b"H"
AUTH_ED25519 = b"E"

HMAC_TAG_LEN       = 32
ED25519_SIG_LEN    = 64
RATCHET_HEADER_LEN = 40
```

### Helper `_wrap_authenticated(payload_bytes, dest_conn, identity)`

Funzione modulo-livello che centralizza la selezione del metodo di
authentication e prefigge il byte corretto. Selection order:
ratchet → HMAC → Ed25519. Ritorna:

- `b"R"` + header(40) + ciphertext (ratchet)
- `b"H"` + tag(32) + payload (HMAC)
- `b"E"` + sig(64) + payload (Ed25519)

### Send sites refactorizzati

I tre punti che emettevano payload autenticato (`_try_send`,
`_send_receipt`, `_try_send_payload`) ora chiamano `_wrap_authenticated`
invece di duplicare il pattern if/elif/else.

### Receiver `_deliver`

Riscritto. Prima dispatch su prefix byte:

- `b"R"` → ratchet path (logica precedente preservata).
- `b"H"` → tag = signed[1:33], payload = signed[33:]. Verify tag
  con `hmac_verify`.
- `b"E"` → sig = signed[1:65], payload = signed[65:]. Verify sig
  con Ed25519PublicKey.verify.
- altro → drop silenzioso.

Eliminato il loop `for tl in (32, 64): try: json.loads(signed[tl:])`
che era trial-and-error sul JSON parsing — un side-channel che un
attaccante poteva potenzialmente sfruttare.

## Wire format

Cambia la wire format del payload **interno** (post-onion-peel,
post-padding-strip). Il wire transport-level non cambia.

**Backward compat: NESSUNA.** I client 0.4.0 non comunicano con
client 0.3.x. Ambo le parti devono aggiornarsi.

## Test

Tutti i test esistenti continuano a passare. Il refactor è semantically
equivalent al wire layer:

- `test_replay_protection` (14): tutti e 3 i path (ratchet/HMAC/Ed25519) ok.
- `test_files` (14): E2E file transfer integro.
- `test_microfixes` (5): ok.
- `test_security_onion` (13), `test_security_obfuscation` (22),
  `test_ratchet` (13), `test_security_crypto` (24): 72/72 ok.
- `test_api_files` (14), `test_cli_files` (12), `test_invite` (17),
  `test_secure_buffer` (13), `test_security_*` (4 file, 73 test),
  `test_pinstore` (17), `test_fuzz_parsers` (8),
  `test_functional_components` (27): 164/164 ok.

Totale focused: **269 test verdi** post-refactor.

ruff: clean. bandit: 0 findings.

## Versioning

Minor 0.3.7 → **0.4.0**. Apre la linea wire-breaking 0.4.x.

## Prossimi target nella linea 0.4.x

- W2: session_id prefix in onion ciphertext (elimina trial-decrypt O(N)).
- W3: BLAKE2s peer_id (sostituisce SHA1).
- W4: sealed sender (cifra `from`).
- W5: Argon2 per-user salt.

Ogni cambiamento wire-breaking → minor bump (0.5.0, 0.6.0, …) o
combinazione in un singolo bump 0.5.0 con tutti.
