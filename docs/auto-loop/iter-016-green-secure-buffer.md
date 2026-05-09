# Iter 016 — Green: SecureBytes (mlock + zeroize)

## Cosa è stato fatto

### Nuovo modulo `src/malphas/secure_buffer.py`

`SecureBytes`:
- `bytearray` storage interno (mutabile, sovrascrivibile).
- `_mlock(buf)` best-effort via `libc.mlock` su Linux/glibc; fallisce silenziosamente se non disponibile o senza CAP_IPC_LOCK.
- `wipe()` overwrite in-place con zero, idempotente.
- `__del__` zeroizza prima di liberare; `_munlock` se mlock era riuscita.
- `__enter__/__exit__` wipe-on-exit (context manager).
- `__bytes__` → copia immutable.
- `__eq__` constant-time via `hmac.compare_digest`.
- `__getitem__` (slice → bytes, int → byte value), `__iter__`, `__contains__` per compatibilità con casi d'uso esistenti.
- `__hash__` solleva `TypeError` (mutable).

### Integrazione in `identity.py`

- `_derive_seed` ora ritorna `SecureBytes`. La copia immutable Argon2 originale resta live fino al GC; il riferimento long-lived è ora wipeable.
- `create_identity` e `create_identity_with_book_key` consumano il seed dentro un `with _derive_seed(passphrase) as seed:` così il buffer viene zeroizzato e mlock-rimosso al termine.
- Rimosso l'import `secrets` non più usato.

### Documentazione

- `SECURITY.md`: nota mlock+zeroize sull'Argon2 seed; chiariti i buffer ancora non protetti (session keys, ratchet root, book_key).

### Test

`tests/test_secure_buffer.py` (13 test):
- `TestConstruction` (4): size, from_bytes, from_bytes wipe-source su mutable, from_bytes su immutable bytes.
- `TestLifecycle` (4): wipe overwrites, double wipe, use-after-wipe, explicit `__del__` zeros via internal handle.
- `TestSemantics` (4): bytes() independent copy, len, equality, context manager.
- `TestMlockBestEffort` (1): mlock failure non solleva.

Risultato: 13/13 PASSED in 0.03s.

### Adattamenti a test esistenti

- `tests/test_security_crypto.py:test_identity_and_book_key_use_different_contexts`: materializza `bytes(seed)` prima di passare a `hkdf_derive` (la lib `cryptography` richiede buffer-protocol).
- I test `test_security_argon2_panic` non sono stati toccati: `__iter__`, `__getitem__`, `__contains__` su SecureBytes coprono i pattern usati (`zip(s1, s2)`, `seed[:32]`, `sha1_raw not in seed`).

### Verifica

- Suite focalizzata (security_* + identity + invite + pinstore + secure_buffer + replay + microfixes + files): **160/160 PASSED**.
- ruff: All checks passed.
- mypy strict bucket (8 moduli ora): Success.

## Garanzie non testabili a unit

- L'effettivo paging-out anti-swap dipende dal kernel + RLIMIT_MEMLOCK del processo. Se l'utente non ha permessi sufficienti, mlock fallisce e degradiamo silenziosamente. Non c'è modo banale di unit-testare "il kernel non ha pageato la mia pagina". Documentato in SECURITY.md.
- L'effettiva zeroizzazione su `__del__` è osservata nel test via `buf._raw` introspection prima/dopo `__del__()`. Sufficiente per l'invariante.

## Versioning

Patch 0.3.2 → 0.3.3 (security improvement, no API/wire change).

## Bucket strict mypy

8 moduli ora puliti: replay, crypto, memory, obfuscation, pinstore, invite, files, secure_buffer.
