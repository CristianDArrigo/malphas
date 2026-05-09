# Iter 015 — Next-target selection

## Stato post 014

Mini-release file transfer chiusa (0.3.0 → 0.3.2: core + CLI + docs).

## Opzioni aperte

| ID | Topic | Effort | Valore | Wire-breaking |
|----|-------|--------|--------|---------------|
| A1 | Web API endpoints `/api/files/*` | M | M | no |
| A2 | mlock + secure-erase su key material | S | M | no |
| A3 | Property-based / fuzzing su onion + ratchet + files | S | M | no |
| A4 | Sealed sender (cifra `from` field) | M | H | sì → 0.4.0 |
| A5 | session_id prefix in onion (B7 from iter-001) | M | M | sì → 0.4.0 |
| A6 | Group chat MLS-based | XL | H | sì → 0.4.0 |
| A7 | Argon2id per-user salt | S | M | quasi (richiede file `.salt`) |
| A8 | Backup/export keys via BIP39 mnemonic | M | M | no |

## Decisione iter-016

Selezione: **A2 — mlock + secure-erase**.

Motivi:
- Aderente al threat model esistente: protegge contro RAM swap che potrebbe esporre material chiavi al disco senza che l'utente lo sappia.
- Self-contained: tocca `identity.py`, `crypto.py`, `addressbook.py` (book_key), `ratchet.py` (root_key, chain_keys).
- TDD-friendly: si può testare il pattern `mlock` + zeroize via `ctypes` introspection.
- Effort piccolo. Buon ROI prima di affrontare wire-breaking change.
- Non rompe niente di pubblico.

Iter-016 implementerà la utility `secure_buffer.py` con:
- `SecureBytes(size)` — bytearray mlocked, zeroizzato su del.
- `SecureBytes.from_bytes(data)` — copia immutable bytes in mlocked region, zeroizza source if mutable.
- `with secure_bytes(...)` context manager.

I siti che useranno SecureBytes:
- `_derive_seed` in identity.py — il seed Argon2id (64 byte).
- `book_key` in addressbook.py.
- `RatchetState._root_key`, `_send_chain_key`, `_recv_chain_key`.

## Prossimi step

iter-017+ = A3 (fuzzing) o A4 (sealed sender) a seconda di tempo.
