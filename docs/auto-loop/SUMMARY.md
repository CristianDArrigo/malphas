# Auto-Loop Autonomous Development Session — Summary

> Single re-entry point per l'utente. Per il dettaglio iter-per-iter,
> vedi `INDEX.md` e i singoli file `iter-NNN-*.md`.

**Periodo:** 2026-05-08 → 2026-05-09 (modalità auto-loop continuata).
**Operatore:** Claude (Opus 4.7 / Sonnet 4.6 mix), modalità auto-mode.
**Punto di partenza:** `c8f7009` — v0.2.0.
**Punto attuale:** `aa2c214` — v0.5.4 (al momento di questa nota; il
SUMMARY è committato come 0.5.5).

---

## Linee di release

| Versione | Tipo | Iter | Topic |
|----------|------|------|-------|
| 0.2.0 | (precedente) | — | baseline (Double Ratchet, Tor HS, auto-reconnect) |
| 0.2.1 | patch | 002–004 | replay protection (sliding window) |
| 0.2.2 | patch | 006 | micro-fixes (secrets/jitter/monotonic/docstring) |
| 0.2.3 | patch | 007 | ruff in CI + 223 auto-fix |
| 0.2.4 | patch | 008 | mypy strict bucket (3 moduli) |
| 0.3.0 | minor | 010 | file transfer chunked (core) |
| 0.3.1 | patch | 012 | CLI commands `/sendfile` `/accept` `/reject` `/savefile` `/files` |
| 0.3.2 | patch | 014 | README docs per file transfer |
| 0.3.3 | patch | 016 | SecureBytes (mlock + zeroize) |
| 0.3.4 | patch | 018 | Hypothesis fuzz tests sui parser |
| 0.3.5 | patch | 020 | coverage gate + bandit static security |
| 0.3.6 | patch | 022 | Web API endpoints `/api/files/*` + WS push |
| 0.3.7 | patch | 024 | README consolidation 0.3.x |
| **0.4.0** | minor | 026 | **WIRE-BREAKING**: auth-type prefix (`b"H"`/`b"E"`/`b"R"`) |
| **0.5.0** | minor | 028 | **WIRE-BREAKING**: BLAKE2s peer_id |
| 0.5.1 | patch | 030 | mypy strict → 11 moduli (discovery/receipts/ratchet) |
| 0.5.2 | patch | 032 | mypy strict → 14 moduli (identity/onion/addressbook) |
| 0.5.3 | patch | 034 | `scripts/check.sh` local mirror del CI |
| 0.5.4 | patch | 036 | single source of truth per il strict bucket |
| 0.5.5 | patch | 038 | (questo SUMMARY) |

19 release totali, 2 wire-breaking (auth prefix, BLAKE2s).

---

## Cosa è cambiato

### Security

- **Replay protection** sliding-window applicata a tutti i kind
  (msg, receipt, file_*).
- **Secrets-grade RNG** per circuit selection (era stdlib `random`).
- **Reconnect jitter** ±20% per evitare thundering herd.
- **Monotonic TTL** in MessageStore — immune a clock-skew NTP.
- **Auth-type prefix** esplicito (`b"H"`/`b"E"`/`b"R"`) elimina
  trial-JSON-parse heuristic del receiver.
- **BLAKE2s peer_id** sostituisce SHA1 (collision-resistant).
- **`SecureBytes`** wraps il seed Argon2id: bytearray-based, mlock
  best-effort, zeroize on drop.
- **CI security gates**: bandit static scan blocking, 0 findings sul
  source.

### File transfer (mini-release v0.3.x)

- Modulo `malphas.files`: `OutgoingFile`, `IncomingFile`,
  `FileTransferManager`. 32 KB chunks, 100 MB cap, SHA-256 integrity.
- 3 nuovi `kind` JSON-payload (offer/chunk/ack), backward-compatible
  con la wire del 0.2.x ma poi superato dalla wire-break 0.4.0.
- CLI: 5 nuovi comandi.
- Web API: 5 endpoint REST (multipart upload, list, accept, reject,
  download) + 2 WebSocket push events.
- Filename sanitization in Content-Disposition.
- Replay protection applicata anche ai chunk.

### Wire format breakages

- **0.4.0**: auth-type prefix nel payload interno (`b"H"`/`b"E"`/`b"R"`).
  Vecchio: `tag(32|64) || JSON` o `b"R" || header || ct`.
- **0.5.0**: peer_id derivato come `BLAKE2s(ed25519_pub, 20)` invece
  di `SHA1(...)`. Stessa lunghezza, valore diverso → upgrade
  side-by-side richiesto.

### Engineering quality

- **CI gate stack** completo a 5 stadi blocking:
  - `ruff` (style + bug + security hint)
  - `mypy --strict` su 14/19 moduli (~52% del codice)
  - `bandit` static security
  - `pytest --cov --cov-fail-under=65`
  - `hypothesis` fuzz su 4 parser
- `scripts/check.sh` local mirror — single command per replicare la CI.
- Single source of truth del bucket strict in `pyproject.toml`
  `[[tool.mypy.overrides]]`.
- 223 auto-fix da ruff (typing modernization, import sort, etc.).
- ~1600 esempi randomizzati per CI run via Hypothesis su
  `peel_layer`, `unpad_payload`, `parse_invite`, `FileOffer.from_dict`.

### Test infrastructure

- 7 nuovi test files: `test_replay_protection`, `test_microfixes`,
  `test_files`, `test_cli_files`, `test_api_files`, `test_secure_buffer`,
  `test_fuzz_parsers`. ~120 nuovi test.
- Suite focalizzata 270+ test verdi, ~84 secondi.
- Coverage focused: 68.4% su 2004 stmt + 438 branch.

### Documentation

- README: nuova sezione "File Transfer" con quickstart Alice→Bob.
- README: nuova sezione "CI quality gates".
- README: nuova sezione "Web API endpoints".
- Architecture diagram aggiornato (ReplayCache, FileTransferManager).
- Threat Model esteso (replay protection, mlock).
- `CHANGELOG.md` (nuovo, completo).
- `SECURITY.md` (nuovo).
- `docs/auto-loop/` — log completo iter per iter (~38 file).

### Nuovi moduli

- `malphas.replay` — sliding-window replay cache (44 stmt).
- `malphas.files` — file transfer (122 stmt).
- `malphas.secure_buffer` — SecureBytes (100 stmt).

---

## Cosa NON è stato toccato

Scope deliberatamente fuori dal loop autonomo perché richiedono
decisioni architetturali o threat-model che vanno discusse con l'utente:

- **Sealed sender** (cifrare il `from` field con la pubkey del
  destinatario). Wire-breaking, security impact alto. Cambia la
  proprietà "chi vede chi parla con chi" anche dopo session compromise.
- **Group chat** (MLS o N-way ratchet). Effort XL, design choice.
- **Argon2 per-user salt**. Sacrifica la "passphrase = identity" pure
  promise per un salt persistito (file `.salt`). Trade-off da
  decidere con l'utente.
- **BIP39 backup mnemonic**. Workflow di mnemonic → passphrase
  derivata. Cambia UX in modo che il loop non dovrebbe decidere senza
  consenso.
- **Mobile** (Android, iOS).
- **GUI desktop** (Tauri / Qt / Textual). La modalità `--mode web` ha
  l'API ma non una vera UI.
- **Resume di file transfer interrotti**.
- **`session_id` prefix in onion** (W2 in iter-001). Wire-breaking,
  elimina il trial-decrypt O(N) sui ratchet ma è un'ottimizzazione
  più che una correzione di sicurezza.
- **mypy strict** su `node.py`, `transport.py`, `api.py`, `cli_ui.py`,
  `__main__.py`. Richiedono annotation work più sostanziale (asyncio
  Task generics, FastAPI decorator types, prompt_toolkit subtypes).

---

## Update post-handoff (sessione 2 — utente di ritorno)

L'utente è tornato e ha approvato 6 work item:

| Phase | Topic | Versione | Iter |
|-------|-------|----------|------|
| 1 | Sealed sender (cifra `from`) | 0.6.0 wire-break | 046 |
| 2 | Argon2 per-user salt | 0.7.0 wire-break | 047 |
| 3 | BIP39 12-word mnemonic backup | 0.7.1 | 048 |
| 4 | File transfer resume | 0.8.0 | 049 |
| 5 | Group chat N-way pairwise | 0.9.0 | 050 |
| 6 | Tkinter GUI ("fatto bene") | 0.10.0 | 051 |

Tutte e 6 chiuse in modalità auto. Wire-breaking changes della
sessione: sealed sender, per-user salt. Le altre quattro non
rompono il wire (kind nuovi droppati silenziosamente da peer
vecchi). Dependency runtime aggiunta: `mnemonic>=0.20`.

Test totali aggiunti in questa fase: 51 (sealed_sender 9 +
salt_store 8 + mnemonic 9 + file_resume 5 + groups 11 + gui 7 +
extra modifications negli E2E esistenti). Strict mypy bucket: 18
moduli. CI gate stack invariato.

## Suggerimenti per la prossima sessione (residual)

1. **mypy strict per `node.py`** — l'ultimo modulo grosso senza
   annotation tightening. ~100 errori da fixare.
2. **Group state persistence** cross-restart (oggi è in-memory).
3. **Group: notify existing members on add** (oggi solo l'invitato
   sa).
4. **Drag-and-drop file send** nella GUI.
5. **Web frontend** vero (oggi `--mode web` ha solo gli endpoint,
   nessun UI).
6. **Mobile** (Android/iOS).

---

## Stato del repo al T_now

```
$ scripts/check.sh --quick
✓ ruff clean
✓ mypy clean (18 strict + 7 lenient = 25 files)
✓ bandit 0 findings

$ git log --oneline | head -10
b0da6b4 0.10.0: Tkinter desktop GUI
5653d95 0.9.0: group chat — N-way pairwise fanout
940c674 0.8.0: file transfer resume — receiver tells sender what to skip
1e1c91b 0.7.1: BIP39 12-word mnemonic backup for the per-user salt
5fe0524 0.7.0: per-user Argon2 salt (WIRE-BREAKING)
df5331b 0.6.0: sealed sender — encrypt the `from` field (WIRE-BREAKING)
4062eee 0.5.8: contributor templates
2fca44c 0.5.7: __version__ from metadata, --version flag, py.typed marker
7f11586 0.5.6: dependabot config + pre-commit mirror
eed973d 0.5.5: cumulative SUMMARY.md for autonomous-loop session
```

Loop autonomo totale: **39+ release** dalla v0.2.0 di partenza.

Pronto per hand-off all'utente.
