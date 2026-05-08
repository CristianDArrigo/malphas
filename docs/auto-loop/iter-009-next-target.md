# Iter 009 — Next-target selection

## Stato post 008

Quattro iterazioni di hardening (replay-protection, micro-fixes, ruff, mypy)
hanno chiuso buona parte dei finding "minori" della review iter-001 e portato
il CI a uno stato in cui il modulo nuovo ha qualità da production: lint +
type-check strict + 14 test integrati.

Patch versions: 0.2.0 → 0.2.4 in due giorni di lavoro.

## Selezione del prossimo obiettivo

La review iter-001 ha lasciato due grandi categorie aperte:

1. **Hardening hot path** (effort medio, valore alto):
   - B7 auth-type prefix (wire-breaking → 0.3.0)
   - A2 session_id davanti al ratchet ciphertext (wire-breaking)
   - mlock + secure-erase
   - Sealed sender

2. **Funzionalità** (effort alto, valore alto):
   - File transfer chunked
   - Group chat (MLS)
   - GUI (web/desktop)
   - Mobile

L'utente ha menzionato esplicitamente "GUI malphas" come opzione interessante.
Ma una GUI completa è 1+ settimana di lavoro lineare. Nel mezzo c'è una
opzione concreta e ad alto valore visibile: **File transfer chunked**.

### Perché file transfer

- Richiesta ricorrente in messenger privacy-first (Briar/Cwtch lo hanno).
- Architetturalmente self-contained: usa lo stesso onion path, stesso
  ratchet/HMAC, stesso store. Si aggiunge un nuovo `kind = "file"` con
  chunking e reassembly.
- TDD chiaro: send/receive di file 5KB / 1MB / 10MB; verifica integrità
  via SHA256.
- Wire format: si può fare backward-compatible aggiungendo nuovi `kind`
  payload — i client vecchi droppano silenziosamente (fail-closed default).
- Apre la strada a feature future (immagini → preview → mini-protocol).

### Perché NON GUI per ora

- Rimanderei a un'iterazione dedicata dopo file transfer perché:
  - Senza file transfer la GUI ha meno features da mostrare.
  - Una GUI Python (Textual? PyQt? Tauri+frontend?) è una decisione di
    architettura che richiede buon thinking — non da auto-mode.
  - Meglio chiudere prima il modulo applicativo, poi avvolgerlo in UI.

## Plan iter-010 — File transfer chunked

Macro-design:

- Nuovo modulo `src/malphas/files.py`: `FileSender` / `FileReceiver`,
  chunking 32KB, SHA256 integrity, manifest message.
- Wire: tre nuovi `kind` JSON: `file_offer`, `file_chunk`, `file_ack`.
- Manifest contiene: `file_id` (random hex), `name`, `size`, `sha256`,
  `chunk_size`, `chunk_count`.
- Chunk: `file_id`, `chunk_idx`, `chunk_data` (base64 encoded).
- Receiver bufferizza in RAM (fedele a zero-disk; salvataggio su disco
  solo su consenso esplicito dell'utente, fuori dallo scope di questo
  iter).
- Replay protection già coperta: stesso `(from_id, msg_id)` esistente.
- Cap: max 100 MB per file in coerenza con lo zero-disk.

CLI:

- `/sendfile <peer|label> <path>` apre file, calcola hash, manda offer.
- Receiver vede notifica "incoming file: name (size)" e ha 30s per
  `/accept <file_id>` o `/reject <file_id>`. Default decline.

Acceptance criteria — TDD:

- [ ] `FileSender.chunkify(path, chunk_size)` produce N+1 messages
       (1 offer + N chunks) deterministically.
- [ ] `FileReceiver.assemble(chunks)` ricostruisce lo stream byte-perfect.
- [ ] SHA256 mismatch → reject + drop.
- [ ] Re-ordering chunk supportato (basta `chunk_idx`).
- [ ] Chunk duplicato non corrompe lo stream (dedup by `(file_id, chunk_idx)`).
- [ ] Cap 100 MB enforced sender-side (errore early).
- [ ] Cap 100 MB enforced receiver-side (drop oltre).
- [ ] Test E2E A→B con file 1 KB, 100 KB, 1 MB.
- [ ] Cancel su `/reject` libera la memoria del receiver.

## Hand-off

Questo loop ha esaurito la lista di follow-up *inclusi* nel review iniziale.
Il prossimo step (iter-010) è una feature, non un fix, e richiederà più
iterazioni (red/green).

Ritorno il controllo all'utente in modo che possa rivedere il diff +
deciderne la direzione (file transfer vs GUI vs altro).

Se vuole continuare il loop in autonomia, basta dire "vai avanti" e procedo
con iter-010 (file transfer) come pianificato.
