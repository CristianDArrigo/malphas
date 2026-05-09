# Iter 013 — Next-target selection

## Stato post 012

File transfer è completo end-to-end:
- Core (iter-010): `malphas.files` con OutgoingFile/IncomingFile/Manager.
- CLI (iter-012): `/sendfile`, `/accept`, `/reject`, `/savefile`, `/files`.
- Tests: 14 + 12 = 26 nuovi test.
- v0.3.0 → v0.3.1 release.

## Decisione iter-014

Tre strade aperte:

1. **Documentazione** — README sezione "File transfer" + esempi quickstart.
   Effort XS, valore L (utenti capiscono come usarlo).

2. **Web API** — endpoint REST `/api/files/send`, `/api/files/accept`,
   `/api/files/list`, WebSocket extension per offer notifications.
   Effort M, valore M (la PWA non ha ancora UI vera, ma sblocca futuri client web).

3. **Resume di transfer interrotti** — feature avanzata. Effort M, valore L
   in questa fase (non strettamente necessario per il MVP).

4. **Sealed sender / session_id prefix** — wire-breaking, posticipato a 0.4.0.

**Decisione**: iter-014 = **README + docs**, perché:
- È bloccante per gli utenti reali.
- Effort minimo, valore alto.
- Costringe a verificare che l'API sia coerente prima di esporla via REST.
- Conclude logicamente la mini-release v0.3.x.

iter-015+ = Web API (Tier 2).

## Plan iter-014

- README: aggiungere sezione "File transfer" tra "Read Receipts" e
  "Resilience". Esempio quickstart simmetrico a "Connecting via invite".
- Aggiornare Architecture diagram (FileTransferManager dentro NODE).
- CLI Reference: aggiungere i 5 nuovi comandi.
- CHANGELOG già aggiornato in iter-010 e iter-012.
- Bump versione 0.3.1 → 0.3.2 (docs-only).

Niente test code richiesto. Garanzia: review manuale.
