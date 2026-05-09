# Iter 038 — Green: cumulative SUMMARY.md

## Cosa è stato fatto

`docs/auto-loop/SUMMARY.md` (~190 righe). Sezioni:

- **Linee di release** — tabella iter → version → topic per tutte le
  19 release prodotte nel loop.
- **Cosa è cambiato** — bullet per area (Security, File Transfer,
  Wire format, Engineering quality, Test infrastructure,
  Documentation, Nuovi moduli).
- **Cosa NON è stato toccato** — scope deliberatamente fuori dal
  loop autonomo perché richiedono decisione utente: sealed sender,
  group chat, per-user salt, BIP39, mobile, GUI, transfer resume,
  session_id prefix, strict-bucket extension a node/transport/api/
  cli_ui/__main__.
- **Suggerimenti per la prossima sessione** — in ordine di valore
  atteso.
- **Stato del repo al T_now** — output di `scripts/check.sh --quick`
  e `git status`.

`INDEX.md` aggiornato con header che punta a `SUMMARY.md` come
re-entry point per l'utente.

## Versioning

Patch 0.5.4 → 0.5.5 (docs only).

## Stato finale del loop

Dopo questo iter, il valore prodotto da iterazioni autonome ulteriori
sta sotto la soglia in cui ha senso continuare senza input utente. Le
opzioni residue sono tutte **decisioni architetturali** che richiedono
consenso (sealed sender, group chat, per-user salt, BIP39).

Il loop schedulerà l'ultimo wakeup a un intervallo lungo (30 min) per
dare tempo all'utente di rivedere e fornire direzione. Se al wakeup
nessuna istruzione, la prossima iter farà altro micro-task di
manutenzione (es. dependency bump, dependabot config).
