# Iter 037 — Next-target selection

## Stato post 036

18 release nel loop autonomo: 0.2.0 → 0.5.4.

Il pattern recente (iter-030, 032, 034, 036) ha lavorato sull'asse
eng/quality/infra. Ogni iter consecutiva fornisce meno valore
incrementale. È tempo di alternare verso qualcosa di più user-facing
o di chiudere fase con un riepilogo cumulativo.

## Selezione iter-038

**`docs/auto-loop/SUMMARY.md`** — un overview cumulativo di tutto il
lavoro fatto nel loop autonomo, indicizzato per fase e con il
mapping iter → release.

Motivi:
- L'utente, quando torna a controllare, ha bisogno di un singolo file
  per orientarsi, non 36 mini-doc da leggere in ordine.
- Effort XS.
- Valore alto: aiuta sia l'utente che il loop futuro.
- Non richiede decisioni di feature/threat-model.

## Acceptance criteria iter-038

- `docs/auto-loop/SUMMARY.md` esiste, ~150–250 righe.
- Sezione "Linee di release" con tabella iter → version → topic.
- Sezione "Cosa è cambiato" con bullet sintetici raggruppati per
  area (security, file-transfer, eng-quality, docs).
- Sezione "Cosa NON è stato toccato" — gli scope deliberatamente
  fuori dal loop autonomo (sealed sender, group chat, GUI, mobile,
  per-user salt, BIP39).
- Sezione "Suggerimenti per la prossima sessione" — opzioni che
  richiedono decisione utente.

Versioning: 0.5.4 → 0.5.5 (docs only).

## Dopo iter-038

Il loop dovrebbe rallentare i wakeup auto-pilot. Stato candidato per
hand-off all'utente: `git status` clean, suite verde, README/CHANGELOG
allineati, summary letto-in-2-minuti. Da quel punto, attendiamo input
prima di prendere decisioni più grandi (sealed sender, group chat).
