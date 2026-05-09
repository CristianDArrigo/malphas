# Iter 045 — Roadmap: 6 phase user-driven (post hand-off resume)

L'utente è tornato e ha approvato 6 work item dalla SUMMARY:

| Phase | Topic | Versione target | Wire-breaking | Decisione utente |
|-------|-------|-----------------|---------------|------------------|
| 1 | Sealed sender | 0.6.0 | sì | da SUMMARY |
| 2 | Argon2 per-user salt | 0.7.0 | sì | da SUMMARY |
| 3 | BIP39 mnemonic | 0.7.x | no | "12 parole, non 24" |
| 4 | File transfer resume | 0.8.0 | sì | da SUMMARY |
| 5 | Group chat | 0.9.0 | sì | "MLS o N-way" → scelgo N-way pairwise |
| 6 | Tkinter GUI | 0.10.0 | no | "tkinter ma fatto bene" |

Mobile (#6 in SUMMARY) saltato: l'utente non l'ha incluso nella lista.

## Ordine di esecuzione

Strict dependence order:

1. **Sealed sender** prima di tutto: tocca il payload JSON inner — meglio
   stabilizzare il wire prima di costruirci sopra resume e group.
2. **Argon2 per-user salt** dopo sealed sender: cambia identity
   derivation, pull-able indipendentemente.
3. **BIP39 mnemonic** non-breaking: può andare dopo o prima dei wire-
   breaking. La metto prima della GUI così la GUI ha già il flow
   di onboarding mnemonic-friendly.
4. **File transfer resume**: aggiunge campi al wire format dei
   `file_chunk`. Indipendente da sealed sender semanticamente, ma
   è elegante farla DOPO sealed sender per non sommare due wire-
   break in iter consecutive.
5. **Group chat N-way pairwise**: semplificazione di MLS — il sender
   cifra il messaggio una volta per ogni membro, fanout di N pacchetti.
   Niente group state ratchet condiviso. Funziona per gruppi piccoli
   (≤10 membri ragionevole, hard cap 50).
6. **Tkinter GUI**: chiude il bundle integrando tutto.

## Versioning

- 0.6.0 (sealed sender, wire-breaking)
- 0.7.0 (per-user salt, wire-breaking)
- 0.7.1 (BIP39)
- 0.8.0 (file resume, wire-breaking)
- 0.9.0 (group, wire-breaking)
- 0.10.0 (GUI, no wire impact ma minor bump per nuova capability)

## Constraint dell'utente: "fai tutto in loop"

Stessa modalità della sessione precedente: ogni phase ha plan → red
(quando ha senso) → green → CHANGELOG → commit → ScheduleWakeup
(o continuazione foreground se il tempo lo permette).

Ho schedule dell'iter passate spesso a 90s; per le phase più grosse
(group chat, GUI) il wakeup sarà a interval più lungo perché serve
più context window per impl + test.
