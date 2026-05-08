# Iter 005 — Next target selection

## Stato post iter-004

Replay protection ha chiuso il gap HMAC/Ed25519/ratchet-grace.
Suite test verde (verificato in iter-004).

## Candidati ancora aperti dalla review iter-001

| ID | Titolo | Severity | Effort | Breaking | Testability |
|----|--------|----------|--------|----------|------|
| A2 | Trial-decrypt ratchet O(N) — session_id prefix | M | M | sì (wire) | media |
| A4 | `random.sample` → `secrets` in circuit selection | L | XS | no | bassa (det.) |
| A6 | Race su panic concorrente | L | S | no | bassa |
| A7 | Reconnect jitter ±20% | L | XS | no | media |
| A8 | MessageQueue overflow silenzioso → notifica caller | L | S | no | media |
| A9 | `time.time()` → `time.monotonic()` per TTL | L | S | no | media |
| B7 | Auth-type tag prefix | M | M | sì (wire) | alta |
| B8 | DoS rate-limit handshake | M | M | no | media |
| C5 | Magic numbers cleanup | XS | XS | no | nessuna |
| C8 | Docstring SHA1→Argon2id in identity.py | XS | XS | no | nessuna |
| D1 | Test replay attack già coperto in iter-004 | done | — | — | — |
| D3 | Coverage gate ≥80% nel CI | M | S | no | n/a |
| E1 | mypy strict in CI | M | S | no | n/a |
| E2 | ruff/black in CI | M | XS | no | n/a |

## Decisione iter-006

Uso una euristica peso = severity × testability / effort:
- A9 monotonic TTL → cosa fatta in iter-004 sul ReplayCache; estendere a MessageStore + ReceiptTracker → severity L, effort S, breaking no, testability media. **Eseguire come quick-win.**
- C8 docstring fix → cosmetico ma 30 secondi. **Pacchettizzare.**
- A7 reconnect jitter → severity L, effort XS, breaking no, testability media. **Pacchettizzare.**
- A4 secrets-based circuit → severity L, effort XS. **Pacchettizzare.**
- E2 ruff in CI → severity M, effort XS. Tier sopra: **eseguire come secondo target.**
- E1 mypy → effort S, severity M. **Tier 2 dopo ruff.**
- D3 coverage gate → effort S, severity M. **Tier 2 dopo mypy.**

Tier 1 batch (next iteration): bundle di **micro-fix sicuri**:
- A4 (secrets in circuit), A7 (jitter), A9 (monotonic TTL nei moduli mancanti), C8 (docstring), C9 (print → ptk_print), C2 (struct import top-level dove possibile).
- Test: dove non testabile (jitter, monotonic) garantito tramite review manuale documentata + un assert smoke.

Tier 2: introduzione **engineering quality CI**:
- ruff + black, configurati ma con `--check` non-blocking nella prima PR per scoprire backlog.
- Poi mypy.
- Poi coverage gate.

Tier 3: refactor **auth-type prefix** (B7) — wire-format breaking → richiede bump 0.3.0.

Tier 4: feature nuove (file transfer chunked → groups MLS).

## Output

iter-006-plan-microfixes.md sarà il prossimo doc.

## Hand-off

Schedulo via ScheduleWakeup il prossimo turno con istruzioni: continua il loop autonomo,
review eseguita, replay-protection done, ora attacca il batch micro-fix.
