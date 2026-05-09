# Iter 017 — Next-target selection

## Stato post 016

8 patch release in due "giorni" del loop:
- v0.2.1 replay protection
- v0.2.2 micro-fixes (secrets/jitter/monotonic/docstring)
- v0.2.3 ruff CI
- v0.2.4 mypy strict bucket
- v0.3.0 file transfer core
- v0.3.1 file transfer CLI
- v0.3.2 file transfer docs
- v0.3.3 SecureBytes (mlock + zeroize)

Bucket strict mypy: 8 moduli.
Suite test focalizzata: 173+ green (numeri variano).

## Selezione iter-018

Scelgo **fuzz / property-based testing** sui parser di buffer non-fidati.

Motivi:
- Aggiunge robustezza concretamente verificabile senza wire-breaking.
- Effort piccolo (Hypothesis è zero-config).
- TDD nello stile classico: i fuzzer trovano bug → fixiamo → ri-test.
- Targeting i tre parser più esposti a input malevoli:
  - `onion.peel_layer` — riceve bytes da un peer non fidato (relay onion).
  - `obfuscation.unpad_payload` — riceve bytes da un peer non fidato.
  - `invite.parse_invite` — riceve bytes paste-ati dall'utente.
  - `files.FileOffer.from_dict` — riceve dict da un peer non fidato.

## Acceptance criteria iter-018

- `hypothesis` aggiunto a dev deps.
- `tests/test_fuzz_parsers.py` con almeno 4 property:
  - `peel_layer(priv, st.binary(min_size=0, max_size=4096))` non crasha; solleva solo `ValueError` o ritorna correttamente.
  - `unpad_payload(st.binary(...))` idem.
  - `parse_invite(st.text(...))` idem; per blob casuali ammessi solo `ValueError`.
  - `FileOffer.from_dict({...})` con dizionari arbitrari → solo `KeyError`/`ValueError`/`TypeError`.
- Se i fuzz scoprono qualche eccezione non gestita → fix nei moduli corrispondenti.
- 200 esempi per property (default Hypothesis = 100, ne usiamo qualcuno in più per copertura).

## Dimensione iter

Effort S–M. Tipicamente: 1 ora di setup + bug-found-fixed iterativo.

## Versioning

Patch 0.3.3 → 0.3.4 (test-only, eventuali fix tracciati nei pacchetti relevant).
