# Iter 018 — Green: Hypothesis fuzz on parsers

## Cosa è stato fatto

### Nuova dev dep

`hypothesis>=6` aggiunto a `[project.optional-dependencies].dev`.

### `tests/test_fuzz_parsers.py`

8 property test, ognuno con `max_examples` da 100 a 300:

1. `test_peel_layer_never_crashes` — bytes random 0..4096 → solo `ValueError`.
2. `test_unpad_payload_never_crashes` — bytes random 0..2048 → solo `ValueError`.
3. `test_parse_invite_text_never_crashes` — text random 0..4096 → solo `ValueError`.
4. `test_parse_invite_with_malphas_prefix` — prefix + b64(random bytes) → solo `ValueError`.
5. `test_file_offer_from_dict_never_crashes` — dict con shape arbitraria → solo `KeyError/ValueError/TypeError`.
6. `test_file_offer_roundtrip` — sanity: round-trip `to_dict → from_dict` resta consistente.
7. `test_parse_invite_prefix_only` — prefix + bytes latin-1 (non-base64) → solo `ValueError`.
8. `test_parse_invite_arbitrary_json_after_prefix` — prefix + sig bogus + JSON valido → solo `ValueError`.

Totale ~1600 esempi randomizzati per CI run.

### Risultato al primo run

```
8 passed in 2.17s
```

I parser esistenti hanno superato il fuzz al primo colpo. Niente fix richiesto. Buon segno: i parser sono già scritti in stile fail-closed coerentemente con la threat model del progetto.

### Documentazione

- CHANGELOG entry per `0.3.4`.
- `.gitignore` aggiunge `.hypothesis/` (cache di Hypothesis con repro DB).

## Garanzie non testabili

Hypothesis salva i counter-example in `.hypothesis/examples/` localmente.
In CI questi non persistono tra run, ma ogni run prova esempi nuovi
(seed pseudo-random). Per repro deterministica si può aggiungere
`@seed(N)` al test specifico — non lo facciamo per default.

## Versioning

Patch 0.3.3 → 0.3.4 (test-only).

## Bucket strict mypy

Invariato (8 moduli). I test stessi non sono nel bucket strict.
