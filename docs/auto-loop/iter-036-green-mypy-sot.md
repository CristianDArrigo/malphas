# Iter 036 — Green: single source of truth for mypy strict bucket

## Cosa è stato fatto

Eliminato il drift hazard documentato in iter-034: il bucket strict
era duplicato in `pyproject.toml`, `.github/workflows/ci.yml`,
`scripts/check.sh`. Ora vive in un solo posto.

### `pyproject.toml`

Due `[[tool.mypy.overrides]]` blocchi:

```toml
[[tool.mypy.overrides]]
module = ["malphas.replay", "malphas.crypto", ...]   # 14 strict modules
strict = true

[[tool.mypy.overrides]]
module = ["malphas.node", "malphas.transport",
          "malphas.api", "malphas.cli_ui",
          "malphas.__main__", "malphas.splash"]      # 6 lenient modules
disable_error_code = [
    "no-untyped-def", "no-untyped-call",
    "type-arg", "var-annotated", "no-any-return",
    "arg-type", "assignment", "attr-defined",
]
```

Lo `disable_error_code` è applicato SOLO ai 6 moduli lenient via
override mirato (un `disable_error_code` globale a livello
`[tool.mypy]` avrebbe disabilitato i check anche per i moduli strict
— verificato sperimentalmente).

### `.github/workflows/ci.yml`

Step "Mypy strict bucket" → "Mypy (strict bucket via pyproject
overrides)", invoca un singolo `mypy src/malphas/`. Niente più lista
di file hardcoded.

### `scripts/check.sh`

Stesso refactor: rimosso l'array `STRICT_BUCKET=(...)` e l'invocazione
`mypy --strict "${STRICT_BUCKET[@]}"`. Ora invoca `mypy src/malphas/`.

## Validation

Test sperimentale del gating:

```
$ # Aggiungo una funzione untyped a crypto.py (strict bucket)
$ mypy src/malphas/
crypto.py:154: error: Function is missing a type annotation [no-untyped-def]
Found 1 error
$ git checkout src/malphas/crypto.py
$ mypy src/malphas/
Success: no issues found in 21 source files
```

Lo stesso test in un modulo del lenient bucket (es. `node.py`) non
produce errori. Il gating è effettivo solo dove voluto.

## Versioning

Patch 0.5.3 → 0.5.4 (eng infra).

## Pattern adottato

D'ora in avanti, estendere il bucket strict richiede:

1. Modifica unica in `pyproject.toml`: spostare il modulo dalla
   lista lenient alla lista strict.
2. Run `scripts/check.sh --quick` per verificare.

Niente più tre file da tenere in sync.
