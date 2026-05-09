# Iter 035 — Next-target selection

## Stato post 034

17 release nel loop autonomo: 0.2.0 → 0.5.3.

## Selezione iter-036

Mini-fix trovato durante iter-034: il bucket strict mypy è duplicato
in tre punti (pyproject `[[tool.mypy.overrides]]`, CI workflow,
`scripts/check.sh`). Ogni iter che estende il bucket deve toccarli
tutti e tre. Drift è inevitabile prima o poi.

**Scelgo Op-drift: single source of truth per il bucket strict.**

Approccio:

- Mantenere `[[tool.mypy.overrides]]` in `pyproject.toml` come fonte
  di verità (è quello che mypy stesso legge per `mypy src/` senza
  args). Così in CI invocheremo `mypy src/malphas/` senza esplicitare
  il bucket — mypy applica gli overrides per modulo automaticamente.
- Verificare che `mypy src/malphas/` (senza args) abbia esito
  equivalente al `mypy <bucket>` esplicito che oggi facciamo.
- Aggiornare `.github/workflows/ci.yml` step "Mypy strict bucket" a
  un singolo `mypy src/malphas/`.
- Aggiornare `scripts/check.sh` allo stesso pattern.
- Rimuovere la lista hardcoded di file in entrambi.

## Acceptance criteria

- `mypy src/malphas/` esce 0 in locale (con il bucket strict + i
  moduli non-strict in modalità non-strict).
- CI workflow lint job esegue `mypy src/malphas/` come singolo step.
- `scripts/check.sh` non hardcoda più i 14 file.
- Estendere il bucket diventa una modifica singola in `pyproject.toml`.

## Rischio

`mypy src/malphas/` esegue mypy su TUTTI i moduli, inclusi `node`,
`api`, `cli_ui`, `transport`, `__main__`, `splash`. Quelli non sono
strict, ma mypy potrebbe ancora trovare errori non-strict. La config
`[tool.mypy]` ha `strict = false` come default, ma il livello
non-strict di mypy emette comunque qualche warning.

Test prima: provo `mypy src/malphas/` localmente e vedo cosa esce.
Se ci sono errori, devo decidere se fixarli (annotation deboli) o
escludere quei file via `[tool.mypy]` `exclude`.

Versioning: 0.5.3 → 0.5.4 (eng infra).
