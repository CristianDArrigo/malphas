# Iter 040 — Green: dependabot + pre-commit

## Cosa è stato fatto

### `.github/dependabot.yml`

- Ecosistema `pip`: PR settimanali (lunedì 06:00). Limite 5 PR aperte.
  Group "runtime" raggruppa minor/patch bumps in un singolo PR per
  ridurre review noise. Label `deps`, `python`.
- Ecosistema `github-actions`: stesso schema, limit 3, label
  `deps`, `ci`.

### `.pre-commit-config.yaml`

Mirror locale di `scripts/check.sh --quick`:

- `ruff` v0.7.4 con `--fix`, files `^(src|tests)/`.
- `mypy` v1.13.0 su `src/malphas/` (full package — gli override
  pyproject applicano lo strict bucket esattamente come in CI).
  `additional_dependencies` include `cryptography>=42.0` e
  `argon2-cffi>=23.0` perché mypy ha bisogno di importarli per i
  moduli strict.
- `bandit` 1.9.4 con `-r -c pyproject.toml -l`.
- `pre-commit/pre-commit-hooks` v5.0.0 — hygiene base:
  trailing-whitespace, end-of-file-fixer, check-yaml, check-toml,
  check-merge-conflict, check-added-large-files (--maxkb=512).

### README

"CI quality gates" subsection esteso:
- Box install di `pre-commit`.
- Nota sul flow Dependabot (weekly grouped PR).

## Versioning

Patch 0.5.5 → 0.5.6 (dev infra).

## Garanzie non testabili

- `dependabot.yml` viene parsed solo da GitHub. Sintassi v2 standard;
  validation manuale.
- `pre-commit-config.yaml` viene eseguito solo se l'utente fa
  `pre-commit install`. Il config riusa rev/version già provate
  localmente in iter-018 (ruff 0.7.4 era la rev iniziale del CI;
  mypy 1.13.0 stable).

## Note di rallentamento

Il loop continua a fornire micro-task non-controversi durante la
finestra senza input utente. Le opzioni residue di sostanza (sealed
sender, group chat, per-user salt, BIP39, GUI) restano fuori scope
fino a istruzione utente.

Prossima iter potrebbe essere: GitHub PR template + CONTRIBUTING.md
(altro micro-infra), o repo hygiene (LICENSE check, CITATION).
