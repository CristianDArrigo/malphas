# Iter 044 — Green: contributor templates

## Cosa è stato fatto

Quattro file di "community / repo hygiene":

### `CONTRIBUTING.md`

Onboarding completo:
- Pre-requisiti di lettura (README threat model, SECURITY.md,
  SUMMARY.md).
- Local setup (venv, pip install -e ".[dev]", pre-commit install).
- Gate stack via `scripts/check.sh`.
- Policy di style (Python 3.10+, type-annotate per strict bucket,
  ruff defaults, tests required).
- Wire-breaking policy: bump minor, marker WIRE-BREAKING in
  CHANGELOG, no compatibility shims.
- Threat-model-relevant changes: regression test required, PR
  description deve referenziare la tabella threat model.
- Commit style.
- In/Out of scope.

### `.github/PULL_REQUEST_TEMPLATE.md`

Form-based:
- Type of change (bug fix / feature / refactor / docs / security /
  WIRE-BREAKING).
- Threat-model impact (richiesto per security/wire-breaking).
- Local checks checklist (scripts/check.sh, CHANGELOG, strict
  bucket bookkeeping).
- Risk note.

### `.github/ISSUE_TEMPLATE/bug_report.yml`

Structured form GitHub:
- Header che reindirizza security-issue altrove (SECURITY.md).
- Campi: what happened, expected, repro steps, malphas/python/OS
  versions, transport (Direct/Tor/Both), extra notes.

### `.github/ISSUE_TEMPLATE/feature_request.yml`

- Reindirizza prima a SUMMARY.md "What was NOT touched".
- Campi: problem, proposal, scope dropdown, alternatives, threat
  model impact, confirmation checkbox.

### `.github/ISSUE_TEMPLATE/config.yml`

- `blank_issues_enabled: false`.
- Contact links: Security advisories (GitHub UI), Discussions per
  "how do I" questions.

## Versioning

Patch 0.5.7 → 0.5.8 (community / repo hygiene).

## Note di stato

Questa è probabilmente l'ultima iter di micro-maintenance del loop
prima di un'effettiva pausa. Le opzioni residue richiedono input
utente sostanziale.

Le tre micro-iter post-hand-off (dependabot+pre-commit, version+
py.typed, contributor templates) sono state tutte non-controverse,
non hanno toccato il source code di crypto/transport/wire, e hanno
chiuso 1 finding del review iniziale (C7 — `__version__` obsoleto).

Bilancio del loop: 22 release, 38+ iter, ~3.5 ore di lavoro auto.
