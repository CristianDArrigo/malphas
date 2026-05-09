# Iter 020 — Green: coverage gate + bandit

## Cosa è stato fatto

### Coverage gate

- `pytest-cov>=5` aggiunto a dev deps.
- `[tool.coverage.run]`:
  - `source = ["src/malphas"]`
  - `branch = true`
  - `omit`: tests, `__main__.py`, `cli_ui.py` (interactive surface).
- `[tool.coverage.report]`: exclude_lines per `pragma: no cover`,
  `raise NotImplementedError`, `if __name__ == .__main__.:`,
  `if TYPE_CHECKING:`. `precision = 1`.
- CI step `Run tests with coverage` ora invoca `pytest --cov
  --cov-fail-under=65` (blocking).

### Bandit

- `bandit>=1.7` aggiunto a dev deps.
- `[tool.bandit]`:
  - `exclude_dirs = ["tests", ".venv", "venv", "build", "dist", "frontend"]`
  - `skips`: B101 (assert in test), B104 (bind 0.0.0.0), B105 (false
    positive su passphrase overwrite), B110/B112 (fail-closed try/
    except/pass|continue), B311 (random per jitter), B324 (SHA1 come
    identifier, fix planned 0.4.0), B404/B603/B607 (subprocess per
    setup HS Tor).
- CI step `Bandit static security scan` (blocking).
- Risultato corrente: 0 findings.

### Misurazione locale

Coverage sulla suite focalizzata (15 test files, 255 test, no
test_api/test_cli/test_integration/test_functional_node):

```
TOTAL  2004 stmts  578 miss  438 branch  87 brpart  68.4%
```

Threshold CI 65% perché:
- La full suite (con test_api 91 tests + test_cli 132 tests +
  test_functional_node + test_integration) raggiunge significativamente
  di più sulla copertura di node.py, transport.py, api.py.
- Vogliamo un gate utile (block regressioni reali) senza essere
  bloccanti su iter conservative.

Future: alzare la threshold incrementalmente man mano che si scrivono
test mirati su transport.py (~20% ora) e api.py (0% nella focused).

### File toccati

- `pyproject.toml` (dev deps + tool sections)
- `.github/workflows/ci.yml` (coverage + bandit step)
- `CHANGELOG.md`

### Verifica

```
$ .venv/bin/bandit -r src/malphas/ -c pyproject.toml -l
0 findings.

$ .venv/bin/pytest <focused suite> --cov --cov-fail-under=65
255 passed, coverage 68.4%
```

## Versioning

Patch 0.3.4 → 0.3.5 (eng infra).

## CI gate stack ora attivo

| Gate | Tool | Status |
|------|------|--------|
| Style + bug | ruff | blocking |
| Types | mypy --strict (8 modules) | blocking |
| Security static | bandit | blocking |
| Tests + coverage | pytest --cov --cov-fail-under=65 | blocking |
| Property fuzz | hypothesis (within tests) | blocking |
