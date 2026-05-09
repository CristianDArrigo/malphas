## Summary

<!-- One paragraph: what this PR does and why. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / dev tooling
- [ ] Documentation
- [ ] Security hardening
- [ ] **Wire-breaking** change (bumps the minor version)

## Threat-model impact

<!-- Required if you ticked "Security hardening" or "Wire-breaking" -->

- Affects which row of the README "Threat Model" table?
- New regression test? `tests/test_<...>.py::<...>`

## Local checks

- [ ] `scripts/check.sh` is green (ruff + mypy + bandit + pytest --cov)
- [ ] CHANGELOG.md updated under the next version
- [ ] If wire-breaking: CHANGELOG entry has the `WIRE-BREAKING` marker
- [ ] If a new module: added to the strict bucket in `pyproject.toml`,
  or explicitly listed as lenient with a one-liner rationale

## Risk

<!-- Anything reviewer should look at extra carefully? Anything that
could surprise an existing user? -->
