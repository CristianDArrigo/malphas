# Contributing to malphas

Thanks for considering a patch. malphas is a privacy-first messenger;
the design is deliberate and changes get measured against a tight
threat model. The notes below describe how to land code that matches
how the project already works.

## Before you start

- Read the relevant section of [README.md](README.md), especially
  **Threat Model**, **Cryptographic Stack**, and the **CI quality
  gates** subsection.
- Read [SECURITY.md](SECURITY.md) for vulnerability reporting (do not
  open a public issue for security problems).
- Check `docs/auto-loop/SUMMARY.md` for a high-level overview of
  recent work and the items that are deliberately out of scope.

## Local setup

```bash
git clone https://github.com/CristianDArrigo/malphas.git
cd malphas
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional but recommended
```

## Run the gates

The exact stack the CI runs, in fail-fast order:

```bash
scripts/check.sh                # ruff + mypy + bandit + pytest --cov
scripts/check.sh --quick        # skip pytest (good for pre-commit)
scripts/check.sh --no-coverage  # pytest without --cov gate
```

A green `scripts/check.sh` is the single contract for "ready to push".

## Style

- Python 3.10+. Type-annotate new code; if it lands in
  `src/malphas/<module>.py` you'll be checked against the strict
  bucket. The bucket lives in `pyproject.toml`
  `[[tool.mypy.overrides]] strict = true`.
- Follow ruff defaults plus the rules `select`-ed in
  `[tool.ruff.lint]`. The rationale for any `noqa` belongs in a
  comment on the same line.
- Tests live in `tests/`, mirror the module name (`test_<module>.py`),
  use `pytest` async via `asyncio_mode = auto`. New code without
  tests is unlikely to be merged.

## Wire format and breaking changes

- Anything that changes the bytes a peer puts on the wire is
  **wire-breaking**. It bumps the **minor** version (e.g. 0.4.0 → 0.5.0)
  and goes in CHANGELOG with the explicit `WIRE-BREAKING` marker.
- malphas does **not** ship compatibility shims between minor
  versions. Both peers in a conversation must run the same minor.
- When in doubt, ask in an issue first.

## Threat-model-relevant changes

If a patch touches identity, transport, onion, ratchet, replay, or
the address book on-disk format, please:

- Reference the threat model in the PR description.
- Note in the description which items in **Protected against** /
  **Partially protected** / **Not protected against** the change
  affects, and how.
- Add a regression test that fails without the patch.

## Commit style

- Imperative subject ≤ 70 chars. Body wraps at ~78. Reference issues
  by number where applicable.
- Group related changes. Prefer one logical change per commit.
- The repo includes "auto-loop" commits from autonomous development
  sessions (see `docs/auto-loop/`); follow the same density when you
  hand-write commits.

## PRs

- Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md). Fill in
  every section that applies.
- Run `scripts/check.sh` locally first.
- One reviewer is enough for non-security patches; for anything in
  the threat-model-relevant list above, ask explicitly for a security
  review.

## What is in scope

- Bug fixes in any module.
- Test coverage for under-tested modules.
- Hardening of existing security mechanisms.
- Documentation and developer-experience improvements.
- New transports, file formats, or wire-format upgrades — please
  open an issue first to align on design.

## What is out of scope (without prior discussion)

- Telemetry, analytics, or anything that calls home.
- Plaintext storage of sensitive material.
- A web frontend that bundles a new framework without first
  discussing it.
- Anything that changes `panic()` to do less.
