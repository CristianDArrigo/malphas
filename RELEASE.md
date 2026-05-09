# malphas — Release Process

> Status: **draft**, applies from `1.0.0-rc1`. Pre-1.0 was
> single-author tag-and-go with no signing or reproducibility
> guarantees. From rc1 onward we follow the steps below for every
> versioned release.

---

## 1 · Cadence and version policy

| Tag form           | Stage             | When                                                                |
|--------------------|-------------------|---------------------------------------------------------------------|
| `vX.Y.Z`           | stable            | After `rc` cycle resolves and external review (REVIEW_REQUEST.md) closes its high-severity findings. |
| `vX.Y.Z-rcN`       | release candidate | Wire-format-touching changes, or any change that needs soak time.   |
| (no tag)           | development       | Day-to-day commits. `pyproject.toml` carries the *next* RC version. |

SemVer with the wire-format carve-out documented in
[`PROTOCOL.md`](PROTOCOL.md) §10.

---

## 2 · Pre-release checklist

Before tagging anything, every item below must be ✅ on `main`.

- [ ] `pytest -q` clean (the documented pre-existing CLI failure
      tracked as TM-11 is the only allowed yellow; everything else
      green).
- [ ] `ruff check src/ tests/` clean.
- [ ] `mypy src/malphas` clean.
- [ ] `bandit -q -r src/malphas` returns 0 High findings.
- [ ] `coverage` ≥ 70 % on every module currently in the
      coverage gate (CI enforces).
- [ ] `THREAT_MODEL.md`, `PROTOCOL.md`, `CHANGELOG.md` all updated
      with the entries the release introduces.
- [ ] If the wire format moved (additive only — see PROTOCOL.md §10):
      a doc rev bump in PROTOCOL.md §15 and THREAT_MODEL.md §7.
- [ ] If new external deps were pulled: review their licences and
      add to TCB (THREAT_MODEL.md §4).

---

## 3 · Cutting the release

```bash
# 1. set the version (PEP 440: 1.0.0 / 1.0.0rc1 / 1.0.0a3 ...)
$EDITOR pyproject.toml

# 2. final sanity
ruff check src/ tests/
mypy src/malphas
bandit -q -r src/malphas
pytest -q

# 3. build (wheel + sdist)
python -m build

# 4. inspect what you're shipping
twine check dist/*
unzip -l dist/malphas-*.whl | grep -E "py$|png$"   # no surprises

# 5. tag with PGP
git tag -s vX.Y.Z -m "malphas X.Y.Z"
git push origin main vX.Y.Z

# 6. (RC only) attach to a GitHub pre-release; no PyPI upload
# 6. (stable) twine upload dist/* to PyPI
```

Tags **must** be PGP-signed. Unsigned tags are not authoritative
releases. The signing key fingerprint should appear in the README
once the first signed tag lands.

---

## 4 · Reproducible builds

Verified end-to-end as of `1.0.0-rc4`. Two invocations of
`scripts/build-reproducible.sh` against the same commit on the
same Python minor + hatchling minor produce wheels with
identical SHA-256.

What's pinned

- `pyproject.toml [build-system].requires`: `hatchling>=1.29,<1.30`.
- `scripts/build-reproducible.sh` exports
  `SOURCE_DATE_EPOCH=<git commit ts>`,
  `PYTHONHASHSEED=0`,
  `PYTHONDONTWRITEBYTECODE=1`,
  `LC_ALL=C`, `TZ=UTC`,
  `umask 022`.
- `Dockerfile.build` pins Python to `python:3.13-slim` and the
  build front-end to `build==1.5.0`. Anyone with Docker can
  reproduce a release artifact with no further config.

How to verify

```bash
# Local, requires Python 3.13.x and hatchling 1.29.x
bash scripts/verify-reproducibility.sh
# Containerized (recommended for cross-host verification)
docker build -f Dockerfile.build -t malphas-build .
docker run --rm -v "$PWD:/src" -w /src malphas-build \
    bash scripts/verify-reproducibility.sh
```

What still varies

- Python **patch** version: 3.13.7 vs 3.13.8 may differ. Pin to
  the same `python:3.13-slim` image digest as the release
  documents (see RELEASE.md §5).
- C extensions: malphas itself is pure Python. Transitive deps
  (`cryptography`, `argon2-cffi`) are pinned in `requirements.txt`
  for the runtime; for the build the wheel is `py3-none-any` so
  no extension code goes into our artifact.

THREAT_MODEL.md §5 TM-08 closed in iter-056.

---

## 5 · Release artifacts

Every stable release publishes:

| Artifact                               | Where               | Signed                          |
|----------------------------------------|---------------------|---------------------------------|
| Source tag                             | GitHub `vX.Y.Z`     | PGP                             |
| Source tarball                         | GitHub release      | PGP detached signature `.asc`   |
| Wheel `malphas-X.Y.Z-py3-none-any.whl` | PyPI                | PEP 458 (when reproducible)     |
| Sdist  `malphas-X.Y.Z.tar.gz`          | PyPI                | PEP 458 (when reproducible)     |

Pre-1.0 releases (the 0.x line) are **not** archived to PyPI. They
exist only as git tags.

---

## 6 · Post-release

- Bump `pyproject.toml` to the next RC version (`1.0.0rc2`,
  `1.1.0rc1`, …).
- Open the next milestone on GitHub.
- Append a "Release notes" section to `CHANGELOG.md` linking the
  GitHub release.

---

## 7 · Hotfixes

Wire-compatible fixes only. A hotfix `1.0.1` ships from a
`hotfix/1.0.x` branch that diverged from the `v1.0.0` tag. If the
fix would touch the wire format (auth, payload kinds, KDF info
strings, etc.) it is **not** a hotfix — it goes through a fresh RC
cycle.

---

## 8 · Yanking

If a release ships a security regression:

1. Yank the affected version from PyPI (`twine yank`).
2. Cut a fixed `X.Y.Z+1` immediately.
3. File a CVE if it's exploitable remotely.
4. Update `THREAT_MODEL.md` §5 with the lesson.
