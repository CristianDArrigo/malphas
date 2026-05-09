# iter-056 — TM-08 reproducible builds

**Date:** 2026-05-09
**Trigger:** scheduled follow-up. Last open release-process gate.

## What landed

### Build pinning
- `pyproject.toml [build-system].requires`:
  `hatchling>=1.29,<1.30`. Comment in-place tells maintainers to
  re-run `verify-reproducibility.sh` and update the documented
  expected hashes when the pin moves.

### Scripts
- `scripts/build-reproducible.sh`: produces `dist/*.whl` and
  `dist/*.tar.gz` with `SOURCE_DATE_EPOCH = git commit ts`,
  `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`, `LC_ALL=C`,
  `TZ=UTC`, `umask 022`. Prints SHA-256 of every artifact.
- `scripts/verify-reproducibility.sh`: builds twice into separate
  tempdirs, compares SHA-256 of both wheels and sdists, exits
  non-zero on any mismatch.

### Container
- `Dockerfile.build`: `python:3.13-slim` + pinned `build==1.5.0`
  + pinned `hatchling>=1.29,<1.30` + the same env knobs. Lets a
  reviewer reproduce a release without trusting the host
  toolchain.

### Verification (live)

Ran `bash scripts/verify-reproducibility.sh` against the working
tree. Both builds produced identical artifacts:

```
6079c6ab0abee68314d5fdfe64747ba41196692e6f83aa9cc45a07ba04274d11  malphas-1.0.0rc3-py3-none-any.whl
6d9ab16d4bdf657676e924c4b6ef1c40381f1708f8b3ba24eb60f6b8d05cc19a  malphas-1.0.0rc3.tar.gz
```

Same hashes on the second run. ✓

### Docs
- `RELEASE.md` §4 rewritten as a closed item with concrete
  commands (host + Docker variants) and the residual variability
  documented (Python patch version, transitive C extensions).
- `THREAT_MODEL.md`: TM-08 marked resolved, non-guarantees row
  reworded to "Yes (iter-056)".

## Version

1.0.0rc3 → 1.0.0rc4 (additive: same wire, new build infra).

## Status of TM table after this iter

| ID    | Status                | Notes                                                  |
|-------|-----------------------|--------------------------------------------------------|
| TM-01 | Medium partial        | Operational consensus shipped; cryptographic PCS TBD.  |
| TM-02 | Parked                | External review deferred at user request.              |
| TM-03 | Resolved              | Wire frozen at 1.0.0-rc1.                              |
| TM-04 | By design             | TOFU window — documented.                              |
| TM-05 | Resolved              | iter-054.                                              |
| TM-06 | Open (low priority)   | Cover traffic basic.                                   |
| TM-07 | Open (low priority)   | Non-deniable signatures.                               |
| TM-08 | Resolved              | iter-056 (this iter).                                  |
| TM-09 | By design             | Receipt omission attack.                               |
| TM-10 | Low                   | Padding granularity leaks contact-count band.          |
| TM-11 | Open                  | Pre-existing CLI test (Mock(_groups)).                 |

Two open items I can autonomously close in the next iter: TM-11
(trivial mock fix) and PROTOCOL.md §14 test vectors. After that,
TM-02 was deferred at user request after this iter.

## Next iter

iter-057 — TM-11 fix the CLI test mock + start the protocol test
vectors file (`tests/test_protocol_vectors.py`) with the first
two vectors (sealed_sender, ratchet header).
