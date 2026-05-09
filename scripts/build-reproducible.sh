#!/usr/bin/env bash
# Reproducible-build entry point (TM-08).
#
# Produces a wheel + sdist whose contents are byte-deterministic for
# a given source tree. Two invocations against the same commit on
# the same Python minor + hatchling minor must produce wheels with
# matching SHA-256.
#
# What we pin:
#   SOURCE_DATE_EPOCH       -> the last commit timestamp (no clock leak)
#   PYTHONHASHSEED          -> 0 (no hash randomization in build code)
#   PYTHONDONTWRITEBYTECODE -> 1 (no .pyc artifacts in the wheel)
#   umask 022               -> stable file modes inside the wheel
#   LC_ALL=C / TZ=UTC       -> stable sort order, stable timestamps
#
# What still varies between hosts:
#   - Python patch version: 3.13.7 vs 3.13.8 may differ. Use the
#     same minor (3.13.x) and the same hatchling minor (1.29.x) as
#     pinned in pyproject.toml [build-system].requires.
#   - C extensions: malphas is pure Python. No risk here.
#
# Verification:
#   ./scripts/verify-reproducibility.sh

set -euo pipefail

cd "$(dirname "$0")/.."

# Use the source's last commit time as the wheel timestamp. Falls
# back to the current epoch only when not in a git checkout.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
else
    SOURCE_DATE_EPOCH="$(date -u +%s)"
fi
export SOURCE_DATE_EPOCH

export PYTHONHASHSEED=0
export PYTHONDONTWRITEBYTECODE=1
export LC_ALL=C
export TZ=UTC
umask 022

echo "→ Reproducible build context"
echo "    SOURCE_DATE_EPOCH = ${SOURCE_DATE_EPOCH} ($(date -u -d @"${SOURCE_DATE_EPOCH}" +%FT%TZ 2>/dev/null || true))"
echo "    Python            = $(python3 --version 2>&1)"
echo "    hatchling         = $(python3 -m pip show hatchling 2>/dev/null | awk '/^Version:/ {print $2}')"

rm -rf dist build src/*.egg-info

echo "→ Building"
python3 -m build --no-isolation

echo "→ Artifacts"
ls -la dist/

echo "→ SHA-256"
( cd dist && sha256sum -- *.whl *.tar.gz )
