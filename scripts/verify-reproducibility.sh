#!/usr/bin/env bash
# Verify that the build is reproducible (TM-08).
#
# Builds twice into separate dist directories with the canonical
# environment knobs (see build-reproducible.sh) and diffs the
# SHA-256 hashes of both wheels. Exit non-zero if any artifact
# differs.
#
# Run before tagging a release; CI may also run this on PRs that
# touch packaging.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x scripts/build-reproducible.sh ]]; then
    echo "scripts/build-reproducible.sh missing or not executable" >&2
    exit 2
fi

OUT_A=$(mktemp -d -t malphas-build-A.XXXX)
OUT_B=$(mktemp -d -t malphas-build-B.XXXX)
trap 'rm -rf "$OUT_A" "$OUT_B"' EXIT

build() {
    local out="$1"
    rm -rf dist
    bash scripts/build-reproducible.sh >/dev/null
    cp -r dist "$out"/
}

echo "→ first build"
build "$OUT_A"
echo "→ second build (should match byte-for-byte)"
build "$OUT_B"

echo
echo "Build A SHA-256:"
( cd "$OUT_A/dist" && sha256sum -- *.whl *.tar.gz )
echo
echo "Build B SHA-256:"
( cd "$OUT_B/dist" && sha256sum -- *.whl *.tar.gz )
echo

A_HASHES=$( cd "$OUT_A/dist" && sha256sum -- *.whl *.tar.gz | awk '{print $1}' | sort )
B_HASHES=$( cd "$OUT_B/dist" && sha256sum -- *.whl *.tar.gz | awk '{print $1}' | sort )

if [[ "$A_HASHES" == "$B_HASHES" ]]; then
    echo "✓ reproducible: both builds produced identical artifacts"
    exit 0
else
    echo "✗ NOT reproducible: artifact hashes differ" >&2
    diff <(echo "$A_HASHES") <(echo "$B_HASHES") || true
    exit 1
fi
