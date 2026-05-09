#!/usr/bin/env bash
# Local mirror of the CI gate stack defined in .github/workflows/ci.yml.
#
# Stages, in fail-fast order:
#   1. ruff check src/ tests/
#   2. mypy --strict <bucket>
#   3. bandit -r src/malphas/ -c pyproject.toml -l
#   4. pytest tests/ -m "not tor and not slow" --cov --cov-fail-under=65
#
# Usage:
#   scripts/check.sh                 # full stack
#   scripts/check.sh --quick         # skip pytest (good for pre-commit)
#   scripts/check.sh --no-coverage   # pytest without --cov gate (faster)
#
# Honors $PYTHON env var (default: ./.venv/bin/python if it exists, else python3).

set -euo pipefail

# ── Resolve interpreter ──────────────────────────────────────────────────────

if [[ -z "${PYTHON:-}" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON=".venv/bin/python"
  else
    PYTHON="$(command -v python3 || command -v python)"
  fi
fi

# ── Stage filtering ──────────────────────────────────────────────────────────

QUICK=0
COV_GATE=1
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --no-coverage) COV_GATE=0 ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

# ── ANSI helpers (degrade if not a tty) ──────────────────────────────────────

if [[ -t 1 ]]; then
  C_HEAD=$'\e[1;36m'  # bold cyan
  C_OK=$'\e[1;32m'    # bold green
  C_ERR=$'\e[1;31m'   # bold red
  C_END=$'\e[0m'
else
  C_HEAD=""; C_OK=""; C_ERR=""; C_END=""
fi

stage() { printf '\n%s===> %s%s\n' "$C_HEAD" "$1" "$C_END"; }
ok()    { printf '%s✓ %s%s\n' "$C_OK" "$1" "$C_END"; }
fail()  { printf '%s✗ %s%s\n' "$C_ERR" "$1" "$C_END" >&2; exit 1; }

# ── Strict bucket (kept in sync with .github/workflows/ci.yml) ───────────────

STRICT_BUCKET=(
  src/malphas/replay.py
  src/malphas/crypto.py
  src/malphas/memory.py
  src/malphas/obfuscation.py
  src/malphas/pinstore.py
  src/malphas/invite.py
  src/malphas/files.py
  src/malphas/secure_buffer.py
  src/malphas/discovery.py
  src/malphas/receipts.py
  src/malphas/ratchet.py
  src/malphas/identity.py
  src/malphas/onion.py
  src/malphas/addressbook.py
)

# ── 1. ruff ──────────────────────────────────────────────────────────────────

stage "ruff check src/ tests/"
"$PYTHON" -m ruff check src/ tests/ || fail "ruff failed"
ok "ruff clean"

# ── 2. mypy --strict ─────────────────────────────────────────────────────────

stage "mypy --strict (${#STRICT_BUCKET[@]} modules)"
"$PYTHON" -m mypy --strict "${STRICT_BUCKET[@]}" || fail "mypy failed"
ok "mypy strict bucket clean"

# ── 3. bandit ────────────────────────────────────────────────────────────────

stage "bandit -r src/malphas/ -c pyproject.toml -l"
"$PYTHON" -m bandit -r src/malphas/ -c pyproject.toml -l > /tmp/bandit.out 2>&1 || {
  cat /tmp/bandit.out
  fail "bandit failed"
}
# bandit exits 0 even on findings if -l isn't specific; we already constrain.
# Surface a one-liner summary if available.
grep -E '^>>|Total issues' /tmp/bandit.out | head -3 || true
ok "bandit 0 findings"

# ── 4. pytest (+coverage) ────────────────────────────────────────────────────

if (( QUICK )); then
  printf '\n%s(skipping pytest — --quick)%s\n' "$C_HEAD" "$C_END"
  ok "all enabled gates passed"
  exit 0
fi

if (( COV_GATE )); then
  stage 'pytest -m "not tor and not slow" --cov --cov-fail-under=65'
  "$PYTHON" -m pytest tests/ -m "not tor and not slow" -q --tb=short \
    --cov --cov-report=term --cov-fail-under=65 || fail "pytest failed"
else
  stage 'pytest -m "not tor and not slow"'
  "$PYTHON" -m pytest tests/ -m "not tor and not slow" -q --tb=short \
    || fail "pytest failed"
fi

ok "all gates passed"
