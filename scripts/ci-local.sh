#!/usr/bin/env bash
# Run what CI runs, locally, against a throwaway venv and database.
#
# The point is the *throwaway* parts: CI has already caught one dependency
# that was only ever installed into the dev venv by hand, and a config path
# that only existed on the dev machine. Testing against the working
# environment cannot find either.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=$(mktemp -d)/venv
DB="_cilocal_$$"
trap 'dropdb --if-exists "$DB" 2>/dev/null || true; rm -rf "$(dirname "$VENV")"' EXIT

echo "==> clean venv"
uv venv --python 3.12 "$VENV" -q
VIRTUAL_ENV="$VENV" uv pip install -q -e ".[dev]"

echo "==> clean database"
createdb "$DB"
export SENTINEL_PG_DSN="postgresql://localhost:5432/$DB"

echo "==> lint";                   "$VENV/bin/ruff" check src tests
echo "==> migrate (from empty)";   "$VENV/bin/sentinel" db migrate >/dev/null
echo "==> migrate (idempotent)";   "$VENV/bin/sentinel" db migrate >/dev/null
echo "==> tests";                  "$VENV/bin/pytest" -q

echo
echo "CI-equivalent checks passed"
