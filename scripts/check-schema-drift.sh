#!/usr/bin/env bash
# Verify that running migrations on an empty database reproduces the live
# schema exactly. Catches hand-made DDL that never became a migration.
set -euo pipefail
cd "$(dirname "$0")/.."

LIVE="${SENTINEL_PG_DB:-sentinel}"
TMPDB="_schemadrift_$$"
trap 'dropdb --if-exists "$TMPDB" 2>/dev/null || true' EXIT

createdb "$TMPDB"
SENTINEL_PG_DSN="postgresql://localhost:5432/$TMPDB" .venv/bin/sentinel db migrate >/dev/null 2>&1

# Strip pg_dump session noise: \restrict tokens are random per invocation.
strip() { grep -vE '^--|^$|^SET |^SELECT pg_catalog|^\\(un)?restrict' ; }

pg_dump -d "$TMPDB" --schema-only --no-owner --no-privileges 2>/dev/null | strip > /tmp/schema-fresh.sql
pg_dump -d "$LIVE"  --schema-only --no-owner --no-privileges 2>/dev/null | strip > /tmp/schema-live.sql

if diff -u /tmp/schema-fresh.sql /tmp/schema-live.sql > /tmp/schema-drift.diff; then
  echo "OK: migrations reproduce the live schema exactly"
else
  echo "DRIFT: the live schema differs from what migrations produce"
  echo "  '-' = only in migrations, '+' = only in live (i.e. never migrated)"
  cat /tmp/schema-drift.diff
  exit 1
fi
