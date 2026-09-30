# Postgres: inspection and migration runbook

Sentinel-AI targets **PostgreSQL 18**. Homebrew's `postgresql@18` is linked, so
plain `psql` is 18.x. Older kegs stay installed but unlinked; reach them by
absolute path (`/opt/homebrew/opt/postgresql@16/bin/psql`).

```bash
psql -d sentinel
```

## Inspecting the database

| Command | Shows |
|---|---|
| `\l+` | all databases with sizes and owners |
| `\c sentinel` | connect to a database |
| `\dt+` | tables with size and row estimates |
| `\d findings` | one table: columns, indexes, FKs, constraints |
| `\d+ findings` | the above plus storage, defaults, comments |
| `\di+` | indexes with sizes |
| `\dx` | installed extensions |
| `\du` | roles |
| `\df` | functions |
| `\dn` | schemas |
| `\x` | toggle expanded output (essential for wide rows) |
| `\timing` | show query durations |
| `\e` | edit the last query in `$EDITOR` |
| `\q` | quit |

Add `-P pager=off` to a `psql -c` invocation if results keep opening in a pager.

```sql
-- biggest tables first
SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS total
FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC;

-- row counts
SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;

-- currently running queries
SELECT pid, state, wait_event_type, left(query, 80) AS query
FROM pg_stat_activity WHERE datname = 'sentinel' AND state <> 'idle';

-- slowest queries by total time (needs pg_stat_statements)
SELECT round(total_exec_time::numeric, 1) AS total_ms,
       calls,
       round(mean_exec_time::numeric, 2) AS mean_ms,
       left(query, 90) AS query
FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 15;

-- reset the counters before a benchmark run
SELECT pg_stat_statements_reset();

-- is an index actually being used?
SELECT indexrelname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes WHERE relname = 'corpus_chunks' ORDER BY idx_scan DESC;
```

## Extensions and why each is installed

| Extension | Purpose here |
|---|---|
| `vector` 0.8.6 | dense retrieval; HNSW index on `corpus_chunks.embedding` |
| `pg_trgm` | fuzzy match on package and version strings |
| `btree_gin` | composite GIN indexes mixing scalar columns with arrays |
| `citext` | case-insensitive `hostname` / `owner_email` — `WEB-01` and `web-01` are one host |
| `pgcrypto` | `digest()` for ticket idempotency keys |
| `unaccent` | normalises vendor advisory text before `tsvector` |
| `pg_stat_statements` | per-query latency; needs `shared_preload_libraries` + restart |

## Migrating between major versions

Postgres major versions have **incompatible on-disk formats**. A PG 16 data
directory cannot be read by PG 18. There are exactly two ways across.

### The rule people get wrong

> Always use the **newer** version's `pg_dump` / `pg_dumpall`.

A newer client can read an older server. The reverse is unsupported and will
either error or produce a subtly bad dump.

### Option A — `pg_upgrade` (binary, in place)

Fast, preserves roles, grants and extensions.

```bash
brew services stop postgresql@16
/opt/homebrew/opt/postgresql@18/bin/pg_upgrade --check \
  -b /opt/homebrew/opt/postgresql@16/bin -B /opt/homebrew/opt/postgresql@18/bin \
  -d /opt/homebrew/var/postgresql@16   -D /opt/homebrew/var/postgresql@18
# drop --check to run it for real
```

Two traps:

- **Every extension must already be installed for the target version** before
  you run it, or the check fails. Install `pgvector` for 18 first.
- `--link` hardlinks instead of copying (much faster), but a *failed* upgrade
  then leaves the **old** cluster unusable too. Don't use it without a dump.

### Option B — dump and restore (logical)

Portable, produces a file, works across any version distance.

```bash
PG18=/opt/homebrew/opt/postgresql@18/bin
"$PG18/pg_dumpall" -p 5432 -f ~/cluster-full.sql          # everything incl. roles
"$PG18/pg_dump"    -p 5432 -Fc -d sentinel -f ~/sentinel.dump   # one database
# ... start the new server on 5432 ...
createdb sentinel
pg_restore -d sentinel --no-owner --no-privileges ~/sentinel.dump
```

At this project's size (tens of MB) this takes seconds, so `pg_upgrade`'s speed
advantage buys nothing. Prefer B until the cluster is large.

### Downgrading (18 → 16)

`pg_upgrade` **cannot go backwards.** The format is forward-only.

The only path is logical: dump from 18, strip any 17/18-only syntax by hand,
restore into 16. Tedious, occasionally impossible.

So downgrade is not a procedure, it is a *preparation*:

1. Take a `pg_dumpall` **before** upgrading, and
2. Don't delete the old cluster's data directory until you're confident.

A retained old cluster turns rollback into "start the other service".

## This machine's history

- **2026-09-30** — migrated 16.13 → 18.6. `blogboard_db` and `chaliye` were
  retired (not migrated); `sentinel` was dump/restored. Backups:
  `~/Documents/pg16-backup-20260930/` (full cluster SQL + per-database custom
  dumps). The PG 16 keg and its data directory are still on disk, stopped.

To reclaim that space once you're happy:

```bash
brew services stop postgresql@16 2>/dev/null
brew uninstall postgresql@16
rm -rf /opt/homebrew/var/postgresql@16
```
