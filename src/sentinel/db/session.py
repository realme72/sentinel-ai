"""Postgres access. One pool, explicit transactions, no ORM.

An ORM would buy little here: the interesting queries are hybrid-retrieval
SQL and bulk upserts, both of which read better hand-written. `psycopg3`'s
server-side binding gives us parameterisation without string building.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from sentinel.config import get_settings

_pool: ConnectionPool | None = None

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = ConnectionPool(
            settings.pg_dsn,
            min_size=1,
            max_size=10,
            kwargs={"row_factory": dict_row},
            open=True,
        )
    return _pool


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """A pooled connection wrapped in a transaction.

    Commits on clean exit, rolls back on exception. Callers should not commit
    by hand -- a half-applied scan is worse than a failed one.
    """
    with get_pool().connection() as conn:
        yield conn


@contextmanager
def cursor() -> Iterator[psycopg.Cursor]:
    with connection() as conn, conn.cursor() as cur:
        yield cur


def query(sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> list[dict]:
    with cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> dict | None:
    with cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> int:
    with cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def apply_schema() -> None:
    with connection() as conn:
        conn.execute(SCHEMA_PATH.read_text())


def build_vector_index(*, m: int = 16, ef_construction: int = 64) -> None:
    """Build the HNSW index AFTER bulk load, never before.

    Inserting a million rows into an existing HNSW index is dramatically
    slower than inserting them and then building it once, because every insert
    has to traverse and patch the graph.
    """
    with connection() as conn:
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON corpus_chunks
            USING hnsw (embedding vector_cosine_ops)
            WITH (m = {int(m)}, ef_construction = {int(ef_construction)})
            """
        )


def reset_database() -> None:
    """Drop every table and reapply the schema. Destructive, dev-only."""
    with connection() as conn:
        conn.execute(
            """
            DO $$ DECLARE r RECORD; BEGIN
              FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname='public')
              LOOP EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE'; END LOOP;
            END $$;
            """
        )
    apply_schema()


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
