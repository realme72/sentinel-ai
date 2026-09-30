"""pgvector backend.

The vectors live in the same database as findings, assets and cves, so a
filtered search is an ordinary SQL predicate and results can be joined to
business data without reconciling IDs across systems.

The trade-off to watch: Postgres plans a filtered vector search as either an
HNSW scan with a post-filter, or a heap scan with the filter pushed down,
depending on what the planner believes about selectivity. When it chooses
wrong on a highly selective filter, recall drops silently -- which is the
behaviour the Qdrant comparison exists to quantify.
"""

from __future__ import annotations

import numpy as np

from sentinel.db.session import connection
from sentinel.rag.store import ChunkRecord, SearchHit


def _vec(v: np.ndarray) -> str:
    return "[" + ",".join(f"{float(x):.6f}" for x in v) + "]"


class PgVectorStore:
    name = "pgvector"

    def __init__(self, ef_search: int = 64) -> None:
        # Query-time recall/latency dial. Higher keeps a longer candidate list.
        self.ef_search = ef_search

    def ensure_ready(self) -> None:
        with connection() as conn:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON corpus_chunks "
                "USING hnsw (embedding vector_cosine_ops) "
                "WITH (m = 16, ef_construction = 64)"
            )

    def upsert(self, records: list[ChunkRecord]) -> int:
        # The corpus builder already writes these rows; this exists so the
        # Protocol is honestly satisfied and the store is usable standalone.
        if not records:
            return 0
        with connection() as conn, conn.cursor() as cur:
            cur.executemany(
                "UPDATE corpus_chunks SET embedding = %s::vector WHERE id = %s",
                [(_vec(r.embedding), r.chunk_id) for r in records],
            )
            return cur.rowcount

    def search(self, vector, k, *, cve_ids=None, source=None) -> list[SearchHit]:
        where, params = [], [_vec(vector)]
        if cve_ids:
            where.append("cve_ids && %s")
            params.append(list(cve_ids))
        if source:
            where.append("source = %s")
            params.append(source)
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        sql = f"""
            SELECT id, content, cve_ids, source,
                   1 - (embedding <=> %s::vector) AS score
            FROM corpus_chunks
            {clause}
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        params.append(_vec(vector))
        params.append(k)

        with connection() as conn, conn.cursor() as cur:
            cur.execute(f"SET LOCAL hnsw.ef_search = {int(self.ef_search)}")
            cur.execute(sql, params)
            return [
                SearchHit(
                    chunk_id=r["id"], score=float(r["score"]), content=r["content"],
                    cve_ids=r["cve_ids"], source=r["source"], backend=self.name,
                )
                for r in cur.fetchall()
            ]

    def count(self) -> int:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM corpus_chunks WHERE embedding IS NOT NULL")
            return cur.fetchone()["n"]
