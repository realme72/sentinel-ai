"""Mirror corpus_chunks into a secondary vector store.

Dual-writing across two systems cannot be transactional, so this does not
pretend otherwise: it is an idempotent full sync keyed on chunk_id, safe to
re-run, with a reconcile check that reports drift rather than hiding it.
"""

from __future__ import annotations

import time

import numpy as np
import structlog

from sentinel.db.session import query
from sentinel.rag.store import ChunkRecord, VectorStore

log = structlog.get_logger()


def _load_chunks(batch: int = 512):
    rows = query(
        "SELECT id, content, cve_ids, source, os_family, embedding::text AS emb "
        "FROM corpus_chunks WHERE embedding IS NOT NULL ORDER BY id"
    )
    for i in range(0, len(rows), batch):
        yield [
            ChunkRecord(
                chunk_id=r["id"], content=r["content"], cve_ids=r["cve_ids"],
                source=r["source"], os_family=r["os_family"],
                embedding=np.fromstring(r["emb"].strip("[]"), sep=",", dtype=np.float32),
            )
            for r in rows[i:i + batch]
        ]


def sync_store(store: VectorStore) -> dict:
    t0 = time.perf_counter()
    store.ensure_ready()
    written = 0
    for batch in _load_chunks():
        written += store.upsert(batch)

    source_count = query(
        "SELECT count(*) AS n FROM corpus_chunks WHERE embedding IS NOT NULL"
    )[0]["n"]
    target_count = store.count()
    drift = source_count - target_count

    log.info("rag.synced", backend=store.name, written=written,
             source=source_count, target=target_count, drift=drift)
    return {
        "backend": store.name, "written": written,
        "source_chunks": source_count, "target_chunks": target_count,
        "drift": drift, "seconds": round(time.perf_counter() - t0, 1),
    }
