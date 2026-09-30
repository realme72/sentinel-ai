"""pgvector vs Qdrant: recall and latency on this corpus.

The interesting axis is *filtered* search. Unfiltered nearest-neighbour is a
solved problem both engines do well; the difference shows up when a selective
metadata filter is applied, because that is where a general-purpose store has
to choose between abandoning its index and post-filtering too few results.

Ground truth is exact here, which is unusual and worth exploiting: for a query
naming CVE-X, the relevant chunks are precisely the chunks whose cve_ids
contain CVE-X. No human labelling, no judgement calls.
"""

from __future__ import annotations

import statistics
import time

import structlog

from sentinel.db.session import query
from sentinel.rag.embed import embed_query, get_model
from sentinel.rag.store import VectorStore

log = structlog.get_logger()


def sample_queries(n: int = 60) -> list[dict]:
    """Sample CVEs weighted toward ones that matter (KEV, high EPSS, many
    findings) plus a random tail, so the benchmark is not all easy cases."""
    return query(
        """
        (SELECT c.cve_id, c.description, count(f.id) AS findings
         FROM cves c JOIN findings f ON f.cve_id = c.cve_id
         WHERE c.kev_listed OR c.epss_score > 0.1
         GROUP BY c.cve_id, c.description ORDER BY count(f.id) DESC LIMIT %s)
        UNION
        (SELECT c.cve_id, c.description, count(f.id)
         FROM cves c JOIN findings f ON f.cve_id = c.cve_id
         WHERE c.description IS NOT NULL
         GROUP BY c.cve_id, c.description ORDER BY md5(c.cve_id) LIMIT %s)
        """,
        (n // 2, n - n // 2),
    )


def _expected(cve_id: str) -> set[int]:
    rows = query("SELECT id FROM corpus_chunks WHERE cve_ids @> ARRAY[%s]", (cve_id,))
    return {r["id"] for r in rows}


def evaluate(
    store: VectorStore,
    queries: list[dict],
    *,
    k: int = 8,
    use_filter: bool = True,
) -> dict:
    recalls, precisions, latencies = [], [], []

    for q in queries:
        cve_id = q["cve_id"]
        expected = _expected(cve_id)
        if not expected:
            continue
        # Natural-language query: the hard case. A bare CVE id would be solved
        # by the prefilter alone and would measure nothing about the engine.
        text = (q["description"] or cve_id)[:300]
        vector = embed_query(text)

        t0 = time.perf_counter()
        hits = store.search(vector, k, cve_ids=[cve_id] if use_filter else None)
        latencies.append((time.perf_counter() - t0) * 1000)

        got = {h.chunk_id for h in hits}
        found = len(got & expected)
        recalls.append(found / min(len(expected), k))
        precisions.append(found / max(len(got), 1))

    return {
        "backend": store.name,
        "filtered": use_filter,
        "queries": len(recalls),
        "recall_at_k": round(statistics.mean(recalls), 4) if recalls else 0.0,
        "precision_at_k": round(statistics.mean(precisions), 4) if precisions else 0.0,
        "p50_ms": round(statistics.median(latencies), 2) if latencies else 0.0,
        "p95_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 2)
                   if len(latencies) > 3 else 0.0,
        "mean_ms": round(statistics.mean(latencies), 2) if latencies else 0.0,
    }


def run(k: int = 8, n_queries: int = 60, ef_values: tuple[int, ...] = (16, 64, 256)) -> list[dict]:
    from sentinel.rag.pgvector_store import PgVectorStore
    from sentinel.rag.qdrant_store import QdrantStore

    get_model()  # pay the cold load once, outside the timed sections
    queries = sample_queries(n_queries)
    log.info("benchmark.start", queries=len(queries), k=k)

    results = []
    for ef in ef_values:
        # Constructed directly rather than via closures: a lambda here would
        # capture `ef` by reference and every factory would see the last value
        # the moment anyone collected them before calling.
        for store in (PgVectorStore(ef_search=ef), QdrantStore(hnsw_ef=ef)):
            for use_filter in (True, False):
                row = evaluate(store, queries, k=k, use_filter=use_filter)
                row["ef_search"] = ef
                results.append(row)
                log.info("benchmark.result", **row)
    return results
