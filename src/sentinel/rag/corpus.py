"""Build the retrieval corpus from enriched CVE facts and observed fixes.

The corpus is assembled from the database rather than scraped, which matters:
every sentence a planner will later be shown traces back to a row that came
from NVD, CISA or Trivy. The grounding gate can therefore check a generated
version string against something with provenance, instead of against text of
unknown origin.
"""

from __future__ import annotations

import time

import structlog

from sentinel.db.session import connection, query
from sentinel.rag.chunk import chunk_cve
from sentinel.rag.embed import embed_passages

log = structlog.get_logger()

# Fix facts are aggregated per CVE: the same CVE affects one package across
# hundreds of hosts, and the corpus needs the package, not the host list.
_CVE_SQL = """
SELECT c.cve_id, c.description, c.cvss_severity, c.cvss_v31_score, c.cwe_ids,
       c.kev_listed, c.kev_ransomware, c.kev_required_action,
       c.kev_short_description, c.kev_vulnerability_name, c.epss_score,
       COALESCE(f.fixes, '{}') AS fixes
FROM cves c
LEFT JOIN LATERAL (
    SELECT array_agg(DISTINCT ARRAY[package_name, installed_version,
                                    COALESCE(fixed_version, '')]) AS fixes
    FROM findings WHERE cve_id = c.cve_id
) f ON TRUE
WHERE c.description IS NOT NULL
ORDER BY c.cve_id
"""


def build_corpus(*, rebuild: bool = False, batch_size: int = 256) -> dict:
    t0 = time.perf_counter()

    if rebuild:
        with connection() as conn:
            conn.execute("TRUNCATE corpus_documents CASCADE")
        log.info("corpus.truncated")

    rows = query(_CVE_SQL)
    log.info("corpus.source_rows", cves=len(rows))

    documents: list[tuple] = []
    all_chunks: list[tuple[str, object]] = []

    for row in rows:
        fixes = [
            (pkg, installed, fixed or None)
            for pkg, installed, fixed in (row["fixes"] or [])
        ]
        chunks = chunk_cve(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_severity=row["cvss_severity"],
            cvss_score=float(row["cvss_v31_score"]) if row["cvss_v31_score"] else None,
            cwe_ids=row["cwe_ids"] or [],
            kev_listed=row["kev_listed"],
            kev_ransomware=row["kev_ransomware"],
            kev_action=row["kev_required_action"],
            epss_score=float(row["epss_score"]) if row["epss_score"] is not None else None,
            fixes=fixes,
        )
        if not chunks:
            continue
        title = row["kev_vulnerability_name"] or f"{row['cve_id']} advisory"
        raw = "\n\n".join(c.content for c in chunks)
        documents.append((("nvd"), row["cve_id"], title, [row["cve_id"]], raw))
        for c in chunks:
            all_chunks.append((row["cve_id"], c))

    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO corpus_documents (source, source_ref, title, cve_ids, raw_text)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (source, source_ref) DO UPDATE SET
                title = EXCLUDED.title, raw_text = EXCLUDED.raw_text,
                cve_ids = EXCLUDED.cve_ids, fetched_at = now()
            """,
            documents,
        )
        cur.execute("SELECT source_ref, id FROM corpus_documents WHERE source='nvd'")
        doc_ids = {r["source_ref"]: r["id"] for r in cur.fetchall()}

        # Rebuilding HNSW once after the load beats patching the graph per row.
        cur.execute("DROP INDEX IF EXISTS idx_chunks_embedding")
        cur.execute("DELETE FROM corpus_chunks WHERE document_id = ANY(%s)",
                    (list(doc_ids.values()),))

        t_embed = time.perf_counter()
        texts = [c.content for _, c in all_chunks]
        vectors = embed_passages(texts, batch_size=batch_size)
        embed_secs = time.perf_counter() - t_embed

        # Per-document chunk_index must restart at 0 to satisfy the unique key.
        per_doc: dict[int, int] = {}
        with cur.copy(
            "COPY corpus_chunks (document_id, chunk_index, content, cve_ids, "
            "source, os_family, embedding) FROM STDIN"
        ) as cp:
            for (cve_id, chunk), vec in zip(all_chunks, vectors, strict=True):
                doc_id = doc_ids[cve_id]
                idx = per_doc.get(doc_id, 0)
                per_doc[doc_id] = idx + 1
                cp.write_row((
                    doc_id, idx, chunk.content, chunk.cve_ids,
                    chunk.source, chunk.os_family,
                    "[" + ",".join(f"{v:.6f}" for v in vec) + "]",
                ))

        cur.execute(
            "CREATE INDEX idx_chunks_embedding ON corpus_chunks "
            "USING hnsw (embedding vector_cosine_ops) "
            "WITH (m = 16, ef_construction = 64)"
        )
        cur.execute("ANALYZE corpus_chunks")

    total = time.perf_counter() - t0
    log.info("corpus.built", documents=len(documents), chunks=len(all_chunks),
             embed_seconds=round(embed_secs, 1), total_seconds=round(total, 1))
    return {
        "documents": len(documents),
        "chunks": len(all_chunks),
        "embed_seconds": round(embed_secs, 1),
        "chunks_per_sec": round(len(all_chunks) / max(embed_secs, 0.01)),
        "total_seconds": round(total, 1),
    }
