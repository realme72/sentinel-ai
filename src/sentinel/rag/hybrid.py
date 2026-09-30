"""Hybrid retrieval: lexical + dense, fused by Reciprocal Rank Fusion.

Measured on this corpus, a pure vector search for the literal string
"CVE-2021-44228" returns CVE-2021-45046 as its top hit, with the correct CVE
third. The Log4j-family descriptions sit at 0.79-0.84 cosine similarity to one
another, so the embedding cannot separate them -- and a planner handed the
wrong advisory will summarise it into a ticket that looks entirely correct.

Three mechanisms, each covering a different failure:

  lexical    exact identifiers and version strings, where embeddings are worst
  dense      paraphrase and intent, where lexical finds nothing
  prefilter  when the query names a CVE, restrict before ranking, so returning
             a different CVE becomes structurally impossible rather than
             merely unlikely
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass

from sentinel.config import get_settings
from sentinel.db.session import connection
from sentinel.rag.embed import embed_query
from sentinel.rag.store import SearchHit, VectorStore

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass(frozen=True)
class FusedHit:
    chunk_id: int
    content: str
    cve_ids: list[str]
    source: str
    rrf_score: float
    lexical_rank: int | None
    dense_rank: int | None


def extract_cve_ids(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text)})


def lexical_search(
    query: str, k: int, *, cve_ids: list[str] | None = None,
) -> list[SearchHit]:
    """Postgres full-text search over chunk content.

    Note this is cover-density ranking (ts_rank_cd), not BM25 -- it weights
    term frequency and proximity but lacks BM25's length saturation. For rare
    identifiers the distinction does not matter: the term matches or it does
    not, which is exactly the property being relied on here.
    """
    where = ["tsv @@ websearch_to_tsquery('english', %s)"]
    params: list = [query]
    if cve_ids:
        where.append("cve_ids && %s")
        params.append(list(cve_ids))

    sql = f"""
        SELECT id, content, cve_ids, source,
               ts_rank_cd(tsv, websearch_to_tsquery('english', %s)) AS score
        FROM corpus_chunks
        WHERE {' AND '.join(where)}
        ORDER BY score DESC
        LIMIT %s
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, [query, *params, k])
        return [
            SearchHit(chunk_id=r["id"], score=float(r["score"]), content=r["content"],
                      cve_ids=r["cve_ids"], source=r["source"], backend="tsvector")
            for r in cur.fetchall()
        ]


def reciprocal_rank_fusion(
    rankings: dict[str, list[SearchHit]], k: int, rrf_k: int = 60,
) -> list[FusedHit]:
    """score(doc) = sum over lists of 1 / (rrf_k + rank_in_that_list)

    Rank-based on purpose. ts_rank_cd returns unbounded floats and cosine
    similarity returns 0-1; adding them is meaningless and normalising them
    needs assumptions that break as the corpus grows. Ranks are always
    comparable, and a document strong in one list still surfaces when it is
    absent from the other.
    """
    scores: dict[int, float] = defaultdict(float)
    positions: dict[int, dict[str, int]] = defaultdict(dict)
    hits: dict[int, SearchHit] = {}

    for list_name, ranking in rankings.items():
        for rank, hit in enumerate(ranking, start=1):
            scores[hit.chunk_id] += 1.0 / (rrf_k + rank)
            positions[hit.chunk_id][list_name] = rank
            hits.setdefault(hit.chunk_id, hit)

    ordered = sorted(scores.items(), key=lambda kv: -kv[1])[:k]
    return [
        FusedHit(
            chunk_id=cid,
            content=hits[cid].content,
            cve_ids=hits[cid].cve_ids,
            source=hits[cid].source,
            rrf_score=round(score, 6),
            lexical_rank=positions[cid].get("lexical"),
            dense_rank=positions[cid].get("dense"),
        )
        for cid, score in ordered
    ]


def search(
    query: str,
    *,
    store: VectorStore | None = None,
    k: int | None = None,
    candidates: int | None = None,
    prefilter: bool = True,
    mode: str = "hybrid",          # hybrid | dense | lexical
) -> dict:
    settings = get_settings()
    k = k or settings.retrieval_final_k
    candidates = candidates or settings.retrieval_candidates

    if store is None:
        from sentinel.rag.pgvector_store import PgVectorStore
        store = PgVectorStore()

    cve_ids = extract_cve_ids(query) if prefilter else None
    timings: dict[str, float] = {}
    rankings: dict[str, list[SearchHit]] = {}

    if mode in ("hybrid", "lexical"):
        t = time.perf_counter()
        rankings["lexical"] = lexical_search(query, candidates, cve_ids=cve_ids)
        timings["lexical_ms"] = round((time.perf_counter() - t) * 1000, 2)

    if mode in ("hybrid", "dense"):
        t = time.perf_counter()
        vector = embed_query(query)
        timings["embed_ms"] = round((time.perf_counter() - t) * 1000, 2)
        t = time.perf_counter()
        rankings["dense"] = store.search(vector, candidates, cve_ids=cve_ids)
        timings["dense_ms"] = round((time.perf_counter() - t) * 1000, 2)

    t = time.perf_counter()
    fused = reciprocal_rank_fusion(rankings, k, rrf_k=settings.rrf_k)
    timings["fuse_ms"] = round((time.perf_counter() - t) * 1000, 2)

    return {
        "query": query,
        "mode": mode,
        "backend": store.name,
        "prefilter_cves": cve_ids or [],
        "candidates_per_branch": candidates,
        "hits": fused,
        "timings": timings,
        "total_ms": round(sum(timings.values()), 2),
    }
