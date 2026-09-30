"""Qdrant backend.

The reason it is here alongside pgvector: **filtered HNSW search**.

Filtering a vector search in a general-purpose store means choosing between
pre-filtering (correct, but abandons the index) and post-filtering (fast, but
a selective filter can return almost nothing). Qdrant builds additional graph
links between points that share filterable payload values, so the HNSW graph
stays navigable *within* a filter and it searches the filtered subgraph
directly.

Nearly every query in this system is scoped to a CVE, so that is exactly the
regime where the two backends should diverge -- which is the point of running
both.
"""

from __future__ import annotations

import numpy as np
import structlog

from sentinel.config import get_settings
from sentinel.rag.store import ChunkRecord, SearchHit

log = structlog.get_logger()


class QdrantStore:
    name = "qdrant"

    def __init__(self, hnsw_ef: int = 64) -> None:
        from qdrant_client import QdrantClient

        settings = get_settings()
        self.collection = settings.qdrant_collection
        self.dim = settings.embed_dim
        self.hnsw_ef = hnsw_ef
        self.client = QdrantClient(url=settings.qdrant_url, timeout=30)

    def ensure_ready(self) -> None:
        from qdrant_client import models

        existing = {c.name for c in self.client.get_collections().collections}
        if self.collection not in existing:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=models.VectorParams(
                    size=self.dim,
                    distance=models.Distance.COSINE,
                ),
                # Same graph parameters as the pgvector index, so the
                # comparison measures the engines and not two tunings.
                hnsw_config=models.HnswConfigDiff(m=16, ef_construct=64),
            )
            log.info("qdrant.collection_created", collection=self.collection)

        # Payload indexes are what make filtered search use the graph rather
        # than degrade to a scan. Without these, the filter is applied after
        # retrieval and a selective one returns too few results.
        self.client.create_payload_index(
            collection_name=self.collection, field_name="cve_ids",
            field_schema=models.PayloadSchemaType.KEYWORD, wait=True,
        )
        self.client.create_payload_index(
            collection_name=self.collection, field_name="source",
            field_schema=models.PayloadSchemaType.KEYWORD, wait=True,
        )

    def upsert(self, records: list[ChunkRecord]) -> int:
        from qdrant_client import models

        if not records:
            return 0
        points = [
            models.PointStruct(
                id=r.chunk_id,
                vector=[float(x) for x in r.embedding],
                payload={
                    "chunk_id": r.chunk_id,
                    "content": r.content,
                    "cve_ids": r.cve_ids,
                    "source": r.source,
                    "os_family": r.os_family,
                },
            )
            for r in records
        ]
        for i in range(0, len(points), 256):
            self.client.upsert(collection_name=self.collection,
                               points=points[i:i + 256], wait=True)
        return len(points)

    def search(self, vector: np.ndarray, k: int, *, cve_ids=None, source=None):
        from qdrant_client import models

        must = []
        if cve_ids:
            must.append(models.FieldCondition(
                key="cve_ids", match=models.MatchAny(any=list(cve_ids))))
        if source:
            must.append(models.FieldCondition(
                key="source", match=models.MatchValue(value=source)))

        result = self.client.query_points(
            collection_name=self.collection,
            query=[float(x) for x in vector],
            limit=k,
            query_filter=models.Filter(must=must) if must else None,
            search_params=models.SearchParams(hnsw_ef=self.hnsw_ef),
            with_payload=True,
        )
        return [
            SearchHit(
                chunk_id=int(p.payload["chunk_id"]),
                score=float(p.score),          # cosine similarity, higher better
                content=p.payload["content"],
                cve_ids=p.payload.get("cve_ids") or [],
                source=p.payload.get("source", ""),
                backend=self.name,
            )
            for p in result.points
        ]

    def count(self) -> int:
        try:
            return self.client.count(self.collection, exact=True).count
        except Exception:
            return 0
