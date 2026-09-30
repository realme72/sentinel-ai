"""The VectorStore contract.

A `typing.Protocol` rather than an abstract base class: structural typing means
an implementation satisfies this by having the right methods, with no import of
this module and no inheritance. The retriever depends on the shape, not on a
class hierarchy, which is what makes pgvector and Qdrant genuinely swappable --
and therefore comparable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import numpy as np


@dataclass(frozen=True)
class ChunkRecord:
    chunk_id: int
    content: str
    cve_ids: list[str]
    source: str
    os_family: str | None
    embedding: np.ndarray


@dataclass(frozen=True)
class SearchHit:
    chunk_id: int
    score: float               # higher is better, whatever the backend's native metric
    content: str
    cve_ids: list[str]
    source: str
    backend: str
    extra: dict = field(default_factory=dict)


@runtime_checkable
class VectorStore(Protocol):
    """Everything the retriever needs from a vector backend."""

    name: str

    def ensure_ready(self) -> None:
        """Create collections/indexes if absent. Must be idempotent."""

    def upsert(self, records: list[ChunkRecord]) -> int:
        """Insert or replace records by chunk_id. Returns rows written."""

    def search(
        self,
        vector: np.ndarray,
        k: int,
        *,
        cve_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SearchHit]:
        """Nearest neighbours, optionally restricted by metadata.

        `cve_ids` is the important one: nearly every query in this system is
        scoped to a known CVE, and how a backend handles a filtered vector
        search is precisely where the two differ.
        """

    def count(self) -> int:
        """Number of indexed vectors."""
