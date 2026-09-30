"""add the HNSW index on corpus_chunks.embedding

Revision ID: 0004_hnsw_index
Revises: 0003_slim_factors
Create Date: 2026-09-30

The index existed on the development database because it was created by hand
during a pgvector smoke test, but no migration created it -- so a fresh deploy
would have come up without it and every vector search would have fallen back
to a sequential scan. Schema drift of exactly the kind the fresh-vs-live diff
check now guards against.

Parameters are the pgvector defaults, chosen to be tuned rather than trusted:
  m = 16               edges per node; higher recall, more memory
  ef_construction = 64 build-time candidate list; better graph, slower build

Note for bulk loads: building HNSW *before* inserting means patching the graph
on every row. sentinel.db.session.build_vector_index() exists so the corpus
ingester can drop this index, COPY, and rebuild once.
"""

from alembic import op

revision = "0004_hnsw_index"
down_revision = "0003_slim_factors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON corpus_chunks "
        "USING hnsw (embedding vector_cosine_ops) "
        "WITH (m = 16, ef_construction = 64)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_chunks_embedding")
