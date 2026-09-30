"""store CISA KEV required-action and short-description text

Revision ID: 0005_kev_action
Revises: 0004_hnsw_index
Create Date: 2026-10-01

The KEV feed carries `requiredAction` and `shortDescription` per entry -- the
only vendor-neutral remediation instruction in any of the free feeds. Loading
discarded them because nothing consumed them yet; the RAG corpus does.
"""

from alembic import op

revision = "0005_kev_action"
down_revision = "0004_hnsw_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev_required_action TEXT")
    op.execute("ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev_short_description TEXT")
    op.execute("ALTER TABLE cves ADD COLUMN IF NOT EXISTS kev_vulnerability_name TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE cves DROP COLUMN IF EXISTS kev_vulnerability_name")
    op.execute("ALTER TABLE cves DROP COLUMN IF EXISTS kev_short_description")
    op.execute("ALTER TABLE cves DROP COLUMN IF EXISTS kev_required_action")
