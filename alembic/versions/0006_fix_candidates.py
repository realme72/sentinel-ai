"""keep every candidate fixed version, not just the chosen one

Revision ID: 0006_fix_candidates
Revises: 0005_kev_action
Create Date: 2026-10-01

Trivy reports fixes across all maintained branches, e.g. CVE-2021-45105 on an
installed 2.14.1 returns "2.12.3, 2.17.0, 2.3.1". Ingest previously kept the
first entry, which for that CVE is 2.12.3 -- a downgrade that leaves the host
exploitable.

Selection now picks the lowest candidate strictly greater than the installed
version. The full list is kept so a remediation plan can mention the
alternative branches (a team pinned to 2.12.x needs 2.12.3, not 2.17.0).
"""

from alembic import op

revision = "0006_fix_candidates"
down_revision = "0005_kev_action"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS "
        "fixed_version_candidates TEXT[] NOT NULL DEFAULT '{}'"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS fixed_version_candidates")
