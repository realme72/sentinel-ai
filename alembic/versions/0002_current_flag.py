"""risk_assessments: is_current flag, partial unique index, rewritten view

Revision ID: 0002_current_flag
Revises: 0001_baseline
Create Date: 2026-09-30

v_current_risk used DISTINCT ON over the whole append-only history. Measured
at 119k assessments it read every row, sorted, deduped to 100,937, then
discarded 99.6% to return 20 -- 140ms and 16,336 blocks spilled to temp. That
cost is O(history), and history only grows.

This adds an explicit is_current flag with a PARTIAL UNIQUE index, which does
two jobs: the read path becomes an index scan instead of a full sort, and
"exactly one current assessment per finding" stops being an application
convention and becomes an invariant the database enforces.
"""

from alembic import op

revision = "0002_current_flag"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS is_current BOOLEAN NOT NULL DEFAULT TRUE")

    # Backfill. Tie-break on id, not computed_at alone: a scoring run inserts
    # every row inside one transaction, so they all share the same now() and
    # ORDER BY computed_at DESC is ambiguous for exactly the rows that matter.
    op.execute(
        """
        WITH ranked AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY finding_id
                       ORDER BY computed_at DESC, id DESC
                   ) AS rn
            FROM risk_assessments
        )
        UPDATE risk_assessments ra
        SET is_current = (r.rn = 1)
        FROM ranked r
        WHERE r.id = ra.id AND ra.is_current <> (r.rn = 1)
        """
    )

    # The invariant, enforced. Any code path that inserts a second current
    # assessment for a finding now fails loudly instead of corrupting the view.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_current "
        "ON risk_assessments (finding_id) WHERE is_current"
    )

    op.execute("DROP VIEW IF EXISTS v_current_risk")
    op.execute(
        """
        CREATE VIEW v_current_risk AS
        SELECT f.id AS finding_id, f.status, f.package_name, f.installed_version,
               f.fixed_version, f.package_type, f.first_seen,
               a.id AS asset_id, a.hostname, a.environment, a.internet_facing,
               a.business_criticality, a.owner_team, a.owner_email,
               c.cve_id, c.cvss_v31_score, c.cvss_severity, c.epss_score,
               c.kev_listed, c.kev_ransomware,
               ra.risk_score, ra.risk_band, ra.sla_days, ra.due_date,
               ra.factors, ra.policy_version, ra.computed_at,
               (ra.due_date < CURRENT_DATE) AS overdue,
               (ra.due_date - CURRENT_DATE) AS days_remaining
        FROM risk_assessments ra
        JOIN findings f ON f.id = ra.finding_id
        JOIN assets   a ON a.id = f.asset_id
        JOIN cves     c ON c.cve_id = f.cve_id
        WHERE ra.is_current
        """
    )

    # Supports the dashboard's default sort without touching history.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_current_band "
        "ON risk_assessments (risk_band, risk_score DESC) WHERE is_current"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_current_due "
        "ON risk_assessments (due_date) WHERE is_current"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_risk_current_due")
    op.execute("DROP INDEX IF EXISTS idx_risk_current_band")
    op.execute("DROP INDEX IF EXISTS uq_risk_current")
    op.execute("DROP VIEW IF EXISTS v_current_risk")
    op.execute(
        """
        CREATE VIEW v_current_risk AS
        SELECT DISTINCT ON (f.id)
               f.id AS finding_id, f.status, f.package_name, f.installed_version,
               f.fixed_version, f.package_type, f.first_seen,
               a.id AS asset_id, a.hostname, a.environment, a.internet_facing,
               a.business_criticality, a.owner_team, a.owner_email,
               c.cve_id, c.cvss_v31_score, c.cvss_severity, c.epss_score,
               c.kev_listed, c.kev_ransomware,
               ra.risk_score, ra.risk_band, ra.sla_days, ra.due_date,
               ra.factors, ra.policy_version, ra.computed_at,
               (ra.due_date < CURRENT_DATE) AS overdue,
               (ra.due_date - CURRENT_DATE) AS days_remaining
        FROM findings f
        JOIN assets a ON a.id = f.asset_id
        JOIN cves   c ON c.cve_id = f.cve_id
        JOIN risk_assessments ra ON ra.finding_id = f.id
        ORDER BY f.id, ra.computed_at DESC
        """
    )
    op.execute("ALTER TABLE risk_assessments DROP COLUMN IF EXISTS is_current")
