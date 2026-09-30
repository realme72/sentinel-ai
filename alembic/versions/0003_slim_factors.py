"""slim risk_assessments.factors and add a history retention function

Revision ID: 0003_slim_factors
Revises: 0002_current_flag
Create Date: 2026-09-30

factors was 102MB of a 118MB heap -- 86%, at 897 bytes/row -- and projected to
2.8GB at 90 nightly runs, 28GB at ten times the fleet. Most of it was
duplication: cve_id, hostname, total and band all exist as columns, and the
per-component `max` ceilings are constants that live in POLICY_VERSION.

This rewrites existing rows into the slim shape and adds prune_risk_history(),
which drops the explanation from superseded rows past a retention window while
keeping the numbers (score, band, due date) forever. Trend analysis needs the
numbers; it does not need 90 copies of why a score was what it was.
"""

from alembic import op

revision = "0003_slim_factors"
down_revision = "0002_current_flag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rewrite historical rows into the shape score_finding() now emits.
    op.execute(
        """
        UPDATE risk_assessments SET factors =
            jsonb_build_object(
                'components',
                (SELECT jsonb_object_agg(key, value - 'max')
                 FROM jsonb_each(factors -> 'components'))
            )
            || CASE
                 WHEN factors ->> 'band_floor_rule' IS NOT NULL
                 THEN jsonb_build_object('band_floor', jsonb_build_object(
                          'rule', factors ->> 'band_floor_rule',
                          'scored_band', factors ->> 'scored_band'))
                 ELSE '{}'::jsonb
               END
            || CASE
                 WHEN factors ? 'sla'
                 THEN jsonb_build_object('sla',
                        jsonb_strip_nulls(
                          jsonb_build_object('rule', factors -> 'sla' ->> 'rule')
                          || CASE WHEN (factors -> 'sla' ->> 'kev_deadline_passed')::bool
                                  THEN jsonb_build_object('kev_deadline_passed', true)
                                  ELSE '{}'::jsonb END
                          || CASE WHEN factors -> 'sla' ->> 'kev_due_date' IS NOT NULL
                                  THEN jsonb_build_object('kev_due_date',
                                         factors -> 'sla' ->> 'kev_due_date')
                                  ELSE '{}'::jsonb END))
                 ELSE '{}'::jsonb
               END
        WHERE factors ? 'components'
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prune_risk_history(retain_days INT DEFAULT 90)
        RETURNS bigint LANGUAGE sql AS $$
            WITH pruned AS (
                UPDATE risk_assessments
                SET factors = '{}'::jsonb
                WHERE NOT is_current
                  AND computed_at < now() - make_interval(days => retain_days)
                  AND factors <> '{}'::jsonb
                RETURNING 1
            )
            SELECT count(*) FROM pruned;
        $$;
        """
    )
    op.execute(
        "COMMENT ON FUNCTION prune_risk_history IS "
        "'Drop the factors explanation from superseded assessments older than "
        "retain_days. Score, band and due_date are always kept.'"
    )


def downgrade() -> None:
    # The dropped fields were derivable from columns, so nothing is
    # unrecoverable -- but reconstructing them row by row would be slower and
    # less accurate than simply re-running `sentinel score`.
    op.execute("DROP FUNCTION IF EXISTS prune_risk_history(INT)")
