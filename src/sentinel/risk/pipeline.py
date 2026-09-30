"""Apply the risk policy to every open finding.

`risk_assessments` is append-only: it is audit evidence, and an owner who asks
"why did my due date move?" deserves the history. But a nightly re-run that
inserts 100k identical rows every night is not history, it is noise.

So a new row is written only when the *outcome* changes -- score, band, due
date, or policy version. A re-run that changes nothing writes nothing.
"""

from __future__ import annotations

import json
import time
from datetime import date

import structlog

from sentinel.db.session import connection
from sentinel.risk.scoring import POLICY_VERSION, AssetFacts, CveFacts, score_finding
from sentinel.risk.sla import resolve_sla

log = structlog.get_logger()

_FACTS_SQL = """
SELECT f.id AS finding_id, f.first_seen,
       c.cve_id, c.cvss_v31_score, c.cvss_v40_score, c.cvss_severity,
       c.kev_listed, c.kev_ransomware, c.kev_due_date, c.epss_score,
       a.hostname, a.environment, a.internet_facing,
       a.business_criticality, a.data_classification,
       r.risk_score AS prev_score, r.risk_band AS prev_band,
       r.due_date AS prev_due, r.policy_version AS prev_policy
FROM findings f
JOIN cves   c ON c.cve_id = f.cve_id
JOIN assets a ON a.id = f.asset_id
LEFT JOIN risk_assessments r ON r.finding_id = f.id AND r.is_current
WHERE f.status = 'open'
"""


def score_open_findings(batch_size: int = 20_000) -> dict:
    t0 = time.perf_counter()
    inserted = unchanged = 0

    # Server-side cursor: streams rather than materialising 100k rows.
    with connection() as conn, conn.cursor(name="risk_facts") as src:
        src.itersize = batch_size
        src.execute(_FACTS_SQL)

        with conn.cursor() as sink:
            sink.execute(
                "CREATE TEMP TABLE _ra (finding_id BIGINT, risk_score NUMERIC, "
                "risk_band TEXT, sla_days INT, due_date DATE, factors JSONB, "
                "policy_version TEXT) ON COMMIT DROP"
            )
            pending: list[tuple] = []

            def flush() -> None:
                if not pending:
                    return
                with sink.copy(
                    "COPY _ra (finding_id, risk_score, risk_band, sla_days, "
                    "due_date, factors, policy_version) FROM STDIN"
                ) as cp:
                    for row in pending:
                        cp.write_row(row)
                pending.clear()

            for row in src:
                cve = CveFacts(
                    cve_id=row["cve_id"],
                    cvss_v31_score=row["cvss_v31_score"],
                    cvss_v40_score=row["cvss_v40_score"],
                    cvss_severity=row["cvss_severity"],
                    kev_listed=row["kev_listed"],
                    kev_ransomware=row["kev_ransomware"],
                    epss_score=row["epss_score"],
                )
                asset = AssetFacts(
                    hostname=row["hostname"],
                    environment=row["environment"],
                    internet_facing=row["internet_facing"],
                    business_criticality=row["business_criticality"],
                    data_classification=row["data_classification"],
                )
                risk = score_finding(cve, asset)
                first_seen = row["first_seen"]
                sla = resolve_sla(
                    risk, cve,
                    first_seen=first_seen.date() if hasattr(first_seen, "date") else first_seen,
                    internet_facing=row["internet_facing"],
                    kev_due_date=row["kev_due_date"],
                )

                # Skip when nothing an owner would notice has changed.
                if (
                    row["prev_policy"] == POLICY_VERSION
                    and row["prev_band"] == risk.band
                    and row["prev_due"] == sla.due_date
                    and row["prev_score"] is not None
                    and float(row["prev_score"]) == risk.score
                ):
                    unchanged += 1
                    continue

                factors = dict(risk.factors)
                # `days` and `due_date` live in their own columns; only
                # the reasoning and the compliance fact go in the blob.
                sla_factors: dict = {"rule": sla.rule}
                if sla.kev_deadline_passed:
                    sla_factors["kev_deadline_passed"] = True
                if sla.kev_due_date:
                    sla_factors["kev_due_date"] = sla.kev_due_date.isoformat()
                factors["sla"] = sla_factors
                pending.append((
                    row["finding_id"], risk.score, risk.band, sla.sla_days,
                    sla.due_date, json.dumps(factors), POLICY_VERSION,
                ))
                inserted += 1
                if len(pending) >= batch_size:
                    flush()
            flush()

            # uq_risk_current enforces one current assessment per finding,
            # so the previous one must be demoted before the new one lands.
            # Same transaction: a crash between the two would otherwise
            # leave a finding with no current assessment at all.
            sink.execute(
                """
                UPDATE risk_assessments ra SET is_current = FALSE
                WHERE ra.is_current
                  AND ra.finding_id IN (SELECT finding_id FROM _ra)
                """
            )
            sink.execute(
                """
                INSERT INTO risk_assessments (finding_id, risk_score, risk_band,
                                              sla_days, due_date, factors,
                                              policy_version, is_current)
                SELECT finding_id, risk_score, risk_band, sla_days, due_date,
                       factors, policy_version, TRUE FROM _ra
                """
            )

    elapsed = time.perf_counter() - t0
    log.info("risk.scored", inserted=inserted, unchanged=unchanged,
             seconds=round(elapsed, 1))
    return {
        "inserted": inserted, "unchanged": unchanged,
        "seconds": round(elapsed, 2),
        "rows_per_sec": round((inserted + unchanged) / max(elapsed, 0.01)),
        "policy_version": POLICY_VERSION,
        "as_of": date.today().isoformat(),
    }
