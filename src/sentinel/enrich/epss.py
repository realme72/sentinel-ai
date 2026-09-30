"""FIRST EPSS -- Exploit Prediction Scoring System.

A daily-refreshed probability that a CVE will be exploited in the next 30
days. Where KEV is ground truth about the past, EPSS is a forecast, and the
two together are what let risk scoring rank a CVSS 7.2 above a quiet 9.8.

The whole corpus (~290k CVEs) is one gzipped CSV, so this is also a single
request regardless of fleet size.
"""

from __future__ import annotations

import csv
import gzip
import io

import httpx
import structlog

from sentinel.config import get_settings
from sentinel.db.session import connection

log = structlog.get_logger()


def fetch_epss() -> tuple[list[tuple[str, float, float]], str | None]:
    settings = get_settings()
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        resp = client.get(settings.epss_url)
        resp.raise_for_status()
        raw = gzip.decompress(resp.content).decode("utf-8")

    lines = raw.splitlines()
    # First line is a comment: #model_version:v2025.03.14,score_date:2026-09-30T00:00:00Z
    model_line = lines[0] if lines and lines[0].startswith("#") else None
    body = [ln for ln in lines if not ln.startswith("#")]

    rows: list[tuple[str, float, float]] = []
    for rec in csv.DictReader(io.StringIO("\n".join(body))):
        try:
            rows.append((rec["cve"], float(rec["epss"]), float(rec["percentile"])))
        except (KeyError, ValueError, TypeError):
            continue
    log.info("epss.fetched", rows=len(rows), model=model_line)
    return rows, model_line


def load_epss() -> dict:
    rows, model_line = fetch_epss()
    with connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE _epss (cve_id TEXT PRIMARY KEY, score NUMERIC, "
                    "percentile NUMERIC) ON COMMIT DROP")
        with cur.copy("COPY _epss (cve_id, score, percentile) FROM STDIN") as cp:
            for r in rows:
                cp.write_row(r)

        cur.execute(
            """
            UPDATE cves c SET epss_score = e.score,
                              epss_percentile = e.percentile,
                              epss_updated_at = now()
            FROM _epss e WHERE e.cve_id = c.cve_id
            """
        )
        matched = cur.rowcount
        cur.execute("SELECT count(*) AS n FROM cves WHERE epss_score >= 0.10")
        hot = cur.fetchone()["n"]

    log.info("epss.loaded", corpus=len(rows), matched_in_fleet=matched)
    return {"corpus": len(rows), "matched": matched, "epss_gte_10pct": hot,
            "model": model_line}
