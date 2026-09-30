"""CISA Known Exploited Vulnerabilities.

The single highest-signal feed in the system. CVSS says how bad a flaw *would*
be; KEV says someone has actually used it against a real organisation. One
~1MB JSON file covers every CVE, so this is a single request regardless of
fleet size.
"""

from __future__ import annotations

import httpx
import structlog

from sentinel.config import get_settings
from sentinel.db.session import connection

log = structlog.get_logger()


def fetch_kev() -> list[dict]:
    settings = get_settings()
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(settings.kev_url)
        resp.raise_for_status()
        payload = resp.json()
    log.info("kev.fetched", catalog_version=payload.get("catalogVersion"),
             count=payload.get("count"))
    return payload.get("vulnerabilities", [])


def load_kev() -> dict:
    """Mark KEV-listed CVEs. Only touches CVEs we actually have findings for."""
    entries = fetch_kev()
    rows = [
        {
            "cve_id": e["cveID"],
            "date_added": e.get("dateAdded") or None,
            "due_date": e.get("dueDate") or None,
            # CISA encodes this as the strings "Known" / "Unknown".
            "ransomware": (e.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        }
        for e in entries
        if e.get("cveID")
    ]

    with connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE _kev (cve_id TEXT PRIMARY KEY, date_added DATE, "
                    "due_date DATE, ransomware BOOLEAN) ON COMMIT DROP")
        with cur.copy("COPY _kev (cve_id, date_added, due_date, ransomware) FROM STDIN") as cp:
            for r in rows:
                cp.write_row((r["cve_id"], r["date_added"], r["due_date"], r["ransomware"]))

        cur.execute(
            """
            UPDATE cves c SET kev_listed = TRUE,
                              kev_date_added = k.date_added,
                              kev_due_date = k.due_date,
                              kev_ransomware = k.ransomware
            FROM _kev k WHERE k.cve_id = c.cve_id
            """
        )
        matched = cur.rowcount
        cur.execute("SELECT count(*) AS n FROM cves WHERE kev_listed AND kev_ransomware")
        ransomware = cur.fetchone()["n"]

    log.info("kev.loaded", catalog_total=len(rows), matched_in_fleet=matched)
    return {"catalog_total": len(rows), "matched": matched, "ransomware": ransomware}
