"""Run Trivy over the SBOM fleet and load findings into Postgres.

Two performance decisions worth knowing about:

1. Scans run in a process pool. Trivy is a subprocess per SBOM and spends most
   of its time on CPU-bound matching, so parallelism is a near-linear win.
2. Rows land via COPY into an UNLOGGED staging table, then move with a single
   INSERT ... SELECT ... ON CONFLICT. At ~125k findings, `executemany` spends
   most of its wall clock on per-statement round trips; COPY streams.
"""

from __future__ import annotations

import json
import re
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import structlog

from sentinel.db.session import connection

log = structlog.get_logger()

# Distro trackers emit non-CVE placeholders (Debian's TEMP-*, RHEL's RHSA-*).
# They are real advisories but have no NVD/KEV/EPSS record, so they cannot be
# enriched or scored. Keep them out of `cves` rather than creating rows that
# every enrichment stage then has to special-case.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass(frozen=True)
class ScanOutcome:
    hostname: str
    findings: list[dict]
    skipped_non_cve: int
    error: str | None = None


def scan_sbom(sbom_path: str) -> ScanOutcome:
    """Scan one SBOM. Runs in a worker process, so it takes/returns plain data."""
    hostname = Path(sbom_path).name.replace(".cdx.json", "")
    try:
        proc = subprocess.run(
            ["trivy", "sbom", "--quiet", "--format", "json", "--scanners", "vuln", sbom_path],
            capture_output=True, text=True, timeout=180, check=True,
        )
    except subprocess.CalledProcessError as exc:
        return ScanOutcome(hostname, [], 0, error=(exc.stderr or "")[:400])
    except subprocess.TimeoutExpired:
        return ScanOutcome(hostname, [], 0, error="trivy timeout")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return ScanOutcome(hostname, [], 0, error=f"bad json: {exc}")

    findings, skipped = [], 0
    for result in payload.get("Results") or []:
        pkg_type = result.get("Type")
        for v in result.get("Vulnerabilities") or []:
            cve_id = v.get("VulnerabilityID", "")
            if not CVE_RE.match(cve_id):
                skipped += 1
                continue
            findings.append(
                {
                    "hostname": hostname,
                    "cve_id": cve_id,
                    "package_name": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    # Trivy returns comma-separated candidates across branches;
                    # the first is the fix for the installed branch.
                    "fixed_version": (v.get("FixedVersion") or "").split(",")[0].strip() or None,
                    "package_type": pkg_type,
                    "severity": v.get("Severity", "UNKNOWN"),
                    "title": v.get("Title"),
                    "description": v.get("Description"),
                    "cvss": v.get("CVSS") or {},
                    "references": v.get("References") or [],
                    "published": v.get("PublishedDate"),
                    "last_modified": v.get("LastModifiedDate"),
                }
            )
    return ScanOutcome(hostname, findings, skipped)


def refresh_vuln_db(max_age_hours: int = 24) -> dict:
    """Refresh Trivy's local vulnerability database if it is stale.

    Trivy caches its DB on disk and will happily keep scanning with a
    months-old copy, silently reporting zero new CVEs. That failure is
    invisible -- scans succeed, findings just stop appearing -- so freshness
    is checked rather than assumed.
    """
    meta = Path.home() / "Library" / "Caches" / "trivy" / "db" / "metadata.json"
    if not meta.exists():
        meta = Path.home() / ".cache" / "trivy" / "db" / "metadata.json"

    age_hours = None
    if meta.exists():
        try:
            downloaded = json.loads(meta.read_text()).get("DownloadedAt", "")
            ts = datetime.fromisoformat(downloaded.replace("Z", "+00:00"))
            age_hours = (datetime.now(UTC) - ts).total_seconds() / 3600
        except (json.JSONDecodeError, ValueError, OSError):
            age_hours = None

    if age_hours is not None and age_hours < max_age_hours:
        log.info("trivy.db.fresh", age_hours=round(age_hours, 1))
        return {"refreshed": False, "age_hours": round(age_hours, 1)}

    log.info("trivy.db.refreshing", age_hours=age_hours)
    proc = subprocess.run(
        ["trivy", "image", "--download-db-only", "--quiet"],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        # A stale DB still scans, so this warns rather than aborting the run.
        log.warning("trivy.db.refresh_failed", error=(proc.stderr or "")[:300])
        return {"refreshed": False, "error": (proc.stderr or "")[:300]}
    return {"refreshed": True, "previous_age_hours": age_hours}


def scan_fleet(sbom_dir: Path, max_workers: int = 8) -> list[ScanOutcome]:
    paths = sorted(str(p) for p in sbom_dir.glob("*.cdx.json"))
    if not paths:
        raise FileNotFoundError(f"no SBOMs in {sbom_dir}")

    outcomes: list[ScanOutcome] = []
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_sbom, p): p for p in paths}
        for i, fut in enumerate(as_completed(futures), 1):
            outcome = fut.result()
            outcomes.append(outcome)
            if outcome.error:
                log.warning("scan.failed", host=outcome.hostname, error=outcome.error)
            if i % 50 == 0 or i == len(paths):
                log.info("scan.progress", done=i, total=len(paths))
    return outcomes


def _best_cvss(cvss_blob: dict) -> tuple[float | None, str | None]:
    """Trivy reports CVSS per source (nvd, redhat, ghsa...). Prefer NVD; it is
    what our risk policy and every compliance doc reference."""
    if not cvss_blob:
        return None, None
    for source in ("nvd", "ghsa", "redhat"):
        entry = cvss_blob.get(source) or {}
        if entry.get("V3Score") is not None:
            return float(entry["V3Score"]), entry.get("V3Vector")
    for entry in cvss_blob.values():
        if isinstance(entry, dict) and entry.get("V3Score") is not None:
            return float(entry["V3Score"]), entry.get("V3Vector")
    return None, None


def load_assets(assets: list[dict]) -> dict[str, int]:
    """Upsert assets, returning hostname -> id."""
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO assets (hostname, ip_address, os_family, os_version, environment,
                                business_criticality, internet_facing, data_classification,
                                owner_team, owner_email, tags)
            VALUES (%(hostname)s, %(ip_address)s, %(os_family)s, %(os_version)s, %(environment)s,
                    %(business_criticality)s, %(internet_facing)s, %(data_classification)s,
                    %(owner_team)s, %(owner_email)s, %(tags)s)
            ON CONFLICT (hostname) DO UPDATE SET
                ip_address = EXCLUDED.ip_address,
                environment = EXCLUDED.environment,
                business_criticality = EXCLUDED.business_criticality,
                internet_facing = EXCLUDED.internet_facing,
                data_classification = EXCLUDED.data_classification,
                owner_team = EXCLUDED.owner_team,
                owner_email = EXCLUDED.owner_email,
                tags = EXCLUDED.tags,
                updated_at = now()
            """,
            [{**a, "tags": json.dumps(a.get("tags", {}))} for a in assets],
        )
        cur.execute("SELECT hostname, id FROM assets")
        return {r["hostname"]: r["id"] for r in cur.fetchall()}


def load_findings(outcomes: list[ScanOutcome], asset_ids: dict[str, int], scan_id: int) -> dict:
    """Bulk-load CVEs and findings via COPY into a staging table."""
    rows = [f for o in outcomes for f in o.findings]
    if not rows:
        return {"cves": 0, "findings": 0, "skipped": 0}

    # Collapse to one record per CVE; keep the highest severity seen.
    cve_seed: dict[str, dict] = {}
    for f in rows:
        prev = cve_seed.get(f["cve_id"])
        if prev and SEVERITY_ORDER.get(f["severity"], 0) <= SEVERITY_ORDER.get(prev["severity"], 0):
            continue
        score, vector = _best_cvss(f["cvss"])
        cve_seed[f["cve_id"]] = {
            "cve_id": f["cve_id"],
            "severity": f["severity"],
            "description": (f["description"] or f["title"] or "")[:8000],
            "score": score,
            "vector": vector,
            "published": f["published"],
            "last_modified": f["last_modified"],
            "references": f["references"][:40],
        }

    with connection() as conn, conn.cursor() as cur:
        # CVEs: seed from Trivy now; NVD will overwrite authoritatively later.
        # COALESCE means a later NVD pass never gets clobbered by a rescan.
        cur.executemany(
            """
            INSERT INTO cves (cve_id, description, cvss_v31_score, cvss_v31_vector,
                              cvss_severity, reference_urls, published_at, last_modified_at)
            VALUES (%(cve_id)s, %(description)s, %(score)s, %(vector)s, %(severity)s,
                    %(references)s, %(published)s, %(last_modified)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                description      = COALESCE(cves.description, EXCLUDED.description),
                cvss_v31_score   = COALESCE(cves.cvss_v31_score, EXCLUDED.cvss_v31_score),
                cvss_v31_vector  = COALESCE(cves.cvss_v31_vector, EXCLUDED.cvss_v31_vector),
                cvss_severity    = COALESCE(cves.cvss_severity, EXCLUDED.cvss_severity)
            """,
            list(cve_seed.values()),
        )

        # TEMP, not UNLOGGED. An UNLOGGED table is permanent and shared:
        # two concurrent scans would interleave rows into it and cross-
        # contaminate findings, and a crash between TRUNCATE and DROP would
        # leak stale rows into the next run. TEMP is session-scoped and
        # dropped automatically, and is already unlogged in modern Postgres.
        cur.execute(
            """
            CREATE TEMP TABLE _stage_findings (
                asset_id BIGINT, cve_id TEXT, package_name TEXT,
                installed_version TEXT, fixed_version TEXT, package_type TEXT
            ) ON COMMIT DROP
            """
        )
        with cur.copy(
            "COPY _stage_findings (asset_id, cve_id, package_name, installed_version, "
            "fixed_version, package_type) FROM STDIN"
        ) as copy:
            for f in rows:
                aid = asset_ids.get(f["hostname"])
                if aid is None:
                    continue
                copy.write_row((aid, f["cve_id"], f["package_name"],
                                f["installed_version"], f["fixed_version"], f["package_type"]))

        # DISTINCT ON guards against a package appearing twice in one SBOM,
        # which would make ON CONFLICT fire twice in a single statement.
        cur.execute(
            """
            INSERT INTO findings (asset_id, cve_id, package_name, installed_version,
                                  fixed_version, package_type, first_scan_id, last_scan_id)
            SELECT DISTINCT ON (asset_id, cve_id, package_name, installed_version)
                   asset_id, cve_id, package_name, installed_version,
                   fixed_version, package_type, %s, %s
            FROM _stage_findings
            ON CONFLICT (asset_id, cve_id, package_name, installed_version) DO UPDATE SET
                last_seen     = now(),
                last_scan_id  = EXCLUDED.last_scan_id,
                fixed_version = EXCLUDED.fixed_version,
                status        = CASE WHEN findings.status = 'fixed'
                                     THEN 'open' ELSE findings.status END
            """,
            (scan_id, scan_id),
        )
        inserted = cur.rowcount

    return {
        "cves": len(cve_seed),
        "findings": inserted,
        "skipped": sum(o.skipped_non_cve for o in outcomes),
    }
