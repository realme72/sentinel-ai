"""NVD API 2.0 enrichment: authoritative CVSS, CWE, and canonical descriptions.

Unlike KEV and EPSS -- one bulk file each -- NVD is one request per CVE, and
it is the hardest rate limit in the pipeline: 5 requests / 30s anonymous,
50 / 30s with a key. That makes it the stage worth engineering.

Three things do the work:

* a **rolling-window rate limiter** shared by every worker, so concurrency
  never exceeds the published quota no matter how many coroutines run;
* **resumability** -- only CVEs with `enriched_at IS NULL` are fetched, AND
  results are written in chunks as they complete. Both halves are required:
  selecting unenriched rows means nothing if a crash at 700/710 persisted
  none of them. Chunking costs no throughput here because the rate limiter,
  not request pipelining, is the bottleneck;
* **retry with backoff** on 429/5xx, because NVD returns 503 under load far
  more often than its docs suggest.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sentinel.config import get_settings
from sentinel.db.session import connection, query
from sentinel.util.ratelimit import RollingWindowLimiter

log = structlog.get_logger()


class RetryableStatus(Exception):
    pass


@retry(
    retry=retry_if_exception_type((RetryableStatus, httpx.TransportError)),
    wait=wait_exponential(multiplier=1.5, min=2, max=45),
    stop=stop_after_attempt(5),
    reraise=True,
)
async def _get_cve(client: httpx.AsyncClient, limiter: RollingWindowLimiter,
                   cve_id: str) -> dict | None:
    await limiter.acquire()
    resp = await client.get("", params={"cveId": cve_id})
    if resp.status_code in (429, 500, 502, 503, 504):
        raise RetryableStatus(f"{cve_id}: HTTP {resp.status_code}")
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities") or []
    return vulns[0]["cve"] if vulns else None


def _parse(cve: dict) -> dict:
    metrics = cve.get("metrics") or {}

    def pick(key: str) -> tuple[float | None, str | None]:
        entries = metrics.get(key) or []
        # NVD publishes several scorings per CVE; the Primary one is NVD's own.
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if not entry:
            return None, None
        data = entry.get("cvssData") or {}
        return data.get("baseScore"), data.get("vectorString")

    v31_score, v31_vector = pick("cvssMetricV31")
    v40_score, v40_vector = pick("cvssMetricV40")

    severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            if data.get("baseSeverity"):
                severity = data["baseSeverity"]
                break
        if severity:
            break

    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )
    cwes = sorted({
        d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    refs = [r["url"] for r in cve.get("references", []) if r.get("url")][:40]

    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": (description or "")[:8000] or None,
        "v31_score": v31_score, "v31_vector": v31_vector,
        "v40_score": v40_score, "v40_vector": v40_vector,
        "severity": severity, "cwes": cwes, "refs": refs,
    }


async def _fetch_chunk(client: httpx.AsyncClient, limiter: RollingWindowLimiter,
                       sem: asyncio.Semaphore, cve_ids: list[str]) -> list[dict]:
    parsed: list[dict] = []

    async def worker(cve_id: str) -> None:
        async with sem:
            try:
                cve = await _get_cve(client, limiter, cve_id)
                if cve:
                    parsed.append(_parse(cve))
            except Exception as exc:  # noqa: BLE001 - one bad CVE must not kill the run
                log.warning("nvd.failed", cve=cve_id, error=str(exc)[:120])

    await asyncio.gather(*(worker(c) for c in cve_ids))
    return parsed


def _persist(parsed: list[dict]) -> None:
    if not parsed:
        return
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            UPDATE cves SET
                published_at     = COALESCE(%(published)s::timestamptz, published_at),
                last_modified_at = COALESCE(%(last_modified)s::timestamptz, last_modified_at),
                description      = COALESCE(%(description)s, description),
                cvss_v31_score   = COALESCE(%(v31_score)s, cvss_v31_score),
                cvss_v31_vector  = COALESCE(%(v31_vector)s, cvss_v31_vector),
                cvss_v40_score   = COALESCE(%(v40_score)s, cvss_v40_score),
                cvss_v40_vector  = COALESCE(%(v40_vector)s, cvss_v40_vector),
                cvss_severity    = COALESCE(%(severity)s, cvss_severity),
                cwe_ids          = %(cwes)s,
                reference_urls   = %(refs)s,
                enriched_at      = now()
            WHERE cve_id = %(cve_id)s
            """,
            parsed,
        )


async def _fetch_all(cve_ids: list[str], concurrency: int, chunk_size: int) -> int:
    settings = get_settings()
    headers = {"User-Agent": "sentinel-ai/0.1"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    # 50 req/30s with a key, 5 without. Stay a little under the line.
    limiter = RollingWindowLimiter(limit=48 if settings.nvd_api_key else 4, window=30.0)
    sem = asyncio.Semaphore(concurrency)
    total_written = 0

    async with httpx.AsyncClient(
        base_url=settings.nvd_base_url, headers=headers, timeout=45,
    ) as client:
        for start in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[start:start + chunk_size]
            parsed = await _fetch_chunk(client, limiter, sem, chunk)
            # Commit before moving on, so a crash keeps everything so far.
            await asyncio.to_thread(_persist, parsed)
            total_written += len(parsed)
            log.info("nvd.progress", done=min(start + chunk_size, len(cve_ids)),
                     total=len(cve_ids), written=total_written)
    return total_written


def load_nvd(*, limit: int | None = None, refresh: bool = False,
             concurrency: int = 8, chunk_size: int = 100) -> dict:
    """Enrich CVEs from NVD. Resumable at chunk granularity."""
    sql = "SELECT cve_id FROM cves WHERE %s ORDER BY cve_id" % (
        "TRUE" if refresh else "enriched_at IS NULL"
    )
    if limit:
        sql += f" LIMIT {int(limit)}"
    cve_ids = [r["cve_id"] for r in query(sql)]
    if not cve_ids:
        return {"requested": 0, "enriched": 0}

    t0 = time.perf_counter()
    written = asyncio.run(_fetch_all(cve_ids, concurrency, chunk_size))
    elapsed = time.perf_counter() - t0

    log.info("nvd.loaded", requested=len(cve_ids), enriched=written,
             seconds=round(elapsed, 1))
    return {
        "requested": len(cve_ids), "enriched": written,
        "seconds": round(elapsed, 1),
        "rate_per_min": round(len(cve_ids) / max(elapsed, 0.01) * 60, 1),
    }
