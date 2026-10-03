"""Read API over the triage pipeline.

Endpoints are declared `def`, not `async def`, on purpose. The data layer is
synchronous psycopg and FastAPI runs sync handlers in a threadpool, which is
comfortably sufficient at this scale. Going async would mean maintaining a
second DB stack (asyncpg alongside psycopg) and rewriting working ingestion
code for no measured benefit.

Read-only by design: everything that writes -- scanning, enrichment, scoring,
planning, filing tickets -- is a CLI/worker concern with its own safety gates
(dry-run defaults, confirmation prompts, grounding checks). An HTTP surface
that could file 1,705 tickets is a liability, not a feature.
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinel.api.models import (
    AssetOut,
    CveOut,
    FindingOut,
    FixActionOut,
    Health,
    PlanOut,
    RiskFactors,
    SearchResponse,
    Stats,
)
from sentinel.config import get_settings
from sentinel.db.session import query, query_one

log = structlog.get_logger()

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Warm the embedding model in the background.

    It is lazily loaded and takes ~15s cold, so without this the first dense
    search on the dashboard costs 4+ seconds and looks like the retrieval is
    slow -- when the measured steady-state is ~14ms. Warming on a daemon
    thread keeps startup instant; a search arriving before it finishes simply
    waits on the same lru_cache as it would have anyway.
    """
    def warm() -> None:
        try:
            from sentinel.rag.embed import get_model
            get_model()
        except Exception as exc:  # noqa: BLE001 - the API must start regardless
            log.warning("api.embed_warmup_failed", error=str(exc)[:160])

    threading.Thread(target=warm, name="embed-warmup", daemon=True).start()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="Sentinel-AI",
    version="0.1.0",
    description=(
        "Agentic vulnerability triage. Risk scores and SLA due dates are "
        "computed by deterministic policy, never by a language model; every "
        "finding exposes the arithmetic that produced its priority."
    ),
)


STATIC_DIR = Path(__file__).with_name("static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """The dashboard, served from the same origin as the API so there is no
    CORS layer and no build step."""
    return FileResponse(STATIC_DIR / "index.html")


# --- health & stats --------------------------------------------------------

@app.get("/health", response_model=Health, tags=["meta"])
def health() -> Health:
    pg_ok, chunks, revision = True, 0, None
    try:
        chunks = (query_one("SELECT count(*) AS n FROM corpus_chunks") or {}).get("n", 0)
        row = query_one("SELECT version_num FROM alembic_version")
        revision = row["version_num"] if row else None
    except Exception as exc:  # noqa: BLE001 - health must report, not raise
        log.warning("health.postgres_down", error=str(exc)[:160])
        pg_ok = False

    qdrant_ok = False
    try:
        import httpx
        qdrant_ok = httpx.get(
            f"{get_settings().qdrant_url}/healthz", timeout=2
        ).status_code == 200
    except Exception:  # noqa: BLE001 - qdrant is optional; pgvector is primary
        qdrant_ok = False

    return Health(
        status="ok" if pg_ok else "degraded",
        postgres=pg_ok, qdrant=qdrant_ok,
        corpus_chunks=chunks, migration=revision,
    )


@app.get("/stats", response_model=Stats, tags=["meta"])
def stats(
    include_fix_actions: bool = Query(
        False, description="also correlate; costs a few hundred ms"
    ),
) -> Stats:
    row = query_one(
        """
        SELECT (SELECT count(*) FROM assets) AS assets,
               (SELECT count(*) FROM cves) AS cves,
               (SELECT count(*) FROM findings) AS findings,
               (SELECT count(*) FROM findings WHERE status='open') AS findings_open,
               (SELECT count(*) FROM cves WHERE kev_listed) AS kev_cves,
               (SELECT count(*) FROM corpus_chunks) AS corpus_chunks,
               (SELECT count(*) FROM remediation_plans) AS plans,
               (SELECT count(*) FROM remediation_plans WHERE grounding_passed)
                   AS plans_grounded,
               (SELECT count(*) FROM tickets) AS tickets
        """
    ) or {}
    fix_actions = None
    if include_fix_actions:
        from sentinel.agents.correlate import correlate
        fix_actions = len(correlate())
    return Stats(**row, fix_actions=fix_actions)


@app.get("/stats/bands", tags=["meta"])
def band_distribution() -> list[dict]:
    """Findings per risk band, plus how many are overdue in each.

    Aggregated server-side: the dashboard must not pull 103k rows to count
    four buckets.
    """
    return query(
        """
        SELECT risk_band AS band, count(*) AS findings,
               count(*) FILTER (WHERE due_date < CURRENT_DATE) AS overdue,
               count(DISTINCT asset_id) AS assets,
               count(*) FILTER (WHERE kev_listed) AS kev
        FROM v_current_risk WHERE status = 'open'
        GROUP BY risk_band
        ORDER BY CASE risk_band WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                                WHEN 'medium' THEN 3 ELSE 4 END
        """
    )


@app.get("/stats/backlog", tags=["meta"])
def due_date_backlog(
    weeks: Annotated[int, Query(ge=2, le=52)] = 12,
) -> list[dict]:
    """Open findings bucketed by the week they fall due.

    One series (findings), so the chart needs no legend -- its title names it.
    """
    return query(
        """
        SELECT to_char(date_trunc('week', due_date), 'YYYY-MM-DD') AS week,
               count(*) AS findings,
               count(*) FILTER (WHERE risk_band IN ('critical','high')) AS urgent
        FROM v_current_risk
        WHERE status = 'open'
          AND due_date < CURRENT_DATE + (%(weeks)s || ' weeks')::interval
        GROUP BY 1 ORDER BY 1
        """,
        {"weeks": weeks},
    )


# --- assets ----------------------------------------------------------------

@app.get("/assets", response_model=list[AssetOut], tags=["assets"])
def list_assets(
    team: str | None = None,
    environment: str | None = None,
    internet_facing: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AssetOut]:
    where, params = ["1=1"], {}
    if team:
        where.append("a.owner_team = %(team)s")
        params["team"] = team
    if environment:
        where.append("a.environment = %(env)s")
        params["env"] = environment
    if internet_facing is not None:
        where.append("a.internet_facing = %(inet)s")
        params["inet"] = internet_facing

    rows = query(
        f"""
        SELECT a.*,
               count(v.finding_id) AS open_findings,
               max(v.risk_score) AS worst_risk_score
        FROM assets a
        LEFT JOIN v_current_risk v ON v.asset_id = a.id AND v.status = 'open'
        WHERE {' AND '.join(where)}
        GROUP BY a.id
        ORDER BY max(v.risk_score) DESC NULLS LAST, a.hostname
        LIMIT {int(limit)} OFFSET {int(offset)}
        """,
        params or None,
    )
    return [AssetOut(**r) for r in rows]


@app.get("/assets/{asset_id}", response_model=AssetOut, tags=["assets"])
def get_asset(asset_id: int) -> AssetOut:
    row = query_one(
        """
        SELECT a.*, count(v.finding_id) AS open_findings,
               max(v.risk_score) AS worst_risk_score
        FROM assets a
        LEFT JOIN v_current_risk v ON v.asset_id = a.id AND v.status='open'
        WHERE a.id = %s GROUP BY a.id
        """,
        (asset_id,),
    )
    if not row:
        raise HTTPException(404, f"asset {asset_id} not found")
    return AssetOut(**row)


# --- findings & triage -----------------------------------------------------

def _finding_filters(
    band: Annotated[str | None, Query(description="critical|high|medium|low")] = None,
    team: str | None = None,
    hostname: str | None = None,
    cve_id: str | None = None,
    package: str | None = None,
    environment: str | None = None,
    internet_facing: bool | None = None,
    kev_only: bool = False,
    overdue_only: bool = False,
) -> dict:
    return {
        "band": band, "team": team, "hostname": hostname, "cve_id": cve_id,
        "package": package, "environment": environment,
        "internet_facing": internet_facing, "kev_only": kev_only,
        "overdue_only": overdue_only,
    }


def _build_where(f: dict) -> tuple[str, dict]:
    """Build the WHERE clause for the findings query.

    Every column is qualified with the `v.` alias. The query joins
    v_current_risk to assets and the two share several column names
    (hostname, owner_team, internet_facing, environment), so a bare name is
    an AmbiguousColumn error at query time rather than a startup failure.
    """
    where, params = ["v.status = 'open'"], {}
    mapping = {
        "band": ("v.risk_band = %(band)s", "band"),
        "team": ("v.owner_team = %(team)s", "team"),
        "hostname": ("v.hostname = %(hostname)s", "hostname"),
        "cve_id": ("v.cve_id = %(cve_id)s", "cve_id"),
        "package": ("v.package_name = %(package)s", "package"),
        "environment": ("v.environment = %(environment)s", "environment"),
    }
    for key, (clause, pname) in mapping.items():
        if f.get(key):
            where.append(clause)
            params[pname] = f[key]
    if f.get("internet_facing") is not None:
        where.append("v.internet_facing = %(inet)s")
        params["inet"] = f["internet_facing"]
    if f.get("kev_only"):
        where.append("v.kev_listed")
    if f.get("overdue_only"):
        where.append("v.due_date < CURRENT_DATE")
    return " AND ".join(where), params


@app.get("/findings", response_model=list[FindingOut], tags=["findings"])
def list_findings(
    filters: Annotated[dict, Depends(_finding_filters)],
    sort: Literal["risk", "due_date", "epss"] = "risk",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[FindingOut]:
    """Open findings, newest risk assessment only, most urgent first."""
    where, params = _build_where(filters)
    order = {
        "risk": "v.risk_score DESC, v.epss_score DESC NULLS LAST",
        "due_date": "v.due_date ASC, v.risk_score DESC",
        "epss": "v.epss_score DESC NULLS LAST, v.risk_score DESC",
    }[sort]
    rows = query(
        f"""
        SELECT v.*, a.os_family
        FROM v_current_risk v JOIN assets a ON a.id = v.asset_id
        WHERE {where}
        ORDER BY {order}
        LIMIT {int(limit)} OFFSET {int(offset)}
        """,
        params or None,
    )
    return [FindingOut(**{k: v for k, v in r.items()
                          if k in FindingOut.model_fields}) for r in rows]


@app.get("/findings/{finding_id}/factors", response_model=RiskFactors,
         tags=["findings"])
def finding_factors(finding_id: int) -> RiskFactors:
    """The scoring arithmetic behind one finding's priority.

    Exposed because an owner who disputes a due date should be shown the
    inputs, not told to trust the number.
    """
    row = query_one(
        """
        SELECT finding_id, risk_score, risk_band, due_date, sla_days,
               policy_version, computed_at, factors
        FROM v_current_risk WHERE finding_id = %s
        """,
        (finding_id,),
    )
    if not row:
        raise HTTPException(404, f"no current assessment for finding {finding_id}")
    return RiskFactors(**row)


# --- CVEs ------------------------------------------------------------------

@app.get("/cves/{cve_id}", response_model=CveOut, tags=["cves"])
def get_cve(cve_id: str) -> CveOut:
    row = query_one(
        """
        SELECT c.*,
               (SELECT count(DISTINCT asset_id) FROM findings f
                WHERE f.cve_id = c.cve_id AND f.status='open') AS affected_assets,
               (SELECT array_agg(DISTINCT package_name) FROM findings f
                WHERE f.cve_id = c.cve_id AND f.status='open') AS affected_packages
        FROM cves c WHERE c.cve_id = %s
        """,
        (cve_id.upper(),),
    )
    if not row:
        raise HTTPException(404, f"{cve_id} not found")
    return CveOut(**{k: v for k, v in row.items() if k in CveOut.model_fields})


# --- fix actions (correlation) --------------------------------------------

@app.get("/fix-actions", response_model=list[FixActionOut], tags=["remediation"])
def list_fix_actions(
    band: str | None = None,
    team: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[FixActionOut]:
    """Findings collapsed into the upgrades a human actually performs.

    This is the unit the dashboard should show: 103,166 findings reduce to
    ~1,705 fix actions, because one `apt-get install` closes many CVEs.
    """
    from sentinel.agents.correlate import correlate

    actions = correlate(bands=[band] if band else None,
                        teams=[team] if team else None, limit=limit)
    keys = [(a.package_name, a.fixed_version) for a in actions]
    plans: dict[tuple[str, str | None], bool] = {}
    if keys:
        for r in query(
            "SELECT package_name, fixed_version, grounding_passed "
            "FROM remediation_plans"
        ):
            plans[(r["package_name"], r["fixed_version"])] = r["grounding_passed"]

    out = []
    for a in actions:
        key = (a.package_name, a.fixed_version)
        out.append(FixActionOut(
            idempotency_key=a.idempotency_key, title=a.title,
            owner_team=a.owner_team, owner_email=a.owner_email,
            package_name=a.package_name, os_family=a.os_family,
            fixed_version=a.fixed_version, risk_band=a.risk_band,
            due_date=a.due_date, max_risk_score=a.max_risk_score,
            asset_count=a.asset_count,
            internet_facing_count=a.internet_facing_count,
            prod_count=a.prod_count, cve_ids=a.cve_ids,
            kev_cve_ids=a.kev_cve_ids, finding_count=len(a.finding_ids),
            hostnames=a.hostnames[:20],
            version_requirements=a.version_requirements,
            has_plan=key in plans, plan_grounded=plans.get(key, False),
        ))
    return out


@app.get("/plans/{plan_id}", response_model=PlanOut, tags=["remediation"])
def get_plan(plan_id: int) -> PlanOut:
    row = query_one("SELECT * FROM remediation_plans WHERE id = %s", (plan_id,))
    if not row:
        raise HTTPException(404, f"plan {plan_id} not found")
    return PlanOut(**{k: v for k, v in row.items() if k in PlanOut.model_fields})


@app.get("/plans", response_model=list[PlanOut], tags=["remediation"])
def list_plans(
    grounded_only: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[PlanOut]:
    rows = query(
        f"""SELECT * FROM remediation_plans
            {'WHERE grounding_passed' if grounded_only else ''}
            ORDER BY created_at DESC LIMIT {int(limit)}"""
    )
    return [PlanOut(**{k: v for k, v in r.items() if k in PlanOut.model_fields})
            for r in rows]


# --- retrieval -------------------------------------------------------------

@app.get("/search", response_model=SearchResponse, tags=["retrieval"])
def search_corpus(
    q: Annotated[str, Query(min_length=2, description="query text or a CVE id")],
    mode: Literal["hybrid", "dense", "lexical"] = "hybrid",
    backend: Literal["pgvector", "qdrant"] = "pgvector",
    prefilter: bool = True,
    k: Annotated[int, Query(ge=1, le=50)] = 8,
) -> SearchResponse:
    """Hybrid retrieval over the advisory corpus.

    `mode` and `prefilter` are exposed because the difference is the point: a
    dense-only search for "CVE-2021-44228" returns unrelated vim CVEs, since
    the Log4j family's descriptions sit at 0.79-0.84 cosine similarity to each
    other. Lexical matching plus a CVE prefilter is what makes retrieval
    correct here.
    """
    from sentinel.rag.hybrid import search as hybrid_search

    if backend == "qdrant":
        from sentinel.rag.qdrant_store import QdrantStore
        store = QdrantStore()
    else:
        from sentinel.rag.pgvector_store import PgVectorStore
        store = PgVectorStore()

    r = hybrid_search(q, store=store, k=k, mode=mode, prefilter=prefilter)
    return SearchResponse(
        query=r["query"], mode=r["mode"], backend=r["backend"],
        prefilter_cves=r["prefilter_cves"], timings=r["timings"],
        total_ms=r["total_ms"],
        hits=[{
            "chunk_id": h.chunk_id, "content": h.content, "cve_ids": h.cve_ids,
            "source": h.source, "rrf_score": h.rrf_score,
            "lexical_rank": h.lexical_rank, "dense_rank": h.dense_rank,
        } for h in r["hits"]],
    )


# --- owner view ------------------------------------------------------------

@app.get("/teams", tags=["owners"])
def list_teams() -> list[dict]:
    """Per-team workload: what each owner is actually on the hook for."""
    return query(
        """
        SELECT owner_team, owner_email,
               count(*) AS open_findings,
               count(DISTINCT asset_id) AS assets,
               count(*) FILTER (WHERE risk_band = 'critical') AS critical,
               count(*) FILTER (WHERE risk_band = 'high') AS high,
               count(*) FILTER (WHERE due_date < CURRENT_DATE) AS overdue,
               min(due_date) AS next_due,
               round(max(risk_score), 1) AS worst_risk_score
        FROM v_current_risk WHERE status = 'open'
        GROUP BY owner_team, owner_email
        ORDER BY critical DESC, open_findings DESC
        """
    )
