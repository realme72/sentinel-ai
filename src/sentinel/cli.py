"""Sentinel-AI command line."""

from __future__ import annotations

import time
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.table import Table

from sentinel.config import get_settings
from sentinel.db import session as db

structlog.configure(
    processors=[structlog.dev.ConsoleRenderer(colors=True)],
    wrapper_class=structlog.make_filtering_bound_logger(20),
)
log = structlog.get_logger()
console = Console()

app = typer.Typer(help="Sentinel-AI: agentic vulnerability triage", no_args_is_help=True)
db_app = typer.Typer(help="Database lifecycle")
fleet_app = typer.Typer(help="Synthetic asset fleet")
app.add_typer(db_app, name="db")
app.add_typer(fleet_app, name="fleet")


@db_app.command("init")
def db_init() -> None:
    """Apply schema.sql (idempotent)."""
    db.apply_schema()
    console.print("[green]schema applied[/green]")


@db_app.command("reset")
def db_reset(
    yes: bool = typer.Option(False, "--yes", help="skip confirmation"),
) -> None:
    """Drop every table and reapply the schema. Destructive."""
    if not yes:
        typer.confirm("Drop ALL tables in the sentinel database?", abort=True)
    db.reset_database()
    console.print("[yellow]database reset[/yellow]")


@db_app.command("stats")
def db_stats() -> None:
    """Row counts and the current triage picture."""
    rows = db.query(
        """
        SELECT 'assets' AS t, count(*) AS n FROM assets
        UNION ALL SELECT 'cves', count(*) FROM cves
        UNION ALL SELECT 'findings', count(*) FROM findings
        UNION ALL SELECT 'findings (open)', count(*) FROM findings WHERE status='open'
        UNION ALL SELECT 'risk_assessments', count(*) FROM risk_assessments
        UNION ALL SELECT 'corpus_chunks', count(*) FROM corpus_chunks
        UNION ALL SELECT 'tickets', count(*) FROM tickets
        """
    )
    table = Table(title="sentinel", show_header=True)
    table.add_column("table"); table.add_column("rows", justify="right")
    for r in rows:
        table.add_row(r["t"], f"{r['n']:,}")
    console.print(table)


@fleet_app.command("generate")
def fleet_generate(
    count: int = typer.Option(500, help="number of synthetic hosts"),
    seed: int = typer.Option(20260930, help="deterministic seed"),
) -> None:
    """Generate the asset fleet and one CycloneDX SBOM per host."""
    from sentinel.ingest.synth import write_fleet

    settings = get_settings()
    out = settings.raw_dir / "sbom"
    t0 = time.perf_counter()
    assets = write_fleet(out, count=count, seed=seed)
    console.print(
        f"[green]{len(assets)} hosts[/green] -> {out} "
        f"({time.perf_counter() - t0:.1f}s)"
    )


@app.command("scan")
def scan(
    workers: int = typer.Option(8, help="parallel trivy processes"),
    count: int = typer.Option(500, help="fleet size to register"),
    seed: int = typer.Option(20260930),
) -> None:
    """Scan every SBOM with Trivy and load assets, CVEs and findings."""
    from sentinel.ingest.synth import generate_assets
    from sentinel.ingest.trivy import load_assets, load_findings, scan_fleet

    settings = get_settings()
    sbom_dir = settings.raw_dir / "sbom"

    t0 = time.perf_counter()
    assets = generate_assets(count, seed)
    asset_ids = load_assets(assets)
    console.print(f"assets loaded: {len(asset_ids):,}")

    scan_row = db.query_one(
        "INSERT INTO scans (scanner, target) VALUES ('trivy', %s) RETURNING id",
        (str(sbom_dir),),
    )
    scan_id = scan_row["id"]

    t_scan = time.perf_counter()
    outcomes = scan_fleet(sbom_dir, max_workers=workers)
    scan_secs = time.perf_counter() - t_scan

    t_load = time.perf_counter()
    stats = load_findings(outcomes, asset_ids, scan_id)
    load_secs = time.perf_counter() - t_load

    db.execute("UPDATE scans SET finished_at = now() WHERE id = %s", (scan_id,))

    failed = [o.hostname for o in outcomes if o.error]
    console.print(
        f"[green]scan #{scan_id}[/green] hosts={len(outcomes)} "
        f"cves={stats['cves']:,} findings={stats['findings']:,} "
        f"non-cve-skipped={stats['skipped']:,}"
    )
    console.print(
        f"  timing: scan {scan_secs:.1f}s ({len(outcomes)/max(scan_secs,0.01):.1f} hosts/s), "
        f"load {load_secs:.1f}s, total {time.perf_counter()-t0:.1f}s"
    )
    if failed:
        console.print(f"[red]{len(failed)} hosts failed:[/red] {failed[:5]}")


enrich_app = typer.Typer(help="Enrich CVEs from free feeds")
app.add_typer(enrich_app, name="enrich")


@enrich_app.command("kev")
def enrich_kev() -> None:
    """CISA Known Exploited Vulnerabilities (one bulk file)."""
    from sentinel.enrich.kev import load_kev
    console.print(load_kev())


@enrich_app.command("epss")
def enrich_epss() -> None:
    """FIRST EPSS exploit probabilities (one bulk file)."""
    from sentinel.enrich.epss import load_epss
    console.print(load_epss())


@enrich_app.command("nvd")
def enrich_nvd(
    limit: int = typer.Option(None, help="only this many CVEs"),
    refresh: bool = typer.Option(False, help="re-fetch already-enriched CVEs"),
    concurrency: int = typer.Option(8, help="in-flight requests (rate limiter still caps the rate)"),
) -> None:
    """NVD API 2.0: authoritative CVSS, CWE, descriptions. Resumable."""
    from sentinel.enrich.nvd import load_nvd
    console.print(load_nvd(limit=limit, refresh=refresh, concurrency=concurrency))


@enrich_app.command("all")
def enrich_all() -> None:
    """KEV and EPSS first (bulk, seconds), then NVD (per-CVE, rate-limited)."""
    from sentinel.enrich.epss import load_epss
    from sentinel.enrich.kev import load_kev
    from sentinel.enrich.nvd import load_nvd
    console.print("kev :", load_kev())
    console.print("epss:", load_epss())
    console.print("nvd :", load_nvd())


@app.command("score")
def score() -> None:
    """Apply the deterministic risk policy to every open finding."""
    from sentinel.risk.pipeline import score_open_findings
    console.print(score_open_findings())


@app.command("triage")
def triage(
    limit: int = typer.Option(15, help="rows to show"),
    band: str = typer.Option(None, help="filter: critical|high|medium|low"),
    team: str = typer.Option(None, help="filter by owner team"),
) -> None:
    """The prioritised queue -- what an owner would actually be handed."""
    where, params = ["1=1"], []
    if band:
        where.append("risk_band = %s"); params.append(band)
    if team:
        where.append("owner_team = %s"); params.append(team)
    rows = db.query(
        f"""SELECT hostname, cve_id, package_name, risk_score, risk_band,
                   due_date, days_remaining, kev_listed, epss_score, owner_team
            FROM v_current_risk WHERE {' AND '.join(where)}
            ORDER BY risk_score DESC, epss_score DESC NULLS LAST LIMIT {int(limit)}""",
        params or None,
    )
    t = Table(title="triage queue", show_header=True, header_style="bold")
    for col in ("host", "cve", "package", "score", "band", "due", "days", "kev", "epss", "team"):
        t.add_column(col, justify="right" if col in {"score", "days", "epss"} else "left")
    palette = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for r in rows:
        t.add_row(
            r["hostname"], r["cve_id"], r["package_name"][:18],
            f"{r['risk_score']:.1f}",
            f"[{palette.get(r['risk_band'],'')}]{r['risk_band']}[/]",
            str(r["due_date"]), str(r["days_remaining"]),
            "YES" if r["kev_listed"] else "",
            f"{r['epss_score']:.3f}" if r["epss_score"] is not None else "",
            r["owner_team"],
        )
    console.print(t)


if __name__ == "__main__":
    app()
