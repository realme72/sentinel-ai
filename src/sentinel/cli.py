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


if __name__ == "__main__":
    app()
