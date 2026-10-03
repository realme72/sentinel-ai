"""API response models.

Explicit rather than returning raw rows: the response shape is the dashboard's
contract, and letting a column rename leak into the UI is how a schema change
becomes a frontend bug.
"""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field


class Health(BaseModel):
    status: str
    postgres: bool
    qdrant: bool
    corpus_chunks: int
    migration: str | None = None


class Stats(BaseModel):
    assets: int
    cves: int
    findings: int
    findings_open: int
    kev_cves: int
    corpus_chunks: int
    plans: int
    plans_grounded: int
    tickets: int
    fix_actions: int | None = Field(None, description="computed on demand; null when skipped")


class AssetOut(BaseModel):
    id: int
    hostname: str
    os_family: str
    os_version: str | None
    environment: str
    business_criticality: int
    internet_facing: bool
    data_classification: str
    owner_team: str
    owner_email: str
    tags: dict
    open_findings: int | None = None
    worst_risk_score: float | None = None


class FindingOut(BaseModel):
    finding_id: int
    hostname: str
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    os_family: str | None = None
    environment: str
    internet_facing: bool
    owner_team: str
    owner_email: str
    cvss_v31_score: float | None
    cvss_severity: str | None
    epss_score: float | None
    kev_listed: bool
    kev_ransomware: bool
    risk_score: float
    risk_band: str
    sla_days: int
    due_date: date
    overdue: bool
    days_remaining: int
    policy_version: str


class RiskFactors(BaseModel):
    """The scoring arithmetic, so a disputed priority can be shown rather than
    asserted."""

    finding_id: int
    risk_score: float
    risk_band: str
    due_date: date
    sla_days: int
    policy_version: str
    computed_at: datetime
    factors: dict


class CveOut(BaseModel):
    cve_id: str
    description: str | None
    cvss_v31_score: float | None
    cvss_v40_score: float | None
    cvss_severity: str | None
    cwe_ids: list[str]
    kev_listed: bool
    kev_ransomware: bool
    kev_date_added: date | None
    kev_due_date: date | None
    kev_required_action: str | None
    epss_score: float | None
    epss_percentile: float | None
    reference_urls: list[str]
    affected_assets: int | None = None
    affected_packages: list[str] | None = None


class FixActionOut(BaseModel):
    idempotency_key: str
    title: str
    owner_team: str
    owner_email: str
    package_name: str
    os_family: str
    fixed_version: str | None
    risk_band: str
    due_date: date
    max_risk_score: float
    asset_count: int
    internet_facing_count: int
    prod_count: int
    cve_ids: list[str]
    kev_cve_ids: list[str]
    finding_count: int
    hostnames: list[str]
    version_requirements: dict[str, str]
    has_plan: bool = False
    plan_grounded: bool = False


class PlanOut(BaseModel):
    id: int
    cve_id: str
    package_name: str
    os_family: str
    fixed_version: str | None
    plan_markdown: str
    commands: list
    rollback: str | None
    compensating_controls: str | None
    requires_reboot: bool | None
    model: str
    grounding_passed: bool
    grounding_report: dict | None
    created_at: datetime


class SearchHitOut(BaseModel):
    chunk_id: int
    content: str
    cve_ids: list[str]
    source: str
    rrf_score: float
    lexical_rank: int | None
    dense_rank: int | None


class SearchResponse(BaseModel):
    query: str
    mode: str
    backend: str
    prefilter_cves: list[str]
    timings: dict
    total_ms: float
    hits: list[SearchHitOut]


class Page(BaseModel):
    total: int
    limit: int
    offset: int
