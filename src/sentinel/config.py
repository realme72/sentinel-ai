"""Runtime configuration. Everything is env-driven so the same code runs
locally, in CI (against the `memory` ticket sink), and in a scheduled job."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=PROJECT_ROOT / ".env",
        extra="ignore",
    )

    # --- datastores ---
    pg_dsn: str = "postgresql://localhost:5432/sentinel"
    qdrant_url: str = "http://localhost:6333"
    qdrant_collection: str = "sentinel_corpus"

    # --- enrichment feeds ---
    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    osv_batch_url: str = "https://api.osv.dev/v1/querybatch"

    # NVD allows 5 req/30s anonymous, 50 req/30s with a key. This is the
    # single hardest rate limit in the pipeline, so it gets its own knob.
    nvd_concurrency: int = 4
    nvd_delay_seconds: float = 0.7

    # --- LLM ---
    planner_model: str = "claude-opus-5"
    bulk_model: str = "claude-haiku-4-5"
    llm_concurrency: int = 8

    # --- embeddings (local, free) ---
    embed_model: str = "BAAI/bge-small-en-v1.5"
    embed_dim: int = 384
    embed_batch_size: int = 64

    # --- retrieval ---
    retrieval_candidates: int = 50   # per-branch top-k before fusion
    retrieval_final_k: int = 8       # what the model actually sees
    rrf_k: int = 60                  # reciprocal-rank-fusion constant

    # --- ticketing ---
    ticket_sink: str = "github"
    github_repo: str = "realme72/sentinel-ai"
    jira_url: str | None = None
    jira_email: str | None = None
    jira_token: str | None = None
    jira_project: str | None = None

    # --- paths ---
    data_dir: Path = Field(default=PROJECT_ROOT / "data")

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def corpus_dir(self) -> Path:
        return self.data_dir / "corpus"


@lru_cache
def get_settings() -> Settings:
    return Settings()
