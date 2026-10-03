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

    # --- LLM: Anthropic ---
    planner_model: str = "claude-opus-5"
    bulk_model: str = "claude-haiku-4-5"
    llm_concurrency: int = 8

    # --- LLM: any OpenAI-compatible endpoint (Groq, Gemini, Cerebras, Ollama) ---
    openai_base_url: str = "https://api.groq.com/openai/v1"
    openai_model: str = "openai/gpt-oss-120b"        # critical + high
    openai_bulk_model: str = "openai/gpt-oss-20b"    # medium + low
    openai_api_key: str | None = None
    # Starting guess only -- the planner reads x-ratelimit-* response headers
    # and re-paces itself, so a stale number here costs one slow call rather
    # than a whole throttled run. Measured on Groq's free tier: 1,000
    # requests/day and 8,000 tokens/minute per model.
    openai_requests_per_minute: int = 28
    openai_tokens_per_minute: int = 8000
    # Counted as a reservation against BOTH the per-minute and per-day token
    # budgets, so it directly sets how many plans a day buys. Measured: a real
    # grounded plan used 491 completion tokens, so 2500 reserved five times
    # what it needed and cut the daily plan count by the same factor.
    # 1200 leaves headroom for a long plan without wasting the budget.
    openai_max_tokens: int = 1200
    # gpt-oss reasoning tokens count against max_tokens and crowd out the
    # JSON; "low" leaves room for the answer. Empty to omit the field for
    # providers that reject it.
    openai_reasoning_effort: str | None = "low"

    # Which planner the router uses per risk band.
    planner_provider: str = "openai"   # openai | anthropic

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

    def resolve_openai_key(self) -> str | None:
        """Settings field first, then the conventional provider env vars."""
        import os
        return (
            self.openai_api_key
            or os.environ.get("GROQ_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def corpus_dir(self) -> Path:
        return self.data_dir / "corpus"


@lru_cache
def get_settings() -> Settings:
    return Settings()
