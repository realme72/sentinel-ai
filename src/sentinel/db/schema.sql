-- Sentinel-AI schema.
--
-- Design rule: this file owns FACTS and DERIVED-BY-RULE values only.
-- Anything an LLM produces lands in `remediation_plans` and is always
-- traceable to the retrieval context that produced it. Due dates are
-- computed by the deterministic SLA policy, never by a model.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- Asset inventory (the CMDB stand-in)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id                  BIGSERIAL PRIMARY KEY,
    hostname            TEXT NOT NULL UNIQUE,
    ip_address          INET,
    os_family           TEXT NOT NULL,              -- debian | rhel | alpine | windows
    os_version          TEXT,
    environment         TEXT NOT NULL,              -- prod | staging | dev
    business_criticality SMALLINT NOT NULL CHECK (business_criticality BETWEEN 1 AND 5),
    internet_facing     BOOLEAN NOT NULL DEFAULT FALSE,
    data_classification TEXT NOT NULL DEFAULT 'internal',  -- public|internal|confidential|restricted
    owner_team          TEXT NOT NULL,
    owner_email         TEXT NOT NULL,
    tags                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets (owner_team, owner_email);
CREATE INDEX IF NOT EXISTS idx_assets_exposure ON assets (internet_facing, environment);

-- ---------------------------------------------------------------------------
-- CVE facts, sourced from NVD / OSV. No model output here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    published_at        TIMESTAMPTZ,
    last_modified_at    TIMESTAMPTZ,
    description         TEXT,
    cvss_v31_score      NUMERIC(3,1),
    cvss_v31_vector     TEXT,
    cvss_v40_score      NUMERIC(3,1),
    cvss_v40_vector     TEXT,
    cvss_severity       TEXT,                       -- LOW|MEDIUM|HIGH|CRITICAL
    cwe_ids             TEXT[] NOT NULL DEFAULT '{}',
    reference_urls      TEXT[] NOT NULL DEFAULT '{}',
    -- CISA KEV
    kev_listed          BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added      DATE,
    kev_due_date        DATE,
    kev_ransomware      BOOLEAN NOT NULL DEFAULT FALSE,
    -- FIRST EPSS (refreshed daily)
    epss_score          NUMERIC(6,5),
    epss_percentile     NUMERIC(6,5),
    epss_updated_at     TIMESTAMPTZ,
    enriched_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves (kev_listed) WHERE kev_listed;
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves (epss_score DESC NULLS LAST);

-- ---------------------------------------------------------------------------
-- Scan runs and findings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id              BIGSERIAL PRIMARY KEY,
    scanner         TEXT NOT NULL,                  -- trivy | grype
    scanner_version TEXT,
    target          TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    raw_path        TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                BIGSERIAL PRIMARY KEY,
    asset_id          BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    package_name      TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version     TEXT,
    package_type      TEXT,                         -- deb | rpm | apk | npm | pypi | gobinary
    status            TEXT NOT NULL DEFAULT 'open', -- open|fixed|accepted_risk|false_positive
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    first_scan_id     BIGINT REFERENCES scans(id),
    last_scan_id      BIGINT REFERENCES scans(id),
    -- Idempotency: re-scanning must UPDATE last_seen, never insert a duplicate.
    UNIQUE (asset_id, cve_id, package_name, installed_version)
);
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings (status, cve_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (asset_id, status);
-- The dedup key: one fix action can close many findings.
CREATE INDEX IF NOT EXISTS idx_findings_fixgroup
    ON findings (asset_id, package_name, fixed_version) WHERE status = 'open';

-- ---------------------------------------------------------------------------
-- Deterministic risk + SLA. Recomputed, never model-authored.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_assessments (
    id            BIGSERIAL PRIMARY KEY,
    finding_id    BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    risk_score    NUMERIC(5,2) NOT NULL,
    risk_band     TEXT NOT NULL,                    -- critical|high|medium|low
    sla_days      INTEGER NOT NULL,
    due_date      DATE NOT NULL,
    -- Every input that produced the score, so any number is reproducible.
    factors       JSONB NOT NULL,
    policy_version TEXT NOT NULL,
    computed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_finding ON risk_assessments (finding_id, computed_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_due ON risk_assessments (due_date, risk_band);

-- ---------------------------------------------------------------------------
-- LLM output. Cached by fix-identity so N hosts sharing a CVE cost ONE call.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_plans (
    id              BIGSERIAL PRIMARY KEY,
    -- The cache key. This is the single biggest cost/latency lever in the system.
    cve_id          TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    package_name    TEXT NOT NULL,
    os_family       TEXT NOT NULL,
    fixed_version   TEXT,
    plan_markdown   TEXT NOT NULL,
    commands        JSONB NOT NULL DEFAULT '[]'::jsonb,
    rollback        TEXT,
    compensating_controls TEXT,
    requires_reboot BOOLEAN,
    -- Provenance: which chunks the model was shown, for eval + audit.
    context_chunk_ids BIGINT[] NOT NULL DEFAULT '{}',
    citations       JSONB NOT NULL DEFAULT '[]'::jsonb,
    model           TEXT NOT NULL,
    -- Grounding gate result (non-LLM check). Plans that fail never reach a ticket.
    grounding_passed BOOLEAN NOT NULL DEFAULT FALSE,
    grounding_report JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, package_name, os_family, fixed_version)
);

-- ---------------------------------------------------------------------------
-- Tickets. Sink-agnostic; the adapter fills external_* columns.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tickets (
    id              BIGSERIAL PRIMARY KEY,
    -- Stable hash over the finding bundle. Prevents duplicate tickets across runs.
    idempotency_key TEXT NOT NULL UNIQUE,
    sink            TEXT NOT NULL,                  -- github | jira | memory
    external_id     TEXT,
    external_url    TEXT,
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    owner_team      TEXT NOT NULL,
    owner_email     TEXT NOT NULL,
    risk_band       TEXT NOT NULL,
    due_date        DATE NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',-- pending|open|closed|failed
    plan_id         BIGINT REFERENCES remediation_plans(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ticket_findings (
    ticket_id  BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, finding_id)
);

-- ---------------------------------------------------------------------------
-- RAG corpus. Hybrid retrieval: tsvector (BM25-ish) + pgvector (HNSW).
-- Mirrored into Qdrant by the dual-write ingester.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS corpus_documents (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,                     -- nvd|osv|rhsa|usn|dsa|msrc|kev|runbook
    source_ref   TEXT NOT NULL,                     -- advisory id / URL
    title        TEXT,
    cve_ids      TEXT[] NOT NULL DEFAULT '{}',
    os_family    TEXT,
    raw_text     TEXT NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, source_ref)
);
CREATE INDEX IF NOT EXISTS idx_corpus_docs_cves ON corpus_documents USING GIN (cve_ids);

CREATE TABLE IF NOT EXISTS corpus_chunks (
    id           BIGSERIAL PRIMARY KEY,
    document_id  BIGINT NOT NULL REFERENCES corpus_documents(id) ON DELETE CASCADE,
    chunk_index  INTEGER NOT NULL,
    content      TEXT NOT NULL,
    -- Denormalised so metadata prefilters don't need a join on the hot path.
    cve_ids      TEXT[] NOT NULL DEFAULT '{}',
    source       TEXT NOT NULL,
    os_family    TEXT,
    embedding    vector(384),                       -- BAAI/bge-small-en-v1.5
    tsv          tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    UNIQUE (document_id, chunk_index)
);
-- Lexical half of hybrid retrieval. Non-negotiable here: embeddings are bad at
-- exact identifiers like CVE-2021-44228 or "openssl 1.1.1w".
CREATE INDEX IF NOT EXISTS idx_chunks_tsv ON corpus_chunks USING GIN (tsv);
CREATE INDEX IF NOT EXISTS idx_chunks_cves ON corpus_chunks USING GIN (cve_ids);
CREATE INDEX IF NOT EXISTS idx_chunks_trgm ON corpus_chunks USING GIN (content gin_trgm_ops);
-- Vector half. HNSW built after bulk load (see db/session.py: build_vector_index).
