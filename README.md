# Sentinel-AI

Agentic vulnerability triage for large asset fleets.

Scanners tell you that 40,000 things are broken. Sentinel-AI works out which
of them matter, who owns them, by when they must be fixed, and exactly what
to run — then files one ticket per *fix action* instead of one per finding.

```
 Trivy ──┐
         ├─► findings ──► enrichment ──► risk + SLA ──► correlation ──► remediation ──► tickets
 assets ─┘               (NVD/KEV/EPSS)   (rules)        (agent)         (RAG agent)    (GitHub/Jira)
                                              │                              │
                                              └── auditable ─────────────────┴── grounded + evaluated
```

## The design rule everything follows

Vulnerability management is an **audit surface**. If a model invents a patch
version or a due date, that is not a bug — it is a compliance defect. So the
system is split into two planes with a hard wall between them:

| | Deterministic plane | AI plane |
|---|---|---|
| Owns | facts, scores, SLA dates, ticket identity | synthesis, correlation, narrative, Q&A |
| Fails by | crashing — loud, fixable | lying plausibly — silent, dangerous |
| Code | `risk/`, `enrich/`, `ingest/` | `agents/`, `rag/` |

**A due date is never model-authored.** It is
`f(CVSS, EPSS, KEV, internet_facing, business_criticality)` → SLA band →
`first_seen + sla_days`, recorded with every input in `risk_assessments.factors`
so any number can be reproduced and defended. The model's job is to *explain*
the date and make hitting it easy.

### Exploitation evidence cannot be diluted

The score is additive (severity ≤40, exploit ≤30, exposure ≤15, asset ≤15),
but additive models have a known failure mode: a CVSS 10.0 actively used in
ransomware drops to "high" on an internal dev box, because zero exposure and
low asset value cancel out ground truth. Sentinel applies **floors** — KEV
listed never bands below `high`, KEV + ransomware never below `critical`.
Context may raise urgency; it may not erase evidence.

(This was caught by a failing test, not by design. See `tests/test_risk.py`.)

## Data sources — all free, no trials

| Source | Gives us | Key |
|---|---|---|
| [Trivy](https://trivy.dev) | findings from FS/SBOM/image scans | none |
| [NVD API 2.0](https://nvd.nist.gov/developers) | CVSS v3.1/v4, CWE, CPE | free, optional |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | *actually* exploited + federal due dates | none |
| [FIRST EPSS](https://www.first.org/epss/) | daily exploit probability | none |
| [OSV.dev](https://osv.dev) | precise fixed-versions per ecosystem | none |
| GitHub Advisory DB | ecosystem advisories | existing token |

## RAG: hybrid retrieval is not optional here

Queries in this domain contain `CVE-2021-44228`, `openssl 1.1.1w`,
`RHSA-2024:1234`. Embeddings are **bad** at exact identifiers — cosine
similarity will happily return `CVE-2021-44229`.

So retrieval is:

1. **Lexical** — Postgres `tsvector` + trigram (exact IDs, version strings)
2. **Dense** — pgvector HNSW / Qdrant (`bge-small-en-v1.5`, local, free)
3. **Fused** — reciprocal rank fusion, then rerank to top-8
4. **Prefiltered** — hard metadata filter on `cve_ids` when the query names one

Both vector stores run behind one `VectorStore` protocol and are dual-written,
so recall@k and latency can be A/B'd rather than argued about.

### Grounding gate

Before any plan reaches a ticket, a **non-LLM** check asserts that every CVE ID
and version string in the output appears verbatim in the retrieved context.
Plans that fail are blocked (`remediation_plans.grounding_passed`). A
hallucinated patch version in a security ticket is the failure that kills the
product, so it is guarded by a regex, not by a prompt.

DeepEval adds faithfulness / contextual precision / contextual recall and a
custom `actionability` G-Eval metric, gated in CI against a golden set.

## Cost and latency

The pipeline touches ~40k findings but makes ~200 LLM calls. In order of impact:

1. **Plan cache keyed on `(cve_id, package, os_family, fixed_version)`** — the
   same CVE across 500 hosts is *one* call, not 500. ~100× win; dwarfs the rest.
2. **Deterministic prefilter** — only findings above a risk threshold reach an
   agent; the rest get templated tickets. Typically −85% LLM volume.
3. **Message Batches API** for the nightly sweep — 50% cost, latency irrelevant.
4. **Prompt caching** on the stable system prompt + tool schemas (~90% off the
   cached prefix). Volatile values go *after* the last breakpoint.
5. **Incremental scans** — only diffs since the last run enter the pipeline.
6. **Model routing** — Haiku 4.5 for extraction/classification, Opus 5 for plans.
7. **Async + bounded semaphores** — NVD's 50 req/30s is the real bottleneck.

## Stack

Runs entirely on localhost. **No Docker required.**

- Postgres 18 + pgvector 0.8.6 (rows, BM25, and vectors in one transactional store)
  plus `citext`, `btree_gin`, `pg_trgm`, `pgcrypto`, `unaccent`, `pg_stat_statements`
- Qdrant 1.19 (native `aarch64-apple-darwin` binary in `bin/`)
- LangGraph agents · Anthropic Claude (Opus 5 planner, Haiku 4.5 bulk)
- sentence-transformers (local embeddings, no API cost)
- DeepEval · pytest · Trivy · Typer CLI

## Status

- [x] Schema under Alembic migrations, deterministic risk + SLA engine
- [x] Synthetic 500-host fleet with real vulnerabilities (103,166 findings, 728 CVEs)
- [x] NVD / KEV / EPSS enrichment
- [x] Hybrid retrieval, pgvector + Qdrant behind one protocol
- [x] LangGraph remediation planner + non-LLM grounding gate
- [x] Correlation: 103,166 findings -> 1,705 fix actions
- [x] GitHub / Jira / memory ticket sinks, dry-run by default
- [ ] DeepEval suite in CI
- [ ] FastAPI, owner digests, dashboard

146 tests, CI green.

## Models

The planner sits behind a `PlannerLLM` protocol, so the provider is
configuration rather than architecture:

| Provider | Use |
|---|---|
| Any OpenAI-compatible endpoint (Groq, Gemini, Cerebras, Ollama) | default; Groq's free tier runs the whole fleet |
| Anthropic (Opus 5 / Haiku 4.5) | when quality matters more than cost |

Model is routed by risk band -- the stronger model for critical and high, the
cheaper one for medium and low.

**The whole fleet costs 108 LLM calls.** 103,166 findings collapse to 1,705
fix actions, which share only 108 unique
`(cve, package, os_family, fixed_version)` plan-cache keys. That is an 88%
cache hit rate, and it is why this runs inside a free tier's daily quota.

> Free hosted tiers generally reserve the right to train on submitted data.
> What this sends is hostnames, package versions and unpatched CVEs. Fine for
> a synthetic fleet; use a self-hosted model or a paid API for real asset
> inventory.

### Measured

| Stage | Scale | Time |
|---|---|---|
| Trivy scan | 500 hosts | 6.2s (81 hosts/s) |
| Load findings | 100,937 rows | 2.2s |
| KEV + EPSS | 382k feed rows | 4s |
| NVD enrichment | 690 CVEs | 423s (rate-limit bound) |
| Risk scoring | 100,937 findings | 0.8s (126k rows/s) |
| Triage query | 20 of 100,937 | 5.2ms |

## Schema changes

Migrations are the single source of truth. `docs/schema.reference.sql` is a
generated snapshot for reading only -- two files that can both create tables is
how a schema and its history drift apart.

```bash
make migrate      # apply to head
make history      # what's applied
make drift        # verify migrations reproduce the live schema
```

`make drift` builds a throwaway database from migrations and diffs it against
the live one. It already caught an HNSW index that existed only because it had
been created by hand.

## Quickstart

```bash
brew install uv trivy postgresql@18 pgvector
uv venv --python 3.12 && uv pip install -e ".[dev]"
createdb sentinel && psql -d sentinel -f src/sentinel/db/schema.sql
cp .env.example .env
.venv/bin/pytest -q
```
