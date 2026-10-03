# Sentinel-AI — architecture

## The problem

A vulnerability scanner over a real fleet produces tens of thousands of
findings. On this 500-host fleet it produces **103,166**. Nobody triages that.
The queue becomes unreadable, so it goes unread, and the two findings that
genuinely matter sit next to 40,000 that don't.

Three things have to happen for that output to become work someone does:

1. **Prioritise** — which of these actually matters, and by when
2. **Collapse** — group findings into the *actions* a human performs
3. **Explain** — say exactly what to run, grounded in something citable

Sentinel-AI does all three, and the design question running through it is
**which parts may be probabilistic and which may not**.

---

## The organising principle

Vulnerability management is an **audit surface**. A due date on a security
ticket is a commitment someone is measured against; in a regulated
organisation it is evidence. If a language model invents a patch version, that
is not a bug — it is a compliance defect that an engineer will act on.

So the system is split in two, with a hard wall between:

| | Deterministic plane | AI plane |
|---|---|---|
| **Owns** | facts, risk scores, SLA dates, ticket identity | synthesis, narrative, Q&A |
| **Code** | `ingest/`, `enrich/`, `risk/`, `tickets/` | `agents/`, `rag/` |
| **Fails by** | crashing — loud, fixable | lying plausibly — silent, dangerous |
| **Verified by** | unit tests, reproducible arithmetic | a non-LLM grounding gate + eval rubric |

**The model proposes; deterministic code disposes.** That sentence explains
most of the design decisions below.

---

## The pipeline

```
 ┌─────────┐   ┌───────────┐   ┌────────┐   ┌─────────────┐   ┌────────┐   ┌─────────┐
 │ 1 INGEST│──▶│ 2 ENRICH  │──▶│ 3 SCORE│──▶│4 CORRELATE  │──▶│ 5 PLAN │──▶│6 TICKET │
 │  Trivy  │   │ NVD/KEV/  │   │ policy │   │  group into │   │LangGraph│  │ GitHub/ │
 │  SBOMs  │   │   EPSS    │   │ engine │   │ fix actions │   │  + RAG  │  │  Jira   │
 └─────────┘   └───────────┘   └────────┘   └─────────────┘   └─────────┘  └─────────┘
  103,166        728 CVEs       122,113        1,705            108 LLM      dry-run
  findings       enriched      assessments   fix actions         calls      by default
                                                                     ▲
                                                        ┌────────────┴────────────┐
                                                        │  RAG: hybrid retrieval  │
                                                        │ tsvector ∪ pgvector/    │
                                                        │ Qdrant, fused with RRF  │
                                                        └─────────────────────────┘
```

Each stage is **idempotent and pull-based**: it asks "what work is
outstanding?" and does it. That is why a crash resumes correctly, and why any
stage can later become a queue worker without rewriting it.

---

### Stage 1 — Ingest

**What happens.** Each host has a CycloneDX SBOM. Trivy scans it and reports
which installed package versions have known CVEs. Findings load into Postgres.

**Tech.** Trivy (CLI, no daemon) · CycloneDX · `ProcessPoolExecutor` ·
Postgres `COPY`

**Why these choices**

- **Process pool, not asyncio.** Trivy is a CPU-bound subprocess; async would
  be slower. Measured: **500 hosts in 6.2s, 84 hosts/sec.**
- **`COPY` into a `TEMP` staging table, then one
  `INSERT … SELECT … ON CONFLICT`.** At 103k rows `executemany` spends most of
  its wall clock on per-statement round trips. Measured: **2.2s to load.**
- **`TEMP`, not `UNLOGGED`.** An `UNLOGGED` table is permanent and shared, so
  two concurrent scans would interleave rows and cross-contaminate findings.
  This was a real bug, fixed before any concurrency existed to trigger it.
- **The fleet is synthetic; the vulnerabilities are not.** Package versions are
  real, genuinely vulnerable releases, so Trivy's real database produces real
  CVEs. Fabricated findings would let every downstream stage pass tests against
  data that could never occur.

**Bug worth knowing.** Trivy lists fixes across *every* maintained branch:
`CVE-2021-45105` on log4j 2.14.1 returns `"2.12.3, 2.17.0, 2.3.1"`. Taking the
first entry told hosts to "upgrade" to **2.12.3** — a *downgrade* that leaves
them exploitable. **4,668 findings were affected.** Selection now picks the
lowest candidate strictly above the installed version.

---

### Stage 2 — Enrich

**What happens.** Each CVE gains authoritative severity, exploitation evidence
and exploit probability.

| Feed | Gives | Shape | Cost |
|---|---|---|---|
| **CISA KEV** | *is it actually being exploited* | one ~1 MB JSON | one request |
| **FIRST EPSS** | 30-day exploit probability | one gzipped CSV (380k rows) | one request |
| **NVD 2.0** | CVSS v3.1/v4.0, CWE, descriptions | **one request per CVE** | rate-limited |

**Why the shapes matter.** KEV and EPSS are bulk files — ~4 seconds regardless
of fleet size. NVD is per-CVE and is the hardest rate limit in the system
(50 req/30s with a key), so it gets the engineering:

- **A rolling-window rate limiter, not a semaphore.** A semaphore caps
  *concurrency*, not *rate* — with fast responses it sails past 50/30s.
  Measured: **690 CVEs in 423s at 97.8/min**, essentially pinned to the quota.
- **Results commit per chunk.** Selecting `enriched_at IS NULL` is only half of
  resumability. The first version gathered all 690 then wrote once, so a crash
  at 689 persisted nothing — the docstring claimed resumability the code
  didn't have.

---

### Stage 3 — Score (the deterministic core)

**What happens.** Every open finding gets a 0–100 risk score, a band, and an
SLA due date. **No model is involved.** Given the same facts it always returns
the same answer, and every input is stored so the arithmetic can be shown.

**The formula.** Four capped components:

| Component | Max | Question it answers |
|---|---|---|
| `severity` | 40 | how bad is it if exploited (CVSS) |
| `exploit` | 30 | is it *actually* being exploited (KEV, EPSS) |
| `exposure` | 15 | can an attacker reach it |
| `asset` | 15 | what does it cost us if they do |

**`exploit` is nearly as heavy as `severity` on purpose.** A CVSS 9.8 nobody
has ever weaponised is a worse use of an engineer's afternoon than a CVSS 7.2
sitting in CISA KEV. Real example from this fleet: `CVE-2021-45105` is CVSS
**5.9** — a "medium" — with an EPSS of **0.99999**. It outranks many HIGHs,
correctly.

**Floors, because additive models have a known failure.** Log4Shell on an
internal, low-criticality dev box scores 71 → "high": zero exposure plus low
asset value cancels out a CVSS 10.0 actively used in ransomware. That is wrong
twice over — dev boxes are the classic lateral-movement beachhead, and
`environment` labels in a real CMDB are routinely stale. So **KEV-listed never
bands below `high`, KEV + ransomware never below `critical`.** Context may
*raise* urgency; it may not erase evidence.

*(Found by a failing test, not by design.)*

**SLA, tightest-wins.** `emergency (KEV + internet-facing, 3d)` → `CISA KEV
deadline` → `band baseline (7/15/45/90d)`.

**Bug worth knowing.** 477 findings were born **already overdue**. Log4Shell's
CISA deadline was 2021-12-24, so the ceiling rule handed a four-year-past due
date to a host first scanned today. An owner cannot hit a deadline that expired
before detection, and it marks every KEV finding SLA-breached on day one, which
destroys the metric. The CISA date is now a **compliance fact**
(`kev_deadline_passed` in `factors`) while `due_date` gets a real window.

**Storage.** `risk_assessments` is **append-only** for audit, but a row is
written only when the *outcome* changes (score, band, due date, policy
version). A nightly re-run that changes nothing writes nothing.
Measured: **103,166 findings scored in 0.8s (126k rows/sec)** via a
server-side cursor and `COPY`.

---

### Stage 4 — Correlate

**What happens.** Findings collapse into the upgrades a human performs.

> **103,166 findings → 1,705 fix actions. 60× reduction.**

One `apt-get install curl=7.74.0-1.3+deb11u2` closes **15 CVEs** on a host.
The unit of work is the *upgrade*, not the finding.

**The grouping key is the whole design:**
`(owner_team, package, os_family, risk_band, has_fix)`

Three decisions, each forced by measurement:

- **`risk_band` is IN the key.** 84% of `(team, package, fix)` groups mix
  bands, with due dates spanning up to **87 days**. One ticket cannot carry a
  3-day deadline for a critical host and 90 days for forty low-risk ones.
- **`fixed_version` is NOT in the key.** Grouping on it fragmented one upgrade
  into many tickets: log4j-core on one team produced **11 tickets across 7
  target versions** for the same ~10 hosts, because each CVE names the release
  that first fixed it. Nobody upgrades a package seven times. The target is now
  the **highest version required across the package**, which is safe for every
  member; the deadline stays per band. All four log4j tickets name `2.25.4`
  with dates from Oct 3 → Dec 29, so satisfying the urgent one closes the rest.
- **`os_family` IS in the key** — the first version missed this. Alpine openssl
  fixes at `1.1.1l-r0`, Debian at `1.1.1k-1+deb11u1`. Taking a max across those
  namespaces is meaningless, and it produced a plan telling an **Alpine host to
  install a Debian package** — which passed grounding, because both strings
  exist in the corpus. 28 packages span families, and the commands differ
  (`apk` vs `apt-get`).

**Idempotency keys exclude the asset set and the target version.** Hosts join
and leave a campaign, and the target rises as new CVEs land — both are
*updates* to the same ticket, not new ones.

---

### Stage 5 — Plan (RAG + agent)

#### 5a. Why RAG, and why hybrid retrieval

Models confabulate exactly the thing that matters here: **version numbers**.
Ask one which openssl release fixes a CVE and it will produce a confident,
plausible, specific answer. RAG is not here to make the model smarter — it is
here to make it **accountable**, so every version traces to a document and a
deterministic check can verify it.

**The measurement that drove the design.** A pure vector search for the literal
string `CVE-2021-44228` returns **vim use-after-free CVEs**. The Log4j family's
descriptions sit at **0.79–0.84 cosine similarity** to each other — the
embedding cannot separate them. Embeddings are weakest at exact identifiers,
and this domain is made almost entirely of exact identifiers.

| Mode | Top hit | On-target |
|---|---|---|
| Dense only | `CVE-2021-4173` (vim) | **0/3** |
| Lexical only | `CVE-2021-44228` | 3/3 |
| Hybrid, no prefilter | `CVE-2021-44228` | 2/3 |
| **Hybrid + prefilter** | `CVE-2021-44228` | **3/3**, 14.5ms |

So retrieval is three mechanisms:

1. **Lexical** — Postgres `tsvector` + `ts_rank_cd`. Exact identifiers and
   version strings. *(Cover-density ranking, not BM25 — it lacks BM25's
   length saturation. Immaterial for rare tokens, which match or don't.)*
2. **Dense** — `bge-small-en-v1.5`, 384-d, local. Paraphrase and intent, where
   lexical finds nothing. Measured **1,162 chunks/sec on MPS** vs 545 on CPU.
3. **Metadata prefilter** — if the query names a CVE, restrict *before*
   ranking. Makes a wrong-CVE result structurally impossible, not merely
   unlikely.

**Fused with Reciprocal Rank Fusion:** `score = Σ 1/(60 + rank)`. **Rank-based,
not score-based**, because `ts_rank_cd` is unbounded and cosine is 0–1 —
adding them is meaningless and normalising needs assumptions that break as the
corpus grows. Ranks are always comparable. And agreement between independent
retrievers is itself signal: the prefiltered query scored 0.033 vs 0.026
precisely because both branches ranked the same chunks highly.

**Chunking is field-based, not a recursive text split.** The most valuable
sentence in an advisory names the fixed version; a split that separates it
from its package yields a chunk that retrieves but cannot be acted on. Every
chunk repeats the CVE ID so it stands alone and the lexical index sees the
identifier.

**Two vector stores behind one `typing.Protocol`** (structural typing — no
base class, no inheritance). The honest benchmark result:

| backend | filtered | recall@8 | p50 |
|---|---|---|---|
| pgvector | yes | 1.000 | 0.96ms |
| qdrant | yes | 1.000 | 2.50ms |

**Indistinguishable on quality.** Both return results identical to exact
brute-force nearest neighbour, because 2,237 vectors is far too few for HNSW's
approximation to approximate anything — Postgres doesn't even *use* the index,
and it's right not to (scanning 2,237 vectors costs 2.4ms; the index saves
0.3ms). pgvector is ~2× faster on the filtered path this system actually uses,
where a CVE filter selects ~3 chunks and brute force beats graph traversal.
**pgvector is the default; Qdrant stays behind the protocol** for when the
corpus justifies it (~100k+ vectors).

#### 5b. The agent

LangGraph, as an **explicit state machine** rather than a `while` loop over
tool calls:

```
check_cache ─hit─────────────────────────────────▶ END   (0 LLM calls)
     │miss
  retrieve ──▶ draft_plan ──▶ ground_check ─pass─▶ persist
     ▲                             │fail
     └──── widen_context ◀─────────┤  (bounded; only while context grows)
                                   └─give_up────▶ mark_ungrounded
```

**Why a graph.** Four things a bare loop can't give: a place to **stop** for
approval; **checkpointed** state so a crash doesn't re-pay for completed LLM
calls; **different recovery per failure kind**; and an answer to "what can this
system do?" that comes from *reading* rather than running. For a system whose
output is a security ticket, that last one is decisive.

**`check_cache` is a node, not an `if`.** It's the biggest cost lever in the
system, so it's visible in the graph:

> **1,705 fix actions share only 108 unique
> `(cve, package, os_family, fixed_version)` plan keys — an 88% cache hit
> rate.** 103,166 findings cost **108 LLM calls**.

**The early exit.** The CVE prefilter caps retrieval at the chunks that exist,
so widening often returns *identical* context and the retry buys the identical
failure at full price. The graph gives up when context stops growing — 3 model
calls down to 2.

#### 5c. The grounding gate — the most important component

**It is a regex, not a prompt.** "Only use the provided context" is a
*request*; models mostly comply. A verbatim check that every CVE ID and
version string appears in a retrieved chunk is a **guarantee**.

It proved itself on the first live call: `gpt-oss-120b` wrote
**`CVE-2021-4428`** — a digit dropped from `CVE-2021-44228`. Rejected.

> **A weaker model makes this check more valuable, not less.** That is what
> makes running on a free tier defensible.

Plans that fail are stored with `grounding_passed = false` and **never reach a
ticket** — kept rather than discarded, because a cluster of them for one
package means the corpus is missing a document, which is a *retrieval* bug.

**Four bugs this gate went through, all in the false-positive direction** —
which is the worse one, because *a gate that blocks good plans is a gate
somebody switches off*:

| Bug | Symptom |
|---|---|
| Trailing period | `"upgrade to 2.17.1."` → version `2.17.1.`, rejected correct plans |
| File extensions | `log4j-core-2.15.0.jar` → version `2.15.0.jar` |
| IP addresses | `127.0.0.1` matches four numeric segments |
| Provenance ≠ selection | asked for curl `deb11u14`, got `deb11u10` — real, but the fix for a *different* CVE |

That last fix was initially **unsatisfiable** and failed 87% of plans:
correlation targets the highest version across a package, but the CVE driving
that maximum sits in a *different band*, so the target appears in no retrieved
chunk — naming it failed as ungrounded, naming the advisory's version failed as
missing-target. The resolution: the target was never corpus text, it is
**scanner data**, so it's injected as an explicit provenanced context fact.

---

### Stage 6 — Ticket

**What happens.** Fix actions render into tickets and file to GitHub, Jira, or
an in-memory sink.

**Safety, because this is the one outward-facing stage.** `dry_run` defaults to
`True` everywhere, the CLI needs explicit `--execute`, and a non-memory sink
additionally prompts. Creating 1,705 issues in someone's tracker is not
something a flag typo should be able to do.

**Idempotency is owned locally.** `tickets.idempotency_key` is `UNIQUE` in
Postgres, so "already filed?" is a primary-key lookup — cheaper than a remote
search, correct when the tracker is unreachable, and immune to two runs racing
a search API into duplicates. Verified: a re-run with a *freshly constructed*
sink (empty internal map) still **updated** its tickets, because the external
ID comes from the database.

**The body is written for whoever gets assigned it** and hasn't read the
advisory: the action first, the deadline, the evidence for the priority (KEV
membership, EPSS, internet exposure, prod count), and a per-CVE minimum table
explaining why the target exceeds what any single CVE demands. **Only grounded
plans are attached.**

---

## Evaluation

The grounding gate catches **fabrication**. It cannot catch **vagueness** —
"apply vendor updates" invents nothing, is true, and is useless. That is what
the eval measures, in two tiers:

**Deterministic rubric (free, runs on everything).** Cannot flatter the model:
`grounded`, `names_target`, `has_commands`, `commands_match_os`,
`has_rollback`, `no_placeholders`, `not_vague`.

**LLM-judged (opt-in, sampled).** DeepEval faithfulness + a custom
actionability G-Eval, judged through the same OpenAI-compatible endpoint. A
sample, not a gate — on a free tier the judge is a *sibling* of the model under
test, so shared failure modes inflate scores.

First measured run found exactly the gap predicted:

```
grounded          100%     ← the gate works
not_vague         100%
no_placeholders    57%     ← the real defect
actionable         50%
```

Half the plans contained `/path/to/...` — grounded, version-correct, and not
runnable by anyone. That drove a prompt change, which is precisely what an eval
harness is *for*.

---

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Database | **Postgres 18** | rows + full-text + vectors in one transactional store |
| Vectors | **pgvector 0.8.6** (HNSW) | lives with the data; one `JOIN`, no ID reconciliation |
| Vectors (alt) | **Qdrant 1.19** | filtered-HNSW comparison, behind a `Protocol` |
| Migrations | **Alembic**, hand-written SQL | schema under version control; no ORM in the query plans that matter |
| Embeddings | **bge-small-en-v1.5** local | free, no rate limit, 1,162 chunks/s on MPS |
| Scanner | **Trivy** | no daemon, huge DB, SBOM-native |
| Agent | **LangGraph** | explicit state machine, checkpointing, interrupts |
| LLM | **any OpenAI-compatible** (Groq/Gemini/Cerebras/Ollama) or **Anthropic** | provider is config, not architecture |
| Eval | **DeepEval** + a deterministic rubric | the rubric carries the weight |
| API | **FastAPI** (sync handlers) | one DB stack; threadpool is sufficient here |
| CLI | **Typer** + **Rich** | every stage runnable and inspectable |
| Extensions | `citext`, `pg_trgm`, `btree_gin`, `pgcrypto`, `unaccent`, `pg_stat_statements` | each earns its place |

**No Docker.** Postgres via brew, Qdrant as a native binary, Trivy daemonless.

---

## Measured performance

| Stage | Scale | Time |
|---|---|---|
| Trivy scan | 500 hosts | 6.2s (84 hosts/s) |
| Load findings | 103,166 rows | 2.2s |
| KEV + EPSS | 382k feed rows | ~4s |
| NVD enrichment | 690 CVEs | 423s (rate-limit bound) |
| Risk scoring | 103,166 findings | 0.8s (126k rows/s) |
| Corpus build | 2,237 chunks | 17s |
| Triage query | 20 of 103,166 | **5.2ms** |
| Hybrid search | 2,237 chunks | 14.5ms |
| Correlation | → 1,705 actions | ~2s |

**The read path needed fixing.** `v_current_risk` originally used
`DISTINCT ON` over the append-only history: to return 20 rows it read all
119k assessments, sorted, deduped to 100,937 and discarded 99.6% —
**140ms with 16,336 blocks spilled to disk**, and O(history) forever. An
`is_current` flag with a **partial unique index** made it an index scan:
**5.2ms, 206 buffers, no spill** — and "exactly one current assessment per
finding" became an invariant the *database* enforces rather than a convention
the application remembers.

---

## Scaling and what's deliberately absent

**Pull-based, idempotent stages** mean any stage can become a queue worker by
wrapping it — no rewrite. I did **not** build the queue, because the whole
pipeline runs in ~11 seconds on a laptop and distributed infrastructure costs
real debugging pain the moment it exists. The point where it earns its place is
the agent stage: LLM calls take seconds, fail intermittently, need retries, and
must not sit in a request path.

**Known limits, stated honestly:**

- Scoring is O(fleet), not O(changes) — it reads all 103k findings to discover
  83k didn't change. Fine at 0.8s; needs a `scored_at` watermark at ~10M.
- `MemorySaver` checkpoints survive interrupts within a process, not restarts.
  LangGraph's Postgres checkpointer would, but it creates its own tables via
  `.setup()`, which breaks the guarantee that Alembic is the only thing
  creating schema.
- Free-tier LLM terms generally permit training on submitted data. What this
  sends is hostnames, package versions and unpatched CVEs — fine for a
  synthetic fleet, unacceptable for real asset inventory.
- Plan quality on a free model is middling. The gate guarantees no invented
  versions; it does not guarantee specificity. Routing critical work to a
  stronger model is the production answer.

---

## The three things worth remembering

1. **The model proposes; deterministic code disposes.** Risk scores and due
   dates are policy-computed and reproducible. The LLM writes prose, and a
   regex verifies every identifier in it.
2. **Hybrid retrieval is not an optimisation here, it is a correctness
   requirement.** Pure vector search returned vim CVEs for a Log4Shell query.
3. **The cache is the architecture.** 103,166 findings → 1,705 actions → 108
   LLM calls. Everything expensive scales with the third number.
