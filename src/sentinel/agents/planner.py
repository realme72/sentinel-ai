"""The remediation planner, as an explicit LangGraph state machine.

Why a graph rather than a `while` loop over tool calls:

* **It can stop.** Creating a ticket is outward-facing, so the graph is
  compiled with an interrupt point and a human resumes it.
* **A crash is not a refund.** State is checkpointed after every node, so
  resuming re-enters at the failed node with earlier work intact instead of
  re-paying for LLM calls already made.
* **Failures differ.** Grounding failure retries with more context; no
  published fix takes a different path entirely; both are visible edges rather
  than branches buried inside one try/except.
* **It is auditable.** "What can this system do?" is answered by reading the
  graph, which matters when the output is a security ticket.

    check_cache ─hit──────────────────────────────► END
         │miss
         ▼
      retrieve ──► draft_plan ──► ground_check ─pass─► persist ──► END
         ▲                             │fail
         │                             ├─ attempts < MAX ─► widen_context ─┐
         └─────────────────────────────┘                                   │
                                       └─ attempts = MAX ─► mark_ungrounded┘

Checkpointing note: MemorySaver gives interrupt/resume within a process.
LangGraph's Postgres checkpointer would survive a restart, but it creates its
own tables through `.setup()`, which would defeat the guarantee that Alembic
migrations are the only thing that creates schema (see `make drift`). Bringing
those tables under a migration is the prerequisite for switching.
"""

from __future__ import annotations

import json
import time
from typing import Annotated, TypedDict

import structlog
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from sentinel.agents.grounding import check_grounding
from sentinel.agents.llm import PlanDraft, PlannerLLM
from sentinel.db.session import query_one
from sentinel.rag.hybrid import search

log = structlog.get_logger()

MAX_ATTEMPTS = 3
WIDEN_FACTOR = 2


def _keep_last(_old, new):
    return new


class PlanState(TypedDict, total=False):
    # --- inputs ---
    cve_id: str
    package_name: str
    os_family: str
    fixed_version: str | None
    # --- working ---
    retrieval_k: Annotated[int, _keep_last]
    attempts: Annotated[int, _keep_last]
    context_chunks: list[str]
    context_chunk_ids: list[int]
    context_grew: Annotated[bool, _keep_last]
    prev_context_size: Annotated[int, _keep_last]
    draft: dict | None
    plan_markdown: str
    grounding: dict
    # --- outputs ---
    status: str          # cached | grounded | ungrounded | no_context
    plan_id: int | None
    cached: bool
    timings: dict


# --------------------------------------------------------------------------
# nodes
# --------------------------------------------------------------------------

def check_cache(state: PlanState) -> dict:
    """The 140:1 lever.

    100,937 findings collapse to 740 unique (cve, package, os_family,
    fixed_version) tuples. A cache hit skips retrieval AND the model entirely,
    so this is the single biggest cost decision in the system -- which is why
    it is a visible node and not an `if` hidden inside another function.
    """
    row = query_one(
        """
        SELECT id, plan_markdown, grounding_passed, grounding_report, context_chunk_ids
        FROM remediation_plans
        WHERE cve_id = %s AND package_name = %s AND os_family = %s
          AND fixed_version IS NOT DISTINCT FROM %s
        """,
        (state["cve_id"], state["package_name"], state["os_family"],
         state.get("fixed_version")),
    )
    if row and row["grounding_passed"]:
        log.info("planner.cache_hit", cve=state["cve_id"], package=state["package_name"])
        return {
            "cached": True, "status": "cached", "plan_id": row["id"],
            "plan_markdown": row["plan_markdown"],
            "grounding": row["grounding_report"] or {},
            "context_chunk_ids": row["context_chunk_ids"] or [],
        }
    # A previously ungrounded plan is retried rather than served.
    return {"cached": False, "attempts": 0,
            "retrieval_k": state.get("retrieval_k", 8)}


def retrieve(state: PlanState) -> dict:
    """Hybrid search, scoped to this CVE.

    The prefilter is not optional here: B3 measured a pure vector search for
    'CVE-2021-44228' returning vim use-after-free CVEs, and a planner handed
    that context writes a confident ticket about the wrong software.
    """
    t0 = time.perf_counter()
    q = (f"{state['cve_id']} remediation for package {state['package_name']} "
         f"on {state['os_family']}")
    result = search(q, k=state.get("retrieval_k", 8), prefilter=True)
    hits = result["hits"]

    # The remediation target is scanner data, not corpus text, and it is not
    # derivable from the retrieved advisories: correlation sets it to the
    # highest version required across the whole package so one upgrade
    # satisfies every band, and the CVE that drives that maximum often sits in
    # a different band than the one being planned. Requiring the model to both
    # name 2.25.4 and find it in a chunk that says "Fixed in version 2.15.0"
    # is unsatisfiable -- it fails as ungrounded or as missing-target, forever.
    #
    # So the target is supplied as an explicit, provenanced context fact. It
    # comes from findings.fixed_version, which Trivy reported and which the
    # version-selection logic already validated as above the installed
    # version. That is at least as authoritative as any advisory sentence.
    chunks = [h.content for h in hits]
    target = state.get("fixed_version")
    if target:
        chunks.insert(0, (
            f"Scanner-reported remediation target: upgrade "
            f"{state['package_name']} to {target} on {state['os_family']}. "
            f"This is the version to install. It may be higher than the "
            f"version named in an individual advisory below, because one "
            f"upgrade must resolve every CVE affecting this package on this "
            f"host, and the highest requirement wins."
        ))
    # The CVE prefilter caps results at however many chunks exist for that CVE,
    # so raising retrieval_k often returns the SAME context. Retrying the model
    # on identical input just buys the identical failure at full price.
    previous = state.get("prev_context_size", -1)
    return {
        "context_chunks": chunks,
        "context_chunk_ids": [h.chunk_id for h in hits],
        "context_grew": len(hits) > previous,
        "prev_context_size": len(hits),
        "timings": {**state.get("timings", {}),
                    "retrieve_ms": round((time.perf_counter() - t0) * 1000, 1)},
    }


def draft_plan(state: PlanState, *, llm: PlannerLLM) -> dict:
    t0 = time.perf_counter()
    draft: PlanDraft = llm.draft(
        cve_id=state["cve_id"],
        package=state["package_name"],
        os_family=state["os_family"],
        fixed_version=state.get("fixed_version"),
        context=state.get("context_chunks", []),
    )
    return {
        "draft": draft.model_dump(),
        "plan_markdown": draft.to_markdown(),
        "attempts": state.get("attempts", 0) + 1,
        "timings": {**state.get("timings", {}),
                    "draft_ms": round((time.perf_counter() - t0) * 1000, 1)},
    }


def ground_check(state: PlanState) -> dict:
    """Deterministic. The model proposes, this disposes.

    The known target version is passed as required: a plan that quotes some
    other real version from the corpus satisfies provenance while still being
    the wrong instruction.
    """
    target = state.get("fixed_version")
    report = check_grounding(
        state.get("plan_markdown", ""),
        state.get("context_chunks", []),
        required_versions=[target] if target else None,
    )
    if not report.passed:
        log.warning("planner.ungrounded", cve=state["cve_id"],
                    attempt=state.get("attempts"), reason=report.reason())
    return {"grounding": report.as_dict()}


def widen_context(state: PlanState) -> dict:
    """Retry with a larger retrieval window.

    The usual cause of a grounding failure is the needed fact not being in the
    8 chunks shown, not the model inventing for its own sake -- so the response
    is more context, not a sterner prompt.
    """
    new_k = state.get("retrieval_k", 8) * WIDEN_FACTOR
    log.info("planner.widening", cve=state["cve_id"],
             attempt=state.get("attempts"), retrieval_k=new_k)
    return {"retrieval_k": new_k}


def _persist(state: PlanState, *, passed: bool) -> dict:
    draft = state.get("draft") or {}
    row = query_one(
        """
        INSERT INTO remediation_plans
            (cve_id, package_name, os_family, fixed_version, plan_markdown,
             commands, rollback, compensating_controls, requires_reboot,
             context_chunk_ids, model, grounding_passed, grounding_report)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (cve_id, package_name, os_family, fixed_version) DO UPDATE SET
            plan_markdown = EXCLUDED.plan_markdown,
            commands = EXCLUDED.commands,
            rollback = EXCLUDED.rollback,
            compensating_controls = EXCLUDED.compensating_controls,
            requires_reboot = EXCLUDED.requires_reboot,
            context_chunk_ids = EXCLUDED.context_chunk_ids,
            grounding_passed = EXCLUDED.grounding_passed,
            grounding_report = EXCLUDED.grounding_report,
            created_at = now()
        RETURNING id
        """,
        (state["cve_id"], state["package_name"], state["os_family"],
         state.get("fixed_version"), state.get("plan_markdown", ""),
         json.dumps(draft.get("commands", [])), draft.get("rollback"),
         draft.get("compensating_controls"), bool(draft.get("requires_reboot")),
         state.get("context_chunk_ids", []), state.get("model", "unknown"),
         passed, json.dumps(state.get("grounding", {}))),
    )
    return {"plan_id": row["id"] if row else None}


def persist(state: PlanState) -> dict:
    out = _persist(state, passed=True)
    return {**out, "status": "grounded"}


def mark_ungrounded(state: PlanState) -> dict:
    """Stored, but flagged. Never reaches a ticket.

    Kept rather than discarded so the failure is inspectable: a cluster of
    ungrounded plans for one package usually means the corpus is missing a
    document, which is a retrieval bug, not a model one.
    """
    log.error("planner.gave_up", cve=state["cve_id"],
              attempts=state.get("attempts"),
              reason=state.get("grounding", {}).get("ungrounded_versions"))
    out = _persist(state, passed=False)
    return {**out, "status": "ungrounded"}


# --------------------------------------------------------------------------
# edges
# --------------------------------------------------------------------------

def route_after_cache(state: PlanState) -> str:
    return "hit" if state.get("cached") else "miss"


def route_after_retrieve(state: PlanState) -> str:
    """Refuse to plan when nothing was actually retrieved.

    Keyed on `context_chunk_ids` -- the RETRIEVED chunks -- not on
    `context_chunks`, which now always holds at least the injected scanner
    target. A target alone is "install version X" with no advisory behind it:
    grounded, but too thin to be worth a model call, and no context is exactly
    when a model is most inclined to fill the gap itself.
    """
    return "empty" if not state.get("context_chunk_ids") else "ok"


def route_after_grounding(state: PlanState) -> str:
    if state.get("grounding", {}).get("passed"):
        return "pass"
    if state.get("attempts", 0) >= MAX_ATTEMPTS:
        return "give_up"
    # Retry only when the last widening actually produced more context. When
    # the prefilter has already returned every chunk that exists for this CVE,
    # another attempt sees identical input and fails identically -- so it is
    # a wasted model call, not a second chance.
    if not state.get("context_grew", True):
        log.info("planner.retry_pointless", cve=state["cve_id"],
                 attempts=state.get("attempts"),
                 context_chunks=state.get("prev_context_size"))
        return "give_up"
    return "retry"


def no_context(state: PlanState) -> dict:
    log.warning("planner.no_context", cve=state["cve_id"])
    return {"status": "no_context", "plan_id": None}


def build_graph(llm: PlannerLLM, *, checkpointer=None):
    g = StateGraph(PlanState)

    g.add_node("check_cache", check_cache)
    g.add_node("retrieve", retrieve)
    g.add_node("draft_plan", lambda s: draft_plan(s, llm=llm))
    g.add_node("ground_check", ground_check)
    g.add_node("widen_context", widen_context)
    g.add_node("persist", persist)
    g.add_node("mark_ungrounded", mark_ungrounded)
    g.add_node("no_context", no_context)

    g.add_edge(START, "check_cache")
    g.add_conditional_edges("check_cache", route_after_cache,
                            {"hit": END, "miss": "retrieve"})
    g.add_conditional_edges("retrieve", route_after_retrieve,
                            {"ok": "draft_plan", "empty": "no_context"})
    g.add_edge("draft_plan", "ground_check")
    g.add_conditional_edges("ground_check", route_after_grounding,
                            {"pass": "persist", "retry": "widen_context",
                             "give_up": "mark_ungrounded"})
    g.add_edge("widen_context", "retrieve")   # cycle: wider window, redraft
    g.add_edge("persist", END)
    g.add_edge("mark_ungrounded", END)
    g.add_edge("no_context", END)

    return g.compile(checkpointer=checkpointer or MemorySaver())


def plan_for(
    llm: PlannerLLM, *, cve_id: str, package_name: str, os_family: str,
    fixed_version: str | None = None, thread_id: str | None = None,
) -> dict:
    graph = build_graph(llm)
    config = {"configurable": {"thread_id": thread_id or f"{cve_id}:{package_name}"}}
    return graph.invoke(
        {
            "cve_id": cve_id, "package_name": package_name,
            "os_family": os_family, "fixed_version": fixed_version,
            "retrieval_k": 8, "attempts": 0, "model": getattr(llm, "model", "unknown"),
        },
        config,
    )
