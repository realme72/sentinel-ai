"""Every path through the planner graph, with a scripted model.

The graph's branches -- cache hit, grounding retry, give-up, empty context --
are the parts most likely to be wrong and the parts a live model would make
expensive and non-deterministic to exercise. So they are tested against a
scripted planner with the database and retrieval patched out: this file
verifies control flow, not SQL and not model quality.
"""

from dataclasses import dataclass
from datetime import date

import pytest

from sentinel.agents import planner as P
from sentinel.agents.llm import PlanDraft, ScriptedPlanner

CVE = "CVE-2021-44228"
PKG = "org.apache.logging.log4j:log4j-core"

CONTEXT = [
    "CVE-2021-44228 (CRITICAL, CVSS 10.0). Remediation for package "
    "org.apache.logging.log4j:log4j-core. Affected versions observed: 2.14.1. "
    "Fixed in version 2.17.1.",
]


@dataclass
class FakeHit:
    chunk_id: int
    content: str


def draft(version: str) -> PlanDraft:
    return PlanDraft(
        summary=f"{CVE} allows remote code execution.",
        steps=[f"Upgrade {PKG} to {version}."],
        commands=[f"mvn versions:use-dep-version -DdepVersion={version}"],
        rollback="Redeploy the previous artifact.",
    )


GOOD = draft("2.17.1")        # 2.17.1 is in CONTEXT
FABRICATED = draft("2.21.9")  # 2.21.9 is not


@pytest.fixture
def wired(monkeypatch):
    """Patch out the database and retrieval; record what the graph did."""
    recorded = {"persisted": [], "searches": []}

    def fake_query_one(sql, params=None):
        if "INSERT INTO remediation_plans" in sql:
            recorded["persisted"].append(params)
            return {"id": 4242}
        return None                      # cache miss by default

    def fake_search(q, **kw):
        recorded["searches"].append({"query": q, "k": kw.get("k")})
        n = kw.get("k", 8)
        return {"hits": [FakeHit(i, CONTEXT[0]) for i in range(1, min(n, 3) + 1)]}

    monkeypatch.setattr(P, "query_one", fake_query_one)
    monkeypatch.setattr(P, "search", fake_search)
    return recorded


def run(llm, **over):
    return P.plan_for(llm, cve_id=CVE, package_name=PKG, os_family="debian",
                      fixed_version="2.17.1", **over)


# --- the happy path --------------------------------------------------------


def test_grounded_plan_persists_and_stops(wired):
    llm = ScriptedPlanner({CVE: [GOOD]})
    out = run(llm)
    assert out["status"] == "grounded"
    assert out["plan_id"] == 4242
    assert out["grounding"]["passed"] is True
    assert len(llm.calls) == 1, "one model call for a clean plan"
    assert len(wired["persisted"]) == 1


# --- the cache, which is the system's biggest cost lever -------------------


def test_cache_hit_skips_retrieval_and_the_model(monkeypatch):
    """100,937 findings collapse to 740 fix actions. A hit must cost nothing."""
    def cached(sql, params=None):
        if "SELECT id, plan_markdown" in sql:
            return {"id": 7, "plan_markdown": "cached plan",
                    "grounding_passed": True, "grounding_report": {"passed": True},
                    "context_chunk_ids": [1, 2]}
        raise AssertionError("nothing else should touch the database")

    searched = []
    monkeypatch.setattr(P, "query_one", cached)
    monkeypatch.setattr(P, "search", lambda *a, **k: searched.append(1))

    llm = ScriptedPlanner({})            # raises if called
    out = run(llm)
    assert out["status"] == "cached"
    assert out["plan_id"] == 7
    assert llm.calls == [], "cache hit must not call the model"
    assert searched == [], "cache hit must not retrieve"


def test_ungrounded_cached_plan_is_retried_not_served(monkeypatch, wired):
    """A stored plan that failed grounding is a known-bad answer, not an
    answer. Serving it would make one bad generation permanent."""
    def stale(sql, params=None):
        if "SELECT id, plan_markdown" in sql:
            return {"id": 9, "plan_markdown": "bad", "grounding_passed": False,
                    "grounding_report": {"passed": False}, "context_chunk_ids": []}
        if "INSERT INTO remediation_plans" in sql:
            return {"id": 10}
        return None

    monkeypatch.setattr(P, "query_one", stale)
    llm = ScriptedPlanner({CVE: [GOOD]})
    out = run(llm)
    assert out["status"] == "grounded"
    assert len(llm.calls) == 1


# --- grounding failure and recovery ---------------------------------------


def test_fabricated_version_triggers_a_retry_with_more_context(wired):
    llm = ScriptedPlanner({CVE: [FABRICATED, GOOD]})
    out = run(llm)
    assert out["status"] == "grounded"
    assert len(llm.calls) == 2, "one failed attempt, then one that worked"
    # The retry must actually widen the window, not just re-roll the dice.
    assert wired["searches"][1]["k"] > wired["searches"][0]["k"]


def test_repeated_fabrication_gives_up_and_flags_the_plan(wired):
    """Bounded retries. The plan is stored so the failure is inspectable --
    a cluster of these for one package means the corpus is missing a
    document, which is a retrieval bug, not a model one.

    The `wired` fixture caps retrieval at three chunks regardless of k, so the
    early exit fires on the second attempt rather than burning the full
    budget. See test_retry_stops_when_widening_cannot_add_context.
    """
    llm = ScriptedPlanner({CVE: [FABRICATED]})
    out = run(llm)
    assert out["status"] == "ungrounded"
    assert 2 <= len(llm.calls) <= P.MAX_ATTEMPTS
    assert out["grounding"]["passed"] is False
    assert "2.21.9" in out["grounding"]["ungrounded_versions"]
    # Stored, but marked: _persist is called with passed=False.
    assert wired["persisted"], "ungrounded plans are kept for inspection"


def test_an_ungrounded_plan_never_claims_success(wired):
    llm = ScriptedPlanner({CVE: [FABRICATED]})
    out = run(llm)
    assert out["status"] != "grounded"
    assert out["plan_markdown"], "the text is kept..."
    assert out["grounding"]["passed"] is False, "...but never marked grounded"


# --- missing context -------------------------------------------------------


def test_empty_retrieval_does_not_call_the_model(monkeypatch):
    """No context is exactly when a model is most likely to invent, so the
    graph refuses rather than asking and hoping the gate catches it."""
    monkeypatch.setattr(P, "query_one", lambda *a, **k: None)
    monkeypatch.setattr(P, "search", lambda *a, **k: {"hits": []})
    llm = ScriptedPlanner({})
    out = run(llm)
    assert out["status"] == "no_context"
    assert out["plan_id"] is None
    assert llm.calls == []


# --- graph shape -----------------------------------------------------------


def test_graph_has_no_path_from_grounding_failure_to_persist():
    """The structural guarantee: an ungrounded plan cannot reach the node that
    marks plans as usable."""
    g = P.build_graph(ScriptedPlanner({})).get_graph()
    edges = {(e.source, e.target, getattr(e, "data", None)) for e in g.edges}
    assert ("ground_check", "persist", "pass") in edges
    assert ("ground_check", "mark_ungrounded", "give_up") in edges
    assert not any(src == "mark_ungrounded" and dst == "persist"
                   for src, dst, _ in edges)


# --- not paying for identical retries --------------------------------------


def test_retry_stops_when_widening_cannot_add_context(monkeypatch):
    """The CVE prefilter caps results at the chunks that exist for that CVE.
    Once widening returns the same context, another attempt sees identical
    input and fails identically -- a wasted model call, not a second chance."""
    persisted = []

    def fake_query_one(sql, params=None):
        if "INSERT INTO remediation_plans" in sql:
            persisted.append(params)
            return {"id": 1}
        return None

    # Always three chunks, no matter what k is asked for.
    monkeypatch.setattr(P, "query_one", fake_query_one)
    monkeypatch.setattr(P, "search", lambda q, **kw: {
        "hits": [FakeHit(i, CONTEXT[0]) for i in range(1, 4)]
    })

    llm = ScriptedPlanner({CVE: [FABRICATED]})
    out = run(llm)
    assert out["status"] == "ungrounded"
    # Two calls, not MAX_ATTEMPTS: the first fails, the second sees the context
    # did not grow and gives up.
    assert len(llm.calls) == 2, f"expected 2 model calls, got {len(llm.calls)}"


def test_retry_continues_while_context_is_still_growing(monkeypatch):
    """The early exit must not fire when widening is actually working."""
    sizes = iter([2, 4, 6])

    def fake_query_one(sql, params=None):
        return {"id": 1} if "INSERT INTO" in sql else None

    monkeypatch.setattr(P, "query_one", fake_query_one)
    monkeypatch.setattr(P, "search", lambda q, **kw: {
        "hits": [FakeHit(i, CONTEXT[0]) for i in range(next(sizes, 6))]
    })

    llm = ScriptedPlanner({CVE: [FABRICATED]})
    out = run(llm)
    assert out["status"] == "ungrounded"
    assert len(llm.calls) == P.MAX_ATTEMPTS, "growing context earns the full budget"


# --- the target must be reachable ------------------------------------------


def test_retrieve_supplies_the_scanner_target_as_context(monkeypatch):
    """Correlation sets the target to the highest version required across the
    whole package, and the CVE driving that maximum is often in a different
    risk band than the one being planned. So the target is frequently absent
    from the retrieved advisories.

    Without injecting it, the grounding check is unsatisfiable: naming the
    target fails as ungrounded, and naming the advisory's version fails as
    missing-target. Every plan fails forever.
    """
    monkeypatch.setattr(P, "search", lambda q, **kw: {
        "hits": [FakeHit(1, "CVE-2021-44228 ... Fixed in version 2.15.0.")]
    })
    out = P.retrieve({"cve_id": CVE, "package_name": PKG, "os_family": "debian",
                      "fixed_version": "2.25.4", "retrieval_k": 8})
    joined = " ".join(out["context_chunks"])
    assert "2.25.4" in joined, "the target must be present in context"
    assert "2.15.0" in joined, "the advisory must still be present"
    assert "highest requirement wins" in joined


def test_no_target_means_no_injected_fact(monkeypatch):
    """When the scanner published no fix there is nothing to assert."""
    monkeypatch.setattr(P, "search", lambda q, **kw: {"hits": [FakeHit(1, "advisory")]})
    out = P.retrieve({"cve_id": CVE, "package_name": PKG, "os_family": "debian",
                      "fixed_version": None, "retrieval_k": 8})
    assert out["context_chunks"] == ["advisory"]


def test_target_version_is_satisfiable_end_to_end(wired):
    """A plan naming the correlator's target must now pass both halves of the
    gate: present in context (injected) and naming the required version."""
    target_draft = PlanDraft(
        summary="Upgrade to the scanner target.",
        steps=["Upgrade log4j-core to 2.25.4."],
        commands=["mvn versions:use-dep-version -DdepVersion=2.25.4"],
        rollback="Redeploy previous.",
    )
    llm = ScriptedPlanner({CVE: [target_draft]})
    out = P.plan_for(llm, cve_id=CVE, package_name=PKG, os_family="debian",
                     fixed_version="2.25.4")
    assert out["status"] == "grounded", out["grounding"]
    assert out["grounding"]["missing_required"] == []


def test_injected_target_does_not_defeat_the_no_context_guard(monkeypatch):
    """The target fact is always present, so the guard must key on retrieved
    chunks. Otherwise "no advisory found" silently became "plan anyway"."""
    monkeypatch.setattr(P, "query_one", lambda *a, **k: None)
    monkeypatch.setattr(P, "search", lambda *a, **k: {"hits": []})
    llm = ScriptedPlanner({})
    out = P.plan_for(llm, cve_id=CVE, package_name=PKG, os_family="debian",
                     fixed_version="2.25.4")
    assert out["status"] == "no_context"
    assert llm.calls == []


# --- provider daily quota --------------------------------------------------


def test_run_stops_on_daily_quota_instead_of_grinding(monkeypatch):
    """Groq's free tier caps tokens per DAY (200,000), a limit that appears in
    no response header -- only in the 429 body. It cannot be waited out within
    a run, and each retry honours a ~60s retry-after, so continuing costs
    ~3 minutes per remaining action for nothing."""
    from sentinel.agents import run as R
    from sentinel.agents.openai_compat import DailyQuotaExhausted

    calls = {"n": 0}

    def exhausted(*a, **k):
        calls["n"] += 1
        raise DailyQuotaExhausted(
            "Rate limit reached ... on tokens per day (TPD): Limit 200000, "
            "Used 199000, Requested 1428"
        )

    monkeypatch.setattr(R, "plan_for", exhausted)
    # The router builds a real planner before plan_for is reached, and that
    # constructor requires an API key -- which tests and CI deliberately lack.
    monkeypatch.setattr(R.PlannerRouter, "for_band",
                        lambda self, band: ScriptedPlanner({}))

    from sentinel.agents.correlate import FixAction

    def act(i):
        return FixAction(
            owner_team="infra", owner_email="i@e.com", package_name=f"pkg{i}",
            fixed_version="1.2.3", risk_band="critical", os_family="debian",
            due_date=date(2026, 10, 3), max_risk_score=90.0, asset_count=1,
            internet_facing_count=0, prod_count=1, cve_ids=["CVE-2021-44228"],
            kev_cve_ids=[], finding_ids=[i], hostnames=["h"], environments=["prod"],
        )

    out = R.plan_actions([act(i) for i in range(10)])
    assert calls["n"] == 1, "must stop after the first quota error, not retry 10x"
    assert out["quota_exhausted"] == 10
    assert "tokens per day" in out["failures"][0]["reason"]
