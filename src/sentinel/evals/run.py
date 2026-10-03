"""Evaluate the plans in the cache.

Runs the free deterministic rubric over everything, and optionally a sampled
LLM-judged pass. Reads plans already in `remediation_plans` rather than
generating fresh ones, so an eval costs nothing unless `--judge` is passed --
which matters when the judge shares a daily token budget with the planner.
"""

from __future__ import annotations

import time

import structlog

from sentinel.db.session import query
from sentinel.evals.metrics import PlanScore, aggregate, score_plan

log = structlog.get_logger()

_PLANS_SQL = """
SELECT p.id, p.cve_id, p.package_name, p.os_family, p.fixed_version,
       p.plan_markdown, p.grounding_passed, p.context_chunk_ids, p.model,
       (SELECT array_agg(c.content ORDER BY c.id)
        FROM corpus_chunks c WHERE c.id = ANY(p.context_chunk_ids)) AS context
FROM remediation_plans p
WHERE p.plan_markdown <> ''
ORDER BY p.created_at DESC
"""


def load_plans(limit: int | None = None) -> list[dict]:
    rows = query(_PLANS_SQL + (f" LIMIT {int(limit)}" if limit else ""))
    return rows


def run_deterministic(limit: int | None = None) -> dict:
    rows = load_plans(limit)
    scores: list[PlanScore] = []
    worst: list[tuple[float, str, list[str]]] = []

    for r in rows:
        s = score_plan(
            r["plan_markdown"],
            grounded=r["grounding_passed"],
            target_version=r["fixed_version"],
            os_family=r["os_family"],
        )
        scores.append(s)
        if not s.actionable:
            worst.append((s.score, f"{r['cve_id']}/{r['package_name']}", s.failures()))

    out = aggregate(scores)
    out["not_actionable"] = [
        {"score": sc, "plan": name, "failed": fails}
        for sc, name, fails in sorted(worst)[:10]
    ]
    log.info("eval.deterministic", **{k: v for k, v in out.items()
                                     if k != "not_actionable"})
    return out


def run_judged(sample: int = 5, call_budget: int = 40) -> dict:
    """Sampled LLM-judged pass: faithfulness plus an actionability rubric.

    A sample, not a gate. On a free tier the judge is a sibling of the model
    under test, so shared failure modes inflate the score -- and every call
    spends budget the planner needs.
    """
    import warnings
    warnings.filterwarnings("ignore")
    from deepeval.metrics import FaithfulnessMetric, GEval
    from deepeval.test_case import LLMTestCase, SingleTurnParams

    from sentinel.evals.judge import GroqJudge

    rows = [r for r in load_plans() if r["context"]][:sample]
    if not rows:
        return {"judged": 0, "reason": "no plans with retrieved context"}

    judge = GroqJudge(call_budget=call_budget)
    faithfulness = FaithfulnessMetric(threshold=0.7, model=judge,
                                      async_mode=False, include_reason=True)
    actionability = GEval(
        name="Actionability",
        model=judge,
        async_mode=False,
        evaluation_params=[SingleTurnParams.INPUT, SingleTurnParams.ACTUAL_OUTPUT],
        criteria=(
            "Could an infrastructure engineer who has not read the advisory "
            "execute this plan without further research? It must name the exact "
            "package and target version, give runnable commands for the stated "
            "OS, say what to restart, and contain no placeholders such as "
            "/path/to/. Generic advice like 'apply vendor updates' scores lowest."
        ),
        threshold=0.7,
    )

    results, t0 = [], time.perf_counter()
    for r in rows:
        tc = LLMTestCase(
            input=(f"Write a remediation plan for {r['cve_id']} affecting "
                   f"{r['package_name']} on {r['os_family']}. "
                   f"Target version: {r['fixed_version']}."),
            actual_output=r["plan_markdown"],
            retrieval_context=list(r["context"]),
        )
        row = {"plan": f"{r['cve_id']}/{r['package_name']}"}
        for metric in (faithfulness, actionability):
            try:
                metric.measure(tc)
                row[metric.__class__.__name__ if metric is faithfulness
                    else "Actionability"] = round(float(metric.score or 0), 3)
                row[f"{'faith' if metric is faithfulness else 'action'}_reason"] = (
                    (metric.reason or "")[:140])
            except Exception as exc:  # noqa: BLE001 - a judge failure is data
                row["error"] = str(exc)[:140]
                break
        results.append(row)

    scored = [r for r in results if "FaithfulnessMetric" in r]
    return {
        "judged": len(results),
        "mean_faithfulness": round(
            sum(r["FaithfulnessMetric"] for r in scored) / max(len(scored), 1), 3),
        "mean_actionability": round(
            sum(r.get("Actionability", 0) for r in scored) / max(len(scored), 1), 3),
        "seconds": round(time.perf_counter() - t0, 1),
        "judge": judge.usage(),
        "results": results,
    }
