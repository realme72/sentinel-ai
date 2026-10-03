"""Run the planner across fix actions, routing model by risk band.

Routing is the main cost lever once the plan cache is in place: a critical,
internet-facing RCE deserves the better model, and a routine `curl` bump on
eight dev boxes does not.

One representative CVE is planned per fix action -- the highest-risk one.
The plan's subject is the *upgrade* ("move package X to version Y"), which is
identical whichever of the action's CVEs motivated it, and the plan cache key
(cve, package, os_family, fixed_version) then dedupes naturally across teams
that share the same upgrade. Dispatch finds it again by matching any CVE in
the action.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import structlog

from sentinel.agents.correlate import FixAction, correlate
from sentinel.agents.llm import PlannerLLM
from sentinel.agents.openai_compat import DailyQuotaExhausted
from sentinel.agents.planner import plan_for
from sentinel.config import get_settings

log = structlog.get_logger()

# Bands that get the stronger model.
HIGH_EFFORT_BANDS = frozenset({"critical", "high"})


@dataclass
class PlannerRouter:
    """Chooses a planner per risk band, constructing each at most once."""

    provider: str = "openai"
    _cache: dict[str, PlannerLLM] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._cache = {}

    def _build(self, model: str) -> PlannerLLM:
        if model in self._cache:
            return self._cache[model]
        if self.provider == "anthropic":
            from sentinel.agents.llm import AnthropicPlanner
            planner: PlannerLLM = AnthropicPlanner(model=model)
        else:
            from sentinel.agents.openai_compat import OpenAICompatPlanner
            planner = OpenAICompatPlanner(model=model)
        self._cache[model] = planner
        return planner

    def for_band(self, band: str) -> PlannerLLM:
        s = get_settings()
        if self.provider == "anthropic":
            model = s.planner_model if band in HIGH_EFFORT_BANDS else s.bulk_model
        else:
            model = s.openai_model if band in HIGH_EFFORT_BANDS else s.openai_bulk_model
        return self._build(model)

    def stats(self) -> dict:
        return {
            model: getattr(p, "stats", {})
            for model, p in self._cache.items()
        }


def _representative(action: FixAction) -> str:
    """Highest-signal CVE in the action: KEV first, then lowest id for
    determinism so repeated runs hit the same cache entry."""
    if action.kev_cve_ids:
        return sorted(action.kev_cve_ids)[0]
    return sorted(action.cve_ids)[0]


def plan_actions(
    actions: list[FixAction],
    *,
    provider: str | None = None,
    limit: int | None = None,
) -> dict:
    router = PlannerRouter(provider=provider or get_settings().planner_provider)
    if limit:
        actions = actions[:limit]

    t0 = time.perf_counter()
    counts = {"grounded": 0, "cached": 0, "ungrounded": 0, "no_context": 0, "error": 0}
    failures: list[dict] = []

    slowest: list[tuple[float, str]] = []

    for i, action in enumerate(actions, 1):
        cve = _representative(action)
        llm = router.for_band(action.risk_band)
        t_action = time.perf_counter()
        calls_before = getattr(llm, "stats", {}).get("calls", 0)
        try:
            out = plan_for(
                llm,
                cve_id=cve,
                package_name=action.package_name,
                os_family=action.os_family,
                fixed_version=action.fixed_version,
                installed_version=action.installed_version,
                thread_id=f"{action.idempotency_key}",
            )
            status = out.get("status", "error")
            counts[status] = counts.get(status, 0) + 1
            if status == "ungrounded":
                failures.append({
                    "cve": cve, "package": action.package_name,
                    "rejected": out.get("grounding", {}).get("ungrounded_versions")
                               or out.get("grounding", {}).get("ungrounded_cves"),
                })
        except DailyQuotaExhausted as exc:
            # Nothing further can succeed today; grinding on would cost ~60s
            # of honoured retry-after per remaining action for nothing.
            log.error("plan.daily_quota_exhausted", detail=str(exc)[:240],
                      completed=i - 1, remaining=len(actions) - i + 1)
            counts["quota_exhausted"] = len(actions) - i + 1
            failures.append({"stopped_at": i, "reason": str(exc)[:200]})
            break
        except Exception as exc:  # noqa: BLE001 - one bad action must not stop the run
            counts["error"] += 1
            failures.append({"cve": cve, "package": action.package_name,
                             "error": str(exc)[:160]})
            log.warning("plan.failed", cve=cve, package=action.package_name,
                        error=str(exc)[:200])

        took = time.perf_counter() - t_action
        calls = getattr(llm, "stats", {}).get("calls", 0) - calls_before
        slowest.append((took, f"{cve}/{action.package_name}"))
        # Anything slow enough to matter gets named as it happens, rather than
        # only in a summary nobody sees until the run ends.
        if took > 20:
            log.info("plan.slow_action", cve=cve, package=action.package_name,
                     seconds=round(took, 1), llm_calls=calls,
                     band=action.risk_band)

        if i % 5 == 0 or i == len(actions):
            log.info("plan.progress", done=i, total=len(actions),
                     elapsed_s=round(time.perf_counter() - t0), **counts)

    elapsed = time.perf_counter() - t0
    planned = counts["grounded"] + counts["ungrounded"]
    return {
        "actions": len(actions),
        **counts,
        "grounded_rate": round(counts["grounded"] / max(planned, 1), 3),
        "seconds": round(elapsed, 1),
        "per_action_s": round(elapsed / max(len(actions), 1), 2),
        "models": router.stats(),
        "slowest_actions": [
            {"seconds": round(s, 1), "action": name}
            for s, name in sorted(slowest, reverse=True)[:5]
        ],
        "failures": failures[:15],
    }


def plan_band(band: str, **kw) -> dict:
    return plan_actions(correlate(bands=[band]), **kw)
