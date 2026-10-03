"""Planner backed by any OpenAI-compatible chat endpoint.

One adapter covers Groq, Google AI Studio, Cerebras, Mistral and a local
Ollama, because they all speak the same `/chat/completions` shape. Only
`base_url`, `model` and the key differ.

It exists because the PlannerLLM Protocol made the provider a configuration
detail rather than an architectural one -- nothing in the graph, the grounding
gate or the plan cache changes.

Using a smaller model here is safe for a specific reason: the grounding gate
verifies mechanically that every CVE id and version string came from retrieved
context. On the very first Groq call, gpt-oss-120b wrote "CVE-2021-4428" --
a digit dropped from CVE-2021-44228 -- and the gate rejected it. A weaker
model makes that check more valuable, not less. What the gate does NOT catch
is vagueness, so plan *quality* still depends on the model.
"""

from __future__ import annotations

import contextlib
import time

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sentinel.agents.llm import SYSTEM_PROMPT, PlanDraft, _build_user_prompt
from sentinel.config import get_settings
from sentinel.util.ratelimit import SyncRollingWindowLimiter

log = structlog.get_logger()


class RetryableStatus(Exception):
    pass


class DailyQuotaExhausted(Exception):
    """The provider's per-day token budget is spent.

    Deliberately NOT retryable. Groq's free tier caps tokens per day (200,000
    on `on_demand`) and that limit appears in no response header -- only in
    the 429 body. Retrying costs ~60s of honoured retry-after per attempt and
    cannot succeed until the day rolls over, so a run that hits it should stop
    and say so rather than grind through every remaining action.
    """


def _strict_schema() -> dict:
    """PlanDraft as a strict JSON schema.

    Built from the Pydantic model but flattened: strict mode rejects the
    `anyOf: [{string}, {null}]` that Pydantic emits for `str | None`, and
    requires every property listed in `required` with additionalProperties
    false. Generating it from the model keeps the two in step; the flattening
    is what makes it acceptable to the endpoint.
    """
    raw = PlanDraft.model_json_schema()
    props: dict = {}
    for name, spec in raw.get("properties", {}).items():
        if "anyOf" in spec:
            types = [s.get("type") for s in spec["anyOf"] if s.get("type")]
            props[name] = {"type": [t for t in types if t] or ["string", "null"]}
        else:
            props[name] = {k: v for k, v in spec.items()
                           if k in ("type", "items", "description")}
        if desc := spec.get("description"):
            props[name]["description"] = desc
    return {
        "type": "object",
        "properties": props,
        "required": list(props),
        "additionalProperties": False,
    }


class OpenAICompatPlanner:
    """Planner over an OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        requests_per_minute: int | None = None,
        tokens_per_minute: int | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        reasoning_effort: str | None = None,
    ) -> None:
        s = get_settings()
        self.model = model or s.openai_model
        self.base_url = (base_url or s.openai_base_url).rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens or s.openai_max_tokens
        # gpt-oss models emit reasoning tokens that count against max_tokens.
        # Left unbounded they crowd out the JSON and the strict-schema decode
        # fails; "low" leaves room for the answer.
        self.reasoning_effort = reasoning_effort or s.openai_reasoning_effort

        key = api_key or s.resolve_openai_key()
        if not key:
            raise RuntimeError(
                "no API key for the OpenAI-compatible endpoint: set GROQ_API_KEY "
                "(or OPENAI_API_KEY / SENTINEL_OPENAI_API_KEY)"
            )

        # Hosted free tiers cap requests AND tokens per minute, and for this
        # workload (~1,450 tokens per plan) the token cap binds first.
        self.limiter = SyncRollingWindowLimiter(
            requests=requests_per_minute or s.openai_requests_per_minute,
            window=60.0,
            tokens=tokens_per_minute or s.openai_tokens_per_minute,
        )
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            timeout=httpx.Timeout(180.0, connect=15.0),
        )
        self._schema = _strict_schema()
        self.stats = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                      "rate_limit_waits": 0.0, "retries": 0}

    @staticmethod
    def _parse_duration(value: str | None) -> float | None:
        """Groq expresses resets as '10.162s', '1m26.4s', '28m48s'."""
        if not value:
            return None
        import re
        total, found = 0.0, False
        for amount, unit in re.findall(r"([\d.]+)\s*(ms|s|m|h)", value):
            found = True
            total += float(amount) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
        if found:
            return total
        try:
            return float(value)
        except ValueError:
            return None

    def _observe_limits(self, headers) -> None:
        """Re-pace from the server's own accounting.

        A hardcoded tokens-per-minute guess is wrong in both directions: too
        high earns 429s, too low wastes most of the run waiting. The response
        carries the authoritative numbers, so the limiter follows them.
        """
        limit = headers.get("x-ratelimit-limit-tokens")
        if limit and limit.isdigit():
            observed = int(limit)
            if observed != self.limiter.tokens:
                log.info("planner.rate_limit_observed", model=self.model,
                         tokens_per_minute=observed, was=self.limiter.tokens)
                self.limiter.tokens = observed

        # No pre-emptive sleep here. An earlier version slept when
        # `x-ratelimit-remaining-tokens` ran low, which double-counted the
        # same quota: the limiter already waits out the window before the next
        # call, so the two stacked into ~130s per batch of four and the run
        # crawled. Updating the limiter's ceiling from the header is enough --
        # one mechanism owns pacing.

    @retry(
        retry=retry_if_exception_type((RetryableStatus, httpx.TransportError)),
        wait=wait_exponential(multiplier=2, min=2, max=20),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _post(self, payload: dict, attempt: int = 0) -> dict:
        if attempt:
            # Same prompt at the same temperature tends to fail the same way.
            payload = {**payload,
                       "temperature": min(self.temperature + 0.2 * attempt, 1.0)}
        resp = self.client.post("/chat/completions", json=payload)
        self._observe_limits(resp.headers)
        if resp.status_code == 429:
            # Log what the server actually said. An earlier version raised a
            # bare "429 rate limited", which cost two debugging rounds: the
            # message names WHICH limit was hit (RPM, TPM, daily) and that is
            # the whole diagnosis.
            body = resp.text[:300]
            with contextlib.suppress(Exception):
                body = resp.json().get("error", {}).get("message", body)
            delay = resp.headers.get("retry-after")
            if "per day" in body.lower() or "(tpd)" in body.lower():
                raise DailyQuotaExhausted(body[:260])
            log.warning(
                "planner.rate_limited", model=self.model, retry_after=delay,
                remaining_tokens=resp.headers.get("x-ratelimit-remaining-tokens"),
                limit_tokens=resp.headers.get("x-ratelimit-limit-tokens"),
                reset_tokens=resp.headers.get("x-ratelimit-reset-tokens"),
                detail=body,
            )
            if delay:
                with contextlib.suppress(ValueError):
                    time.sleep(min(float(delay), 60.0))
            self.stats["retries"] += 1
            raise RetryableStatus(f"429: {body[:160]}")
        if resp.status_code >= 500:
            self.stats["retries"] += 1
            raise RetryableStatus(f"HTTP {resp.status_code}: {resp.text[:200]}")
        if resp.status_code >= 400:
            # raise_for_status() yields "Client error '400 Bad Request'" plus a
            # link to MDN, which says nothing about what the provider objected
            # to. The body usually names the field.
            detail = resp.text[:400]
            with contextlib.suppress(Exception):
                detail = resp.json().get("error", {}).get("message", detail)
            # Constrained decoding is stochastic: the model sometimes cannot
            # satisfy a strict schema on a given sample. That is a transient
            # 400, not a malformed request, so it is worth another draw.
            if "failed to generate json" in detail.lower():
                self.stats["retries"] += 1
                raise RetryableStatus(f"schema decode failed: {detail[:120]}")
            raise ValueError(f"HTTP {resp.status_code} from {self.model}: {detail}")
        return resp.json()

    def draft(self, *, cve_id, package, os_family, fixed_version, context) -> PlanDraft:
        user = _build_user_prompt(cve_id, package, os_family, fixed_version, context)
        # Groq charges max_tokens as a RESERVATION against the per-minute token
        # budget, not just the tokens actually produced. Estimating the output
        # instead let the limiter admit nearly twice the quota: it allowed ~4
        # calls/min at a guessed 1,650 tokens while the server was reserving
        # ~3,150, so every batch ended in 429s and exponential backoff.
        # ~3.7 chars/token for technical prose.
        estimate = int((len(SYSTEM_PROMPT) + len(user)) / 3.7) + self.max_tokens

        waited = self.limiter.acquire(estimate)
        self.stats["rate_limit_waits"] += waited

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "remediation_plan", "strict": True,
                                "schema": self._schema},
            },
        }
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        data = self._post(payload)

        usage = data.get("usage") or {}
        # Deliberately NOT calling limiter.record_actual(total_tokens) here.
        # The provider charged the reservation (prompt + max_tokens), not the
        # tokens it ended up producing, so replacing the reservation with
        # actual usage under-reports consumption by roughly half and the
        # limiter admits twice the quota again. The reservation stands.
        self.stats["calls"] += 1
        self.stats["prompt_tokens"] += usage.get("prompt_tokens", 0)
        self.stats["completion_tokens"] += usage.get("completion_tokens", 0)

        content = data["choices"][0]["message"]["content"]
        log.info("planner.drafted", cve=cve_id, package=package, model=self.model,
                 prompt_tokens=usage.get("prompt_tokens"),
                 completion_tokens=usage.get("completion_tokens"),
                 waited_s=round(waited, 1))
        try:
            return PlanDraft.model_validate_json(content)
        except Exception:
            # Strict mode should prevent this, but a provider that silently
            # ignores the schema must fail loudly rather than return junk.
            raise ValueError(
                f"{self.model} returned unparseable plan JSON: {content[:300]}"
            ) from None
