"""DeepEval judge backed by the same OpenAI-compatible endpoint as the planner.

DeepEval defaults to OpenAI, which this project has no key for. More
importantly, judge calls are charged against the same daily token budget as
the planner (86 plan-sized calls/day on Groq's free tier), so the judge is
deliberately cheap: a small model, low max_tokens, and a hard call counter so
an eval run cannot quietly eat the budget the planner needs.

A note on judging with the model under test: using one gpt-oss variant to
grade another shares failure modes, which inflates scores. That is a real
limitation of evaluating on a free tier, and it is why the deterministic
metrics in `metrics.py` carry the weight -- they are the ones that cannot
flatter the model.
"""

from __future__ import annotations

import json

import httpx
import structlog
from deepeval.models.base_model import DeepEvalBaseLLM

from sentinel.config import get_settings

log = structlog.get_logger()


class GroqJudge(DeepEvalBaseLLM):
    """Minimal DeepEvalBaseLLM over /chat/completions."""

    def __init__(self, model: str | None = None, max_tokens: int = 900,
                 call_budget: int = 60) -> None:
        s = get_settings()
        self._model = model or s.openai_bulk_model
        self.base_url = s.openai_base_url.rstrip("/")
        self.max_tokens = max_tokens
        self.call_budget = call_budget
        self.calls = 0
        self.tokens = 0
        key = s.resolve_openai_key()
        if not key:
            raise RuntimeError("no API key for the judge endpoint (GROQ_API_KEY)")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {key}"},
            timeout=httpx.Timeout(120.0, connect=15.0),
        )
        super().__init__(self._model)

    # --- DeepEvalBaseLLM contract -----------------------------------------

    def load_model(self, *a, **kw):
        return self

    def get_model_name(self, *a, **kw) -> str:
        return f"groq:{self._model}"

    def supports_structured_outputs(self) -> bool:
        return True

    def supports_json_mode(self) -> bool:
        return True

    def supports_temperature(self) -> bool:
        return True

    # --- generation --------------------------------------------------------

    def _complete(self, prompt: str, schema=None) -> str:
        if self.calls >= self.call_budget:
            raise RuntimeError(
                f"judge call budget of {self.call_budget} reached. The daily "
                f"token quota is shared with the planner, so the eval stops "
                f"rather than spending the planner's budget."
            )
        body: dict = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "max_tokens": self.max_tokens,
        }
        if schema is not None:
            body["response_format"] = {"type": "json_object"}

        resp = self._client.post("/chat/completions", json=body)
        if resp.status_code != 200:
            detail = resp.text[:200]
            try:
                detail = resp.json().get("error", {}).get("message", detail)
            except Exception:  # noqa: BLE001 - a non-JSON body is still useful
                detail = resp.text[:200]
            raise RuntimeError(f"judge HTTP {resp.status_code}: {detail}")

        data = resp.json()
        self.calls += 1
        self.tokens += (data.get("usage") or {}).get("total_tokens", 0)
        return data["choices"][0]["message"]["content"] or ""

    def generate(self, prompt: str, *a, schema=None, **kw):
        text = self._complete(prompt, schema)
        if schema is None:
            return text
        return self._coerce(text, schema)

    async def a_generate(self, prompt: str, *a, schema=None, **kw):
        # Synchronous under the hood: the daily token budget caps throughput
        # far below anything concurrency would buy.
        return self.generate(prompt, schema=schema, **kw)

    def generate_with_schema(self, prompt: str, *a, schema=None, **kw):
        return self.generate(prompt, schema=schema, **kw)

    async def a_generate_with_schema(self, prompt: str, *a, schema=None, **kw):
        return self.generate(prompt, schema=schema, **kw)

    def batch_generate(self, prompts: list[str], *a, **kw) -> list[str]:
        return [self.generate(p) for p in prompts]

    @staticmethod
    def _coerce(text: str, schema):
        """Parse the judge's JSON into the pydantic schema DeepEval expects."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1].removeprefix("json").strip()
        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError:
            # Last resort: the outermost JSON object in the response.
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start < 0 or end <= start:
                raise
            payload = json.loads(cleaned[start:end + 1])
        return schema(**payload)

    def usage(self) -> dict:
        return {"judge_model": self._model, "calls": self.calls,
                "tokens": self.tokens, "budget": self.call_budget}
