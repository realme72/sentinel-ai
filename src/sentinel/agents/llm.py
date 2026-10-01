"""The planner's model interface.

Behind a Protocol so every graph path can be tested without network access or
spend. The fake is not a convenience -- the graph's retry, grounding-failure
and cache branches are the parts most likely to be wrong, and they must be
testable deterministically.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, Field

from sentinel.config import get_settings

log = structlog.get_logger()

SYSTEM_PROMPT = """You write remediation instructions for a vulnerability \
management system used by infrastructure teams.

Rules you must follow:

1. Use ONLY facts present in the provided context. Every CVE identifier and \
every version number you write MUST appear verbatim in the context. A \
downstream check verifies this mechanically and rejects plans that fail, so \
inventing a version number wastes the attempt.
2. If the context gives no fixed version, say so plainly and propose \
compensating controls instead of guessing an upgrade target.
3. Be specific and operational. Name the package, the exact target version, \
the command, and what to restart. "Apply vendor updates" is not a plan.
4. Never propose destructive commands (filesystem wipes, piping remote \
scripts to a shell).
5. Assume the reader owns the host but has not read the advisory."""


class PlanDraft(BaseModel):
    """Structured planner output, so parsing never depends on prose shape."""

    summary: str = Field(description="One or two sentences: what is wrong and why it matters.")
    steps: list[str] = Field(description="Ordered remediation steps, each concrete.")
    commands: list[str] = Field(default_factory=list,
                                description="Exact shell commands, OS-appropriate.")
    rollback: str = Field(description="How to revert if the change breaks something.")
    compensating_controls: str | None = Field(
        default=None,
        description="What to do when no fixed version exists. Null when a patch is available.",
    )
    requires_reboot: bool = Field(default=False)

    def to_markdown(self) -> str:
        parts = [self.summary, ""]
        if self.steps:
            parts.append("**Steps**")
            parts += [f"{i}. {s}" for i, s in enumerate(self.steps, 1)]
            parts.append("")
        if self.commands:
            parts.append("**Commands**")
            parts.append("```bash")
            parts += self.commands
            parts.append("```")
            parts.append("")
        if self.compensating_controls:
            parts += ["**Compensating controls**", self.compensating_controls, ""]
        parts += ["**Rollback**", self.rollback]
        if self.requires_reboot:
            parts += ["", "_Requires a reboot._"]
        return "\n".join(parts)


@runtime_checkable
class PlannerLLM(Protocol):
    model: str

    def draft(self, *, cve_id: str, package: str, os_family: str,
              fixed_version: str | None, context: list[str]) -> PlanDraft:
        ...


def _build_user_prompt(cve_id, package, os_family, fixed_version, context) -> str:
    joined = "\n\n---\n\n".join(f"[chunk {i}] {c}" for i, c in enumerate(context, 1))
    known_fix = fixed_version or "none recorded"
    return (
        f"<context>\n{joined}\n</context>\n\n"
        f"Write a remediation plan for {cve_id} affecting package `{package}` "
        f"on a {os_family} host. Fixed version recorded by the scanner: {known_fix}.\n\n"
        f"Every version number and CVE id in your answer must appear in the context above."
    )


class AnthropicPlanner:
    """Live planner backed by the Claude API."""

    def __init__(self, model: str | None = None, effort: str = "high") -> None:
        import anthropic

        self.model = model or get_settings().planner_model
        self.effort = effort
        self.client = anthropic.Anthropic()

    def draft(self, *, cve_id, package, os_family, fixed_version, context) -> PlanDraft:
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=4096,
            # The system prompt is byte-stable across every call in a run, so
            # it is the natural cache breakpoint. The volatile context goes in
            # the user turn, after it.
            system=[{"type": "text", "text": SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort, "format": PlanDraft},
            messages=[{
                "role": "user",
                "content": _build_user_prompt(cve_id, package, os_family,
                                              fixed_version, context),
            }],
        )
        usage = response.usage
        log.info("planner.drafted", cve=cve_id, package=package, model=self.model,
                 input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
                 cache_read=getattr(usage, "cache_read_input_tokens", 0))
        return response.parsed


class ScriptedPlanner:
    """Deterministic planner for tests.

    `responses` maps cve_id -> list of drafts, consumed one per attempt, so a
    test can make the first attempt fail grounding and the second succeed.
    """

    model = "scripted"

    def __init__(self, responses: dict[str, list[PlanDraft]]) -> None:
        self.responses = {k: list(v) for k, v in responses.items()}
        self.calls: list[dict] = []

    def draft(self, *, cve_id, package, os_family, fixed_version, context) -> PlanDraft:
        self.calls.append({"cve_id": cve_id, "package": package,
                           "os_family": os_family, "context_chunks": len(context)})
        queue = self.responses.get(cve_id)
        if not queue:
            raise AssertionError(f"ScriptedPlanner has no response left for {cve_id}")
        return queue.pop(0) if len(queue) > 1 else queue[0]
