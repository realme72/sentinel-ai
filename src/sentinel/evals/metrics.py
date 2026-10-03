"""Plan quality metrics.

Two tiers, and the split is deliberate.

**Deterministic (free, always run).** These cannot flatter the model and cost
nothing, so they run on every plan. They measure the things that make a plan
*actionable* -- which is precisely what the grounding gate cannot see. The gate
proves a plan invents nothing; it is perfectly happy with "apply vendor
updates", which is grounded, true, and useless.

**LLM-judged (costly, opt-in).** Faithfulness and an actionability rubric.
Judge calls draw on the same daily token budget as the planner, and on a free
tier the judge is a sibling of the model under test -- shared failure modes
inflate scores. So these are a sample, not a gate.

The placeholder check earns its place from a real observation: an otherwise
correct Log4Shell plan instructed
`cp /path/to/log4j-core-2.14.1.jar /path/to/backup/` -- grounded, specific
about versions, and not runnable by anyone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Commands that belong to each packaging system. A plan telling a Debian host
# to run `apk add` is wrong in a way no version check would catch.
OS_COMMANDS = {
    "debian": ("apt-get", "apt ", "dpkg", "apt-cache"),
    "rhel": ("yum", "dnf", "rpm", "microdnf"),
    "alpine": ("apk",),
}
# Ecosystem tooling is OS-independent.
ECOSYSTEM_COMMANDS = ("mvn", "gradle", "pip", "pip3", "npm", "yarn", "poetry")

# Text that signals the plan was never made concrete.
# A placeholder is an angle-bracket token the reader must replace. Matching
# every `<...>` was wrong: `<artifactId>` and `<version>` are real Maven tags,
# and a plan that shows a pom.xml snippet is MORE actionable, not less. So the
# token must also contain a word that marks it as a blank to fill in.
_PLACEHOLDER_WORDS = (
    r"your|previous|prev|old|current|insert|todo|placeholder|example"
    r"|service[-_ ]?name|unit[-_ ]?name|host|hostname|path|app[-_ ]?name"
)
PLACEHOLDER_RE = re.compile(
    r"(/path/to/"
    # No \b after the word: it does not match between "previous" and "_",
    # so `<previous_version>` slipped through.
    rf"|<(?=[^>\n]{{0,40}}(?:{_PLACEHOLDER_WORDS}))[^>\n]{{3,40}}>"
    r"|\byour[-_ ](app|service|host|server|application)\b"
    r"|\bexample\.com\b|\bTODO\b|\bxxx+\b|\[insert)",
    re.IGNORECASE,
)
VAGUE_RE = re.compile(
    r"\b(apply (the )?(vendor|security|latest) (updates?|patches?)"
    r"|update (the )?(package|software) as needed"
    r"|follow vendor instructions"
    r"|consult (the )?(vendor|documentation)"
    r"|upgrade to (the )?(latest|newest|fixed) version)\b",
    re.IGNORECASE,
)
CODE_BLOCK_RE = re.compile(r"```(?:bash|sh|shell)?\n(.*?)```", re.DOTALL)


@dataclass
class PlanScore:
    grounded: bool
    names_target: bool
    has_commands: bool
    commands_match_os: bool
    has_rollback: bool
    no_placeholders: bool
    not_vague: bool
    detail: dict = field(default_factory=dict)

    CHECKS = ("grounded", "names_target", "has_commands", "commands_match_os",
              "has_rollback", "no_placeholders", "not_vague")

    @property
    def passed(self) -> int:
        return sum(bool(getattr(self, c)) for c in self.CHECKS)

    @property
    def score(self) -> float:
        return round(self.passed / len(self.CHECKS), 3)

    @property
    def actionable(self) -> bool:
        """The bar for a plan an engineer can execute without research.

        `commands_match_os` is part of it: a plan telling a Debian host to run
        `apk add` is not a plan with a small flaw, it is not executable. Only
        `has_rollback` is excluded -- desirable, but its absence does not stop
        someone acting on the plan.
        """
        return (self.grounded and self.names_target and self.has_commands
                and self.commands_match_os and self.no_placeholders
                and self.not_vague)

    def as_dict(self) -> dict:
        return {c: bool(getattr(self, c)) for c in self.CHECKS} | {
            "score": self.score, "actionable": self.actionable, **self.detail
        }

    def failures(self) -> list[str]:
        return [c for c in self.CHECKS if not getattr(self, c)]


def extract_commands(plan_markdown: str) -> list[str]:
    cmds: list[str] = []
    for block in CODE_BLOCK_RE.findall(plan_markdown):
        cmds += [ln.strip() for ln in block.splitlines() if ln.strip()]
    return cmds


def score_plan(
    plan_markdown: str,
    *,
    grounded: bool,
    target_version: str | None,
    os_family: str,
) -> PlanScore:
    commands = extract_commands(plan_markdown)
    joined = " ".join(commands)

    expected = OS_COMMANDS.get(os_family, ())
    uses_os_tool = any(c in joined for c in expected)
    uses_ecosystem = any(joined.startswith(c) or f" {c} " in f" {joined} "
                         for c in ECOSYSTEM_COMMANDS)
    # Wrong-OS tooling is a hard fail; ecosystem tooling (mvn, pip) is
    # legitimately OS-independent and counts as a match.
    wrong_os = [
        fam for fam, cmds in OS_COMMANDS.items()
        if fam != os_family and any(c in joined for c in cmds)
    ]

    placeholders = PLACEHOLDER_RE.findall(plan_markdown)
    vague = VAGUE_RE.findall(plan_markdown)

    return PlanScore(
        grounded=grounded,
        names_target=bool(target_version) and target_version in plan_markdown,
        has_commands=bool(commands),
        commands_match_os=(uses_os_tool or uses_ecosystem) and not wrong_os,
        has_rollback="rollback" in plan_markdown.lower(),
        no_placeholders=not placeholders,
        not_vague=not vague,
        detail={
            "command_count": len(commands),
            "wrong_os_tooling": wrong_os,
            "placeholders": sorted({p[0] if isinstance(p, tuple) else p
                                    for p in placeholders})[:4],
            "vague_phrases": sorted({v[0] if isinstance(v, tuple) else v
                                     for v in vague})[:4],
        },
    )


def aggregate(scores: list[PlanScore]) -> dict:
    if not scores:
        return {"plans": 0}
    n = len(scores)
    out = {"plans": n,
           "mean_score": round(sum(s.score for s in scores) / n, 3),
           "actionable_rate": round(sum(s.actionable for s in scores) / n, 3)}
    for check in PlanScore.CHECKS:
        out[f"{check}_rate"] = round(
            sum(bool(getattr(s, check)) for s in scores) / n, 3)
    return out
