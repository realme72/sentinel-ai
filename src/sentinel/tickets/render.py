"""Render a FixAction (plus optional plan) into a ticket body.

Written for the person who gets assigned it and has not read the advisory:
what to do, on which hosts, by when, and why it is ranked where it is. The
risk arithmetic is included because an owner who disputes a priority should be
shown the numbers rather than told to trust them.
"""

from __future__ import annotations

from sentinel.agents.correlate import HOSTNAMES_INLINE, FixAction
from sentinel.tickets.sink import Ticket, marker

_BAND_LABEL = {"critical": "sev:critical", "high": "sev:high",
               "medium": "sev:medium", "low": "sev:low"}


def render_body(action: FixAction, *, plan_markdown: str | None = None,
                plan_grounded: bool = False) -> str:
    lines: list[str] = [marker(action.idempotency_key), ""]

    # --- what and by when ---
    if action.has_fix:
        lines.append(f"**Action** — upgrade `{action.package_name}` to "
                     f"**{action.fixed_version}** on {action.asset_count} host(s).")
    else:
        lines.append(f"**Action** — no fixed version is published for "
                     f"`{action.package_name}`. A compensating control is required.")
    lines.append("")
    lines.append(f"**Due {action.due_date}** · risk band **{action.risk_band}** "
                 f"· highest score {action.max_risk_score:.1f}/100")
    lines.append("")

    # --- why it ranks here ---
    why: list[str] = []
    if action.kev_cve_ids:
        why.append(f"{len(action.kev_cve_ids)} of these CVEs are in the CISA "
                   f"Known Exploited Vulnerabilities catalog "
                   f"({', '.join(action.kev_cve_ids)}) — observed exploited in the wild")
    if action.max_epss is not None and action.max_epss >= 0.1:
        why.append(f"highest EPSS exploit probability {action.max_epss:.2%} "
                   f"in the next 30 days")
    if action.internet_facing_count:
        why.append(f"{action.internet_facing_count} affected host(s) are internet-facing")
    if action.prod_count:
        why.append(f"{action.prod_count} are production")
    if why:
        lines.append("**Why this priority**")
        lines += [f"- {w}" for w in why]
        lines.append("")

    # --- the CVEs, and why the target may exceed any single one ---
    lines.append(f"**Resolves {len(action.cve_ids)} CVE(s)**")
    if action.version_requirements:
        lines.append("")
        lines.append("| CVE | fixed in |")
        lines.append("|---|---|")
        for cve in sorted(action.version_requirements):
            lines.append(f"| {cve} | {action.version_requirements[cve]} |")
        highest = action.fixed_version
        if highest and len(set(action.version_requirements.values())) > 1:
            lines.append("")
            lines.append(f"Target is **{highest}** — the highest version required across "
                         f"this package, so one upgrade closes all of them. If you are "
                         f"pinned to an older branch, the per-CVE minimums above are the "
                         f"floor for that branch.")
    else:
        lines.append("")
        lines += [f"- {c}" for c in sorted(action.cve_ids)]
    lines.append("")

    # --- the plan ---
    if plan_markdown:
        status = "" if plan_grounded else " _(ungrounded — review before acting)_"
        lines.append(f"**Remediation**{status}")
        lines.append("")
        lines.append(plan_markdown)
        lines.append("")

    # --- scope ---
    lines.append(f"**Affected hosts** ({action.asset_count})")
    shown = action.hostnames[:HOSTNAMES_INLINE]
    lines.append("")
    lines.append(", ".join(f"`{h}`" for h in shown))
    if action.asset_count > len(shown):
        lines.append("")
        lines.append(f"…and {action.asset_count - len(shown)} more.")
    lines.append("")

    env = ", ".join(action.environments) or "unknown"
    os_f = ", ".join(action.os_families) or "unknown"
    lines.append(f"**Scope** — environments: {env} · OS: {os_f} · "
                 f"owner: {action.owner_team} ({action.owner_email})")
    lines.append("")
    lines.append("---")
    lines.append(f"_Filed by Sentinel-AI. Covers {len(action.finding_ids)} scanner "
                 f"findings. Due date is computed by policy from first detection, "
                 f"not by a language model._")
    return "\n".join(lines)


def render_ticket(action: FixAction, *, plan_markdown: str | None = None,
                  plan_grounded: bool = False) -> Ticket:
    labels = ["sentinel", _BAND_LABEL.get(action.risk_band, "sev:unknown")]
    if action.kev_cve_ids:
        labels.append("kev")
    if not action.has_fix:
        labels.append("no-fix-available")
    if action.internet_facing_count:
        labels.append("internet-facing")
    labels.append(f"team:{action.owner_team}")

    return Ticket(
        idempotency_key=action.idempotency_key,
        title=action.title,
        body=render_body(action, plan_markdown=plan_markdown,
                         plan_grounded=plan_grounded),
        owner_team=action.owner_team,
        owner_email=action.owner_email,
        risk_band=action.risk_band,
        due_date=action.due_date,
        labels=labels,
    )
