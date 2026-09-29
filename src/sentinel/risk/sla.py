"""Remediation SLA policy: risk band -> days -> due date.

The due date on a security ticket is a commitment an asset owner will be
measured against, and in a regulated org it is audit evidence. So it is
computed here, by rule, from `first_seen`. A language model never picks it.

The model's job is to explain the date and make hitting it easy. That split
is the whole design.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from sentinel.risk.scoring import POLICY_VERSION, CveFacts, RiskResult

# Baseline clock, in days from first detection.
BAND_SLA_DAYS = {"critical": 7, "high": 15, "medium": 45, "low": 90}

# Anything KEV-listed AND reachable from the internet is an incident, not a
# ticket in a queue. This short-circuits the band clock.
EMERGENCY_SLA_DAYS = 3


@dataclass(frozen=True)
class SlaResult:
    sla_days: int
    due_date: date
    rule: str
    policy_version: str = POLICY_VERSION


def resolve_sla(
    risk: RiskResult,
    cve: CveFacts,
    *,
    first_seen: date,
    internet_facing: bool,
    kev_due_date: date | None = None,
) -> SlaResult:
    """Pick the *tightest* applicable deadline.

    Precedence, strictest first:
      1. KEV + internet-facing  -> 3 days (emergency)
      2. CISA KEV due date      -> ceiling, if it lands earlier than our band
      3. Risk band baseline     -> 7 / 15 / 45 / 90 days
    """
    band_days = BAND_SLA_DAYS.get(risk.band, BAND_SLA_DAYS["low"])
    baseline_due = first_seen + timedelta(days=band_days)

    if cve.kev_listed and internet_facing:
        return SlaResult(
            sla_days=EMERGENCY_SLA_DAYS,
            due_date=first_seen + timedelta(days=EMERGENCY_SLA_DAYS),
            rule="emergency_kev_internet_facing",
        )

    # CISA publishes a remediation deadline for KEV entries. If it is sooner
    # than what our band would give, it wins -- never loosen an external
    # deadline just because our own maths was more relaxed.
    if cve.kev_listed and kev_due_date and kev_due_date < baseline_due:
        return SlaResult(
            sla_days=max((kev_due_date - first_seen).days, 0),
            due_date=kev_due_date,
            rule="cisa_kev_due_date_ceiling",
        )

    return SlaResult(
        sla_days=band_days,
        due_date=baseline_due,
        rule=f"band_baseline_{risk.band}",
    )


def is_overdue(due: date, *, today: date | None = None) -> bool:
    return due < (today or date.today())


def days_remaining(due: date, *, today: date | None = None) -> int:
    return (due - (today or date.today())).days
