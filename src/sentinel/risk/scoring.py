"""Deterministic risk scoring.

This module is the reason the system is auditable. No LLM touches any number
here. Given the same facts it always returns the same score, and `factors`
records every input and every component so an asset owner who disputes a
priority can be shown the arithmetic.

Score is 0-100, built from four capped components:

    severity  (<=40)  CVSS base score -- how bad is it if exploited
    exploit   (<=30)  KEV + EPSS      -- is it ACTUALLY being exploited
    exposure  (<=15)  reachability    -- can an attacker get to it
    asset     (<=15)  blast radius    -- what does it cost us if they do

The weighting is deliberate: `exploit` is nearly as heavy as `severity`
because a CVSS 9.8 nobody has ever weaponised is a worse use of an engineer's
afternoon than a CVSS 7.2 sitting in CISA KEV.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

POLICY_VERSION = "2026.09.1"

MAX_SEVERITY = 40.0
MAX_EXPLOIT = 30.0
MAX_EXPOSURE = 15.0
MAX_ASSET = 15.0

# Fallback when NVD has published no CVSS vector yet (common in the first
# days after disclosure, which is exactly when you most want to act).
_SEVERITY_FALLBACK = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}

_DATA_CLASS_POINTS = {"restricted": 5.0, "confidential": 3.0, "internal": 1.0, "public": 0.0}

BANDS = (("critical", 75.0), ("high", 55.0), ("medium", 35.0), ("low", 0.0))
_BAND_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Floors that the additive score is not allowed to undercut.
#
# Without these, a CVSS 10.0 actively used in ransomware campaigns drops to
# "high" on an internal dev box, because zero exposure plus low asset value
# cancels out ground-truth exploitation. That is the standard failure mode of
# additive risk models, and it is wrong twice over: dev boxes are the classic
# lateral-movement beachhead, and `environment` labels in a real CMDB are
# frequently stale. Context may *raise* urgency; it may not dilute evidence
# that something is being exploited in the wild right now.
KEV_RANSOMWARE_FLOOR = "critical"
KEV_FLOOR = "high"


@dataclass(frozen=True)
class CveFacts:
    cve_id: str
    cvss_v31_score: float | None = None
    cvss_v40_score: float | None = None
    cvss_severity: str | None = None
    kev_listed: bool = False
    kev_ransomware: bool = False
    epss_score: float | None = None


@dataclass(frozen=True)
class AssetFacts:
    hostname: str
    environment: str
    internet_facing: bool
    business_criticality: int
    data_classification: str = "internal"


@dataclass(frozen=True)
class RiskResult:
    score: float
    band: str
    factors: dict
    policy_version: str = POLICY_VERSION


def _as_float(value) -> float | None:
    if value is None:
        return None
    return float(value) if not isinstance(value, Decimal) else float(value)


def severity_component(cve: CveFacts) -> tuple[float, dict]:
    """CVSS base score scaled to 0-40. Prefers v3.1 because it is what the
    overwhelming majority of tooling and policy documents still speak."""
    base = _as_float(cve.cvss_v31_score)
    source = "cvss_v31"
    if base is None:
        base = _as_float(cve.cvss_v40_score)
        source = "cvss_v40"
    if base is None and cve.cvss_severity:
        base = _SEVERITY_FALLBACK.get(cve.cvss_severity.upper())
        source = "severity_label_fallback"
    if base is None:
        # Unknown severity is treated as medium, not zero. An unscored CVE is
        # an absence of information, not evidence of safety.
        base, source = 5.0, "unscored_default"

    return round(min(base / 10.0, 1.0) * MAX_SEVERITY, 2), {
        "cvss_base": base,
        "cvss_source": source,
    }


def exploit_component(cve: CveFacts) -> tuple[float, dict]:
    """Real-world exploitation signal. KEV is ground truth ("this has been
    used against someone"); EPSS is a forecast. KEV therefore dominates."""
    epss = _as_float(cve.epss_score)
    detail: dict = {"kev_listed": cve.kev_listed, "kev_ransomware": cve.kev_ransomware,
                    "epss_score": epss}

    if cve.kev_listed and cve.kev_ransomware:
        detail["reason"] = "kev_ransomware"
        return MAX_EXPLOIT, detail
    if cve.kev_listed:
        detail["reason"] = "kev_listed"
        return 25.0, detail

    if epss is None:
        detail["reason"] = "no_epss_data"
        return 0.0, detail
    for threshold, points, reason in (
        (0.50, 20.0, "epss_gte_50pct"),
        (0.10, 12.0, "epss_gte_10pct"),
        (0.01, 6.0, "epss_gte_1pct"),
    ):
        if epss >= threshold:
            detail["reason"] = reason
            return points, detail
    detail["reason"] = "epss_below_1pct"
    return 0.0, detail


def exposure_component(asset: AssetFacts) -> tuple[float, dict]:
    """Reachability. An unpatched box nobody can route to is a different
    problem from the same box behind a public load balancer."""
    env = asset.environment.lower()
    detail = {"internet_facing": asset.internet_facing, "environment": env}

    if asset.internet_facing and env == "prod":
        detail["reason"] = "internet_facing_prod"
        return MAX_EXPOSURE, detail
    if asset.internet_facing:
        detail["reason"] = "internet_facing_nonprod"
        return 10.0, detail
    points = {"prod": 6.0, "staging": 3.0}.get(env, 0.0)
    detail["reason"] = f"internal_{env}"
    return points, detail


def asset_component(asset: AssetFacts) -> tuple[float, dict]:
    """Blast radius: how much it costs us if this one falls over."""
    crit_points = (max(1, min(5, asset.business_criticality)) - 1) * 2.5  # 0..10
    data_points = _DATA_CLASS_POINTS.get(asset.data_classification.lower(), 1.0)
    return round(min(crit_points + data_points, MAX_ASSET), 2), {
        "business_criticality": asset.business_criticality,
        "criticality_points": crit_points,
        "data_classification": asset.data_classification,
        "data_points": data_points,
    }


def band_for(score: float) -> str:
    for name, floor in BANDS:
        if score >= floor:
            return name
    return "low"


def apply_exploit_floor(band: str, cve: CveFacts) -> tuple[str, str | None]:
    """Raise `band` to the floor demanded by real-world exploitation evidence.

    Returns the (possibly unchanged) band and the name of the rule that moved
    it, so the decision shows up in `factors` rather than surprising someone.
    """
    floor = None
    if cve.kev_listed and cve.kev_ransomware:
        floor, rule = KEV_RANSOMWARE_FLOOR, "kev_ransomware_floor"
    elif cve.kev_listed:
        floor, rule = KEV_FLOOR, "kev_floor"

    if floor and _BAND_ORDER[floor] > _BAND_ORDER[band]:
        return floor, rule
    return band, None


def score_finding(cve: CveFacts, asset: AssetFacts) -> RiskResult:
    severity, sev_d = severity_component(cve)
    exploit, exp_d = exploit_component(cve)
    exposure, expo_d = exposure_component(asset)
    asset_pts, asset_d = asset_component(asset)

    total = round(severity + exploit + exposure + asset_pts, 2)
    scored_band = band_for(total)
    band, floor_rule = apply_exploit_floor(scored_band, cve)

    return RiskResult(
        score=total,
        band=band,
        factors={
            "cve_id": cve.cve_id,
            "hostname": asset.hostname,
            "components": {
                "severity": {"points": severity, "max": MAX_SEVERITY, **sev_d},
                "exploit": {"points": exploit, "max": MAX_EXPLOIT, **exp_d},
                "exposure": {"points": exposure, "max": MAX_EXPOSURE, **expo_d},
                "asset": {"points": asset_pts, "max": MAX_ASSET, **asset_d},
            },
            "total": total,
            "scored_band": scored_band,
            "band": band,
            "band_floor_rule": floor_rule,
        },
    )
