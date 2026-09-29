"""The deterministic core gets real tests. If this drifts, every ticket the
system has ever filed becomes unexplainable."""

from datetime import date

import pytest

from sentinel.risk.scoring import AssetFacts, CveFacts, band_for, score_finding
from sentinel.risk.sla import BAND_SLA_DAYS, resolve_sla

PROD_EDGE = AssetFacts(
    hostname="edge-01", environment="prod", internet_facing=True,
    business_criticality=5, data_classification="restricted",
)
DEV_BOX = AssetFacts(
    hostname="dev-07", environment="dev", internet_facing=False,
    business_criticality=1, data_classification="internal",
)

LOG4SHELL = CveFacts(
    cve_id="CVE-2021-44228", cvss_v31_score=10.0, cvss_severity="CRITICAL",
    kev_listed=True, kev_ransomware=True, epss_score=0.97,
)
QUIET_MEDIUM = CveFacts(
    cve_id="CVE-2024-99999", cvss_v31_score=5.3, cvss_severity="MEDIUM",
    kev_listed=False, epss_score=0.0004,
)


def test_worst_case_saturates_near_100():
    r = score_finding(LOG4SHELL, PROD_EDGE)
    assert r.score == 100.0
    assert r.band == "critical"


def test_same_cve_scores_lower_on_an_unreachable_dev_box():
    hot = score_finding(LOG4SHELL, PROD_EDGE)
    cold = score_finding(LOG4SHELL, DEV_BOX)
    assert cold.score < hot.score
    # Still critical -- log4shell on a dev box is not a Friday problem, but it
    # should not outrank the internet-facing one.
    assert cold.band == "critical"


def test_exploited_medium_outranks_quiet_high():
    """The core claim of the weighting: evidence of exploitation beats a
    bigger CVSS number with no exploitation signal."""
    exploited_medium = score_finding(
        CveFacts(cve_id="CVE-A", cvss_v31_score=6.5, kev_listed=True), PROD_EDGE
    )
    quiet_high = score_finding(
        CveFacts(cve_id="CVE-B", cvss_v31_score=8.8, epss_score=0.0001), PROD_EDGE
    )
    assert exploited_medium.score > quiet_high.score


def test_unscored_cve_defaults_to_medium_not_zero():
    r = score_finding(CveFacts(cve_id="CVE-NEW"), DEV_BOX)
    assert r.factors["components"]["severity"]["cvss_source"] == "unscored_default"
    assert r.factors["components"]["severity"]["points"] == 20.0


def test_factors_are_complete_enough_to_recompute_the_score():
    r = score_finding(LOG4SHELL, PROD_EDGE)
    comps = r.factors["components"]
    assert sum(c["points"] for c in comps.values()) == pytest.approx(r.score)
    assert set(comps) == {"severity", "exploit", "exposure", "asset"}


@pytest.mark.parametrize(
    "score,expected",
    [(100.0, "critical"), (75.0, "critical"), (74.9, "high"),
     (55.0, "high"), (34.9, "low"), (0.0, "low")],
)
def test_band_boundaries(score, expected):
    assert band_for(score) == expected


# --- SLA -------------------------------------------------------------------

SEEN = date(2026, 9, 30)


def test_kev_plus_internet_facing_is_a_three_day_emergency():
    risk = score_finding(LOG4SHELL, PROD_EDGE)
    sla = resolve_sla(risk, LOG4SHELL, first_seen=SEEN, internet_facing=True)
    assert sla.sla_days == 3
    assert sla.due_date == date(2026, 10, 3)
    assert sla.rule == "emergency_kev_internet_facing"


def test_cisa_due_date_tightens_but_never_loosens_our_clock():
    risk = score_finding(LOG4SHELL, DEV_BOX)
    earlier = resolve_sla(
        risk, LOG4SHELL, first_seen=SEEN, internet_facing=False,
        kev_due_date=date(2026, 10, 2),
    )
    assert earlier.due_date == date(2026, 10, 2)
    assert earlier.rule == "cisa_kev_due_date_ceiling"

    later = resolve_sla(
        risk, LOG4SHELL, first_seen=SEEN, internet_facing=False,
        kev_due_date=date(2026, 12, 25),
    )
    assert later.sla_days == BAND_SLA_DAYS["critical"]
    assert later.rule == "band_baseline_critical"


def test_quiet_medium_on_a_dev_box_gets_a_relaxed_clock():
    risk = score_finding(QUIET_MEDIUM, DEV_BOX)
    sla = resolve_sla(risk, QUIET_MEDIUM, first_seen=SEEN, internet_facing=False)
    assert risk.band == "low"
    assert sla.sla_days == 90


def test_sla_is_a_pure_function_of_first_seen():
    """Re-running the pipeline must not silently slide deadlines to the right."""
    risk = score_finding(QUIET_MEDIUM, PROD_EDGE)
    a = resolve_sla(risk, QUIET_MEDIUM, first_seen=SEEN, internet_facing=True)
    b = resolve_sla(risk, QUIET_MEDIUM, first_seen=SEEN, internet_facing=True)
    assert a == b


# --- exploit floors --------------------------------------------------------


def test_kev_ransomware_cannot_be_banded_below_critical():
    """Context may raise urgency; it may not dilute evidence of active
    exploitation. Scored 71 on this box, floored to critical."""
    r = score_finding(LOG4SHELL, DEV_BOX)
    assert r.factors["scored_band"] == "high"
    assert r.band == "critical"
    assert r.factors["band_floor_rule"] == "kev_ransomware_floor"


def test_plain_kev_floors_at_high():
    quiet_kev = CveFacts(cve_id="CVE-C", cvss_v31_score=4.0, kev_listed=True)
    r = score_finding(quiet_kev, DEV_BOX)
    assert r.band == "high"
    assert r.factors["band_floor_rule"] == "kev_floor"


def test_floor_never_lowers_an_already_higher_band():
    r = score_finding(LOG4SHELL, PROD_EDGE)
    assert r.band == "critical"
    assert r.factors["band_floor_rule"] is None  # scored there on its own
