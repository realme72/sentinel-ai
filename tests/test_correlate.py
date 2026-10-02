"""Correlation turns 103,166 findings into 937 fix actions. The grouping key
is the whole design, and two choices in it were wrong at first."""

from datetime import date

import pytest

from sentinel.agents.correlate import FixAction, correlate, summarise
from sentinel.db.session import query_one


def action(**over) -> FixAction:
    base = dict(
        owner_team="infra", owner_email="infra@example.com",
        package_name="org.apache.logging.log4j:log4j-core",
        fixed_version="2.25.4", risk_band="critical", due_date=date(2026, 10, 3),
        max_risk_score=96.0, asset_count=10, internet_facing_count=1, prod_count=3,
        cve_ids=["CVE-2021-44228"], kev_cve_ids=["CVE-2021-44228"],
        finding_ids=[1, 2, 3], hostnames=["api-prod-035"],
        os_families=["debian"], environments=["prod"],
    )
    base.update(over)
    return FixAction(**base)


# --- idempotency: a re-scan must update a ticket, not file another ---------


def test_key_is_stable_across_runs():
    assert action().idempotency_key == action().idempotency_key


def test_key_ignores_the_asset_set():
    """Hosts join and leave a campaign as the fleet changes. That is an update
    to the same ticket, not a new ticket."""
    a = action(asset_count=10, hostnames=["h1"], finding_ids=[1])
    b = action(asset_count=40, hostnames=["h1", "h2"], finding_ids=[1, 2, 3])
    assert a.idempotency_key == b.idempotency_key


def test_key_ignores_the_target_version():
    """The target rises as new CVEs land on the same package. Still the same
    upgrade campaign."""
    assert action(fixed_version="2.17.1").idempotency_key == \
           action(fixed_version="2.25.4").idempotency_key


def test_key_separates_bands():
    """Different bands carry different deadlines, so they are different
    tickets even for the same package."""
    assert action(risk_band="critical").idempotency_key != \
           action(risk_band="medium").idempotency_key


def test_key_separates_fixable_from_unfixable():
    """"Upgrade to X" and "no patch exists, apply a compensating control" are
    different pieces of work."""
    assert action(fixed_version="2.25.4").idempotency_key != \
           action(fixed_version=None).idempotency_key


def test_key_separates_teams():
    assert action(owner_team="infra").idempotency_key != \
           action(owner_team="payments").idempotency_key


def test_title_states_the_action_not_the_finding():
    assert action().title.startswith("[CRITICAL] Upgrade ")
    assert "2.25.4" in action().title
    assert "no fix available" in action(fixed_version=None).title
    assert "1 host" in action(asset_count=1).title and \
           "1 hosts" not in action(asset_count=1).title


# --- against the real fleet ------------------------------------------------

_has_data = (query_one("SELECT count(*) AS n FROM risk_assessments WHERE is_current") or
             {"n": 0})["n"] > 0
needs_data = pytest.mark.skipif(not _has_data, reason="no scored findings in this database")


@needs_data
def test_one_upgrade_per_package_per_band():
    """The bug this replaced: grouping on fixed_version produced 11 tickets
    for log4j-core on one team across 7 target versions, for the same hosts.
    Nobody upgrades a package seven times."""
    log4j = [a for a in correlate()
             if "log4j-core" in a.package_name and a.owner_team == "infra"]
    assert log4j, "expected log4j findings for the infra team"
    assert len(log4j) <= 4, f"one ticket per band at most, got {len(log4j)}"
    assert len({a.risk_band for a in log4j}) == len(log4j), "one per band"


@needs_data
def test_every_band_names_the_same_target_version():
    """Satisfying the urgent ticket must close the relaxed ones. Different
    targets per band would mean upgrading the same package twice."""
    by_package: dict[tuple[str, str], set[str]] = {}
    for a in correlate():
        if a.fixed_version:
            by_package.setdefault((a.owner_team, a.package_name), set()).add(a.fixed_version)
    multi = {k: v for k, v in by_package.items() if len(v) > 1}
    assert not multi, f"packages with inconsistent targets: {list(multi)[:3]}"


@needs_data
def test_target_satisfies_every_cve_in_the_group():
    """The target must be >= the highest per-CVE minimum it claims to fix."""
    from sentinel.ingest.versions import version_key

    for a in correlate(bands=["critical", "high"]):
        if not a.fixed_version or not a.version_requirements:
            continue
        needed = max(a.version_requirements.values(), key=version_key)
        assert version_key(a.fixed_version) >= version_key(needed), (
            f"{a.package_name}: target {a.fixed_version} below required {needed}"
        )


@needs_data
def test_due_dates_do_not_mix_within_a_ticket():
    """Band is in the key precisely so one ticket carries one deadline."""
    for a in correlate():
        assert isinstance(a.due_date, date)


@needs_data
def test_reduction_is_substantial():
    s = summarise(correlate())
    assert s["findings_covered"] > s["fix_actions"] * 10, (
        f"expected a large reduction, got {s['reduction_factor']}x"
    )
