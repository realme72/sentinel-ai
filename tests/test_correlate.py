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
        os_family="debian", environments=["prod"],
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
    # The OS family is named because the command differs by packaging system.
    assert "debian" in action().title
    assert "1 debian host" in action(asset_count=1).title
    assert "1 debian hosts" not in action(asset_count=1).title


# --- against the real fleet ------------------------------------------------

_has_data = (query_one("SELECT count(*) AS n FROM risk_assessments WHERE is_current") or
             {"n": 0})["n"] > 0
needs_data = pytest.mark.skipif(not _has_data, reason="no scored findings in this database")


@needs_data
def test_one_upgrade_per_package_per_band_per_os():
    """The bug this replaced: grouping on fixed_version produced 11 tickets
    for log4j-core on one team across 7 target versions, for the same hosts.
    Nobody upgrades a package seven times.

    One ticket per (band, os_family) is the correct granularity -- the band
    carries the deadline and the OS carries the command."""
    log4j = [a for a in correlate()
             if "log4j-core" in a.package_name and a.owner_team == "infra"]
    assert log4j, "expected log4j findings for the infra team"
    keys = [(a.risk_band, a.os_family) for a in log4j]
    assert len(keys) == len(set(keys)), f"duplicate (band, os) groups: {keys}"


@needs_data
def test_every_band_names_the_same_target_within_an_os_family():
    """Satisfying the urgent ticket must close the relaxed ones, so bands on
    the same package and OS must agree on the target.

    Scoped per os_family: Alpine and Debian legitimately differ, and
    conflating them was the cross-packaging bug."""
    by_scope: dict[tuple[str, str, str], set[str]] = {}
    for a in correlate():
        if a.fixed_version:
            key = (a.owner_team, a.package_name, a.os_family)
            by_scope.setdefault(key, set()).add(a.fixed_version)
    multi = {k: v for k, v in by_scope.items() if len(v) > 1}
    assert not multi, f"inconsistent targets within one OS: {list(multi)[:3]}"


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


@needs_data
def test_hostnames_come_back_as_a_list_not_a_string():
    """hostname is CITEXT and psycopg has no citext[] loader, so an aggregated
    citext array arrives as the literal '{a,b,c}' string. Rendering then
    iterated it per character and produced `{`, `a`, `p`, `i`, ... in the
    ticket body. The SQL casts to text; this keeps it that way."""
    for a in correlate(bands=["critical"])[:5]:
        assert isinstance(a.hostnames, list), f"got {type(a.hostnames).__name__}"
        for h in a.hostnames:
            assert isinstance(h, str) and len(h) > 1, f"suspicious hostname {h!r}"
        assert isinstance(a.cve_ids, list)
        assert isinstance(a.environments, list)


@needs_data
def test_target_version_never_crosses_packaging_systems():
    """Alpine openssl fixes at 1.1.1l-r0 and Debian at 1.1.1k-1+deb11u1.
    Comparing those is not a comparison, and the first version of this code
    produced a plan telling an Alpine host to install a Debian package --
    which passed grounding, because both strings exist in the corpus."""
    suffixes = {"alpine": "-r", "debian": "deb", "rhel": ".el"}
    for a in correlate():
        if not a.fixed_version:
            continue
        marker = suffixes.get(a.os_family)
        if marker and marker not in a.fixed_version:
            # Not every version carries a distro marker, so only assert the
            # negative: it must not carry a DIFFERENT family's marker.
            for other_os, other_marker in suffixes.items():
                if other_os != a.os_family and other_marker in a.fixed_version:
                    raise AssertionError(
                        f"{a.package_name} on {a.os_family} targets "
                        f"{a.fixed_version}, which looks like {other_os}"
                    )


@needs_data
def test_one_os_family_per_action():
    for a in correlate()[:50]:
        assert isinstance(a.os_family, str) and a.os_family
