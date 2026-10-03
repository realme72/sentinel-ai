"""Collapse findings into fix actions -- the thing that makes the output usable.

A scanner produces one finding per (host, package, CVE). Filing one ticket
each would mean 103,166 tickets for this fleet, which is how vulnerability
programmes get ignored: the queue is unreadable, so nobody reads it.

But one `apt-get install curl=7.74.0-1.3+deb11u2` closes 15 CVEs on a host.
The unit a human acts on is the *upgrade*, not the finding.

Grouping key: (owner_team, package, os_family, risk_band, has_fix). Measured:

    per finding                      103,166
    per (host, package, fix)          24,890
    per (team, package, fix, band)     3,718
    per (team, package, band, fix?)      937
    + os_family                        1,705   <- 60x reduction, and correct

Two decisions, each forced by the data.

**risk_band is in the key.** 84% of (team, package, fix) groups mix bands,
with due dates spanning up to 87 days. One ticket cannot carry a 3-day
deadline for a critical host and a 90-day one for forty low-risk hosts.

**fixed_version is NOT in the key.** Grouping on it fragmented one upgrade
into many tickets: log4j-core on the `infra` team produced 11 tickets across
7 target versions for the same ~10 hosts, because each CVE names the release
that first fixed it. Nobody upgrades a package seven times.

**os_family IS in the key**, which the first version missed. Version strings
are not comparable across packaging systems: Alpine openssl fixes at
`1.1.1l-r0` and Debian at `1.1.1k-1+deb11u1`, and taking a max across those
namespaces is meaningless. It produced a plan telling an Alpine host to
install a Debian package, which passed grounding because both strings exist
somewhere in the corpus. 28 packages in this fleet span families, and the
remediation commands differ too (`apk` vs `apt-get`), so they are genuinely
different pieces of work.

So the target is the highest fixed version required across the whole
(team, package) scope -- which is safe for every member, since it is at or
above each individual requirement -- while the deadline stays per band. The
critical ticket and the medium ticket then name the SAME target version with
different dates, so satisfying the urgent one closes the relaxed one too.

This stage is entirely deterministic. The model's job comes later: writing the
remediation narrative for a group, not deciding what belongs in it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date

import structlog

from sentinel.db.session import query
from sentinel.ingest.versions import version_key

log = structlog.get_logger()

# Hosts named inline in a ticket body before it becomes a wall of text; the
# rest are summarised by count and attached as a list.
HOSTNAMES_INLINE = 12


@dataclass
class FixAction:
    owner_team: str
    owner_email: str
    package_name: str
    # The highest version required across this (team, package) -- not merely
    # the one this band's CVEs demand. Upgrading once must satisfy all of them.
    fixed_version: str | None
    risk_band: str
    # Single family, not a list: a ticket spanning packaging systems cannot
    # name one target version or one command.
    os_family: str
    due_date: date
    max_risk_score: float
    asset_count: int
    internet_facing_count: int
    prod_count: int
    cve_ids: list[str]
    kev_cve_ids: list[str]
    finding_ids: list[int]
    hostnames: list[str]
    environments: list[str]
    max_epss: float | None = None
    # The rollback target. Without it the planner writes `<previous_version>`
    # for a fact it was already given.
    installed_version: str | None = None
    # Per-CVE minimum requirements, so a plan can explain why the target is
    # higher than any single CVE demands, and serve a team pinned to an
    # older branch.
    version_requirements: dict[str, str] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    @property
    def idempotency_key(self) -> str:
        """Stable across runs so a re-scan updates a ticket instead of filing
        a second one.

        Deliberately excludes the asset list: hosts join and leave the group
        as the fleet changes, and that is an *update* to the same campaign,
        not a new one.
        """
        # Excludes fixed_version as well: the target rises as new CVEs land
        # on the same package, and that is an update to the same campaign.
        basis = "|".join([
            self.owner_team, self.package_name, self.os_family, self.risk_band,
            "fix" if self.fixed_version else "nofix",
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:32]

    @property
    def title(self) -> str:
        target = f" to {self.fixed_version}" if self.fixed_version else " (no fix available)"
        scope = f"{self.asset_count} {self.os_family} host" + (
            "s" if self.asset_count != 1 else "")
        return (f"[{self.risk_band.upper()}] Upgrade {self.package_name}{target} "
                f"on {scope}")

    @property
    def has_fix(self) -> bool:
        return self.fixed_version is not None


_GROUP_SQL = """
SELECT v.owner_team, v.owner_email, v.package_name, a.os_family, v.risk_band,
       (v.fixed_version IS NOT NULL)                   AS has_fix,
       min(v.due_date)                                 AS due_date,
       max(v.risk_score)                               AS max_risk_score,
       count(DISTINCT v.asset_id)                      AS asset_count,
       count(DISTINCT v.asset_id) FILTER (WHERE v.internet_facing) AS internet_facing_count,
       count(DISTINCT v.asset_id) FILTER (WHERE v.environment = 'prod') AS prod_count,
       array_agg(DISTINCT v.cve_id ORDER BY v.cve_id)   AS cve_ids,
       array_remove(array_agg(DISTINCT CASE WHEN v.kev_listed THEN v.cve_id END), NULL)
                                                       AS kev_cve_ids,
       array_agg(DISTINCT v.finding_id)                 AS finding_ids,
       (array_agg(DISTINCT v.hostname::text ORDER BY v.hostname::text))[1:200] AS hostnames,
       array_agg(DISTINCT v.environment)                AS environments,
       max(v.epss_score)                                AS max_epss,
       (array_agg(DISTINCT v.installed_version))[1]      AS installed_version,
       array_agg(DISTINCT v.cve_id || '=' || COALESCE(v.fixed_version, '')) AS cve_fix_pairs
FROM v_current_risk v
JOIN assets a ON a.id = v.asset_id
WHERE v.status = 'open' %(extra_where)s
GROUP BY v.owner_team, v.owner_email, v.package_name, a.os_family, v.risk_band,
         (v.fixed_version IS NOT NULL)
ORDER BY max(v.risk_score) DESC, min(v.due_date) ASC
"""

# Highest fixed version per (team, package, os_family). Scoped to one
# packaging system, because comparing an Alpine version to a Debian one is
# not a comparison.
_PACKAGE_TARGET_SQL = """
SELECT v.owner_team, v.package_name, a.os_family,
       array_remove(array_agg(DISTINCT v.fixed_version), NULL) AS versions
FROM v_current_risk v
JOIN assets a ON a.id = v.asset_id
WHERE v.status = 'open' AND v.fixed_version IS NOT NULL
GROUP BY v.owner_team, v.package_name, a.os_family
"""


def correlate(
    *,
    bands: list[str] | None = None,
    teams: list[str] | None = None,
    limit: int | None = None,
) -> list[FixAction]:
    """Group open findings into fix actions, most urgent first."""
    clauses, params = [], {}
    if bands:
        clauses.append("AND v.risk_band = ANY(%(bands)s)")
        params["bands"] = bands
    if teams:
        clauses.append("AND v.owner_team = ANY(%(teams)s)")
        params["teams"] = teams

    sql = _GROUP_SQL % {"extra_where": " ".join(clauses)}
    if limit:
        sql += f" LIMIT {int(limit)}"

    rows = query(sql, params or None)

    # Highest required version per (team, package), computed with version
    # ordering rather than string ordering -- 2.9.10 must beat 2.9.8.
    targets: dict[tuple[str, str, str], str] = {}
    for r in query(_PACKAGE_TARGET_SQL):
        versions = r["versions"] or []
        if versions:
            key = (r["owner_team"], r["package_name"], r["os_family"])
            targets[key] = max(versions, key=version_key)

    actions: list[FixAction] = []
    for r in rows:
        requirements = {}
        for pair in r["cve_fix_pairs"] or []:
            cve, _, ver = pair.partition("=")
            if ver:
                requirements[cve] = ver

        actions.append(FixAction(
            owner_team=r["owner_team"],
            owner_email=r["owner_email"],
            package_name=r["package_name"],
            fixed_version=(targets.get((r["owner_team"], r["package_name"],
                                        r["os_family"]))
                           if r["has_fix"] else None),
            risk_band=r["risk_band"],
            os_family=r["os_family"],
            due_date=r["due_date"],
            max_risk_score=float(r["max_risk_score"]),
            asset_count=r["asset_count"],
            internet_facing_count=r["internet_facing_count"],
            prod_count=r["prod_count"],
            cve_ids=r["cve_ids"] or [],
            kev_cve_ids=r["kev_cve_ids"] or [],
            finding_ids=r["finding_ids"] or [],
            hostnames=r["hostnames"] or [],
            environments=sorted(r["environments"] or []),
            max_epss=float(r["max_epss"]) if r["max_epss"] is not None else None,
            installed_version=r.get("installed_version"),
            version_requirements=requirements,
        ))

    log.info("correlate.done", fix_actions=len(actions),
             findings=sum(len(a.finding_ids) for a in actions))
    return actions


def summarise(actions: list[FixAction]) -> dict:
    total_findings = sum(len(a.finding_ids) for a in actions)
    by_band: dict[str, int] = {}
    for a in actions:
        by_band[a.risk_band] = by_band.get(a.risk_band, 0) + 1
    return {
        "fix_actions": len(actions),
        "findings_covered": total_findings,
        "reduction_factor": round(total_findings / max(len(actions), 1), 1),
        "by_band": dict(sorted(by_band.items())),
        "without_fix": sum(1 for a in actions if not a.has_fix),
        "touching_internet_facing": sum(1 for a in actions if a.internet_facing_count),
    }
