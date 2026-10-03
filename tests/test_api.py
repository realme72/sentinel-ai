"""API contract tests.

These run against the live development database, so they skip when it is
empty (CI has migrations but no data). What they assert is the *contract* --
response shape, filters, and the read-only guarantee -- not specific numbers,
which change with every rescan.
"""

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import app
from sentinel.db.session import query_one

client = TestClient(app)

_has_data = (query_one("SELECT count(*) AS n FROM risk_assessments WHERE is_current")
             or {"n": 0})["n"] > 0
needs_data = pytest.mark.skipif(not _has_data, reason="no scored findings")


# --- meta ------------------------------------------------------------------


def test_health_reports_component_state():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded"}
    assert isinstance(body["postgres"], bool)
    assert isinstance(body["qdrant"], bool), "qdrant is optional, not fatal"


def test_health_names_the_applied_migration():
    """Knowing which revision is live is the first question when an API and a
    database disagree."""
    assert client.get("/health").json()["migration"]


@needs_data
def test_stats_skips_correlation_unless_asked():
    assert client.get("/stats").json()["fix_actions"] is None
    r = client.get("/stats", params={"include_fix_actions": True}).json()
    assert r["fix_actions"] > 0


# --- findings --------------------------------------------------------------


@needs_data
def test_findings_are_returned_most_urgent_first():
    rows = client.get("/findings", params={"limit": 20}).json()
    scores = [r["risk_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)


@needs_data
@pytest.mark.parametrize("sort", ["risk", "due_date", "epss"])
def test_every_sort_mode_works(sort):
    r = client.get("/findings", params={"sort": sort, "limit": 5})
    assert r.status_code == 200 and r.json()


@needs_data
def test_filters_narrow_the_result_set():
    all_rows = client.get("/findings", params={"limit": 100}).json()
    crit = client.get("/findings", params={"band": "critical", "limit": 100}).json()
    assert all(r["risk_band"] == "critical" for r in crit)
    assert len(crit) <= len(all_rows)

    kev = client.get("/findings", params={"kev_only": True, "limit": 50}).json()
    assert all(r["kev_listed"] for r in kev)

    inet = client.get("/findings",
                      params={"internet_facing": True, "limit": 50}).json()
    assert all(r["internet_facing"] for r in inet)


@needs_data
def test_finding_exposes_its_risk_arithmetic():
    """An owner disputing a due date must be able to see the inputs."""
    fid = client.get("/findings", params={"limit": 1}).json()[0]["finding_id"]
    body = client.get(f"/findings/{fid}/factors").json()
    assert body["finding_id"] == fid
    assert body["policy_version"]
    comps = body["factors"]["components"]
    assert set(comps) == {"severity", "exploit", "exposure", "asset"}
    # The score must be reconstructible from the published factors.
    assert sum(c["points"] for c in comps.values()) == pytest.approx(
        body["risk_score"], abs=0.01)


def test_unknown_finding_is_a_404():
    assert client.get("/findings/999999999/factors").status_code == 404


# --- cves ------------------------------------------------------------------


@needs_data
def test_cve_lookup_is_case_insensitive():
    a = client.get("/cves/CVE-2021-44228")
    b = client.get("/cves/cve-2021-44228")
    assert a.status_code == b.status_code == 200
    assert a.json()["cve_id"] == b.json()["cve_id"]


@needs_data
def test_cve_includes_exploitation_signals():
    body = client.get("/cves/CVE-2021-44228").json()
    assert body["kev_listed"] is True
    assert body["epss_score"] > 0.9
    assert body["affected_assets"] > 0
    assert body["cwe_ids"]


def test_unknown_cve_is_a_404():
    assert client.get("/cves/CVE-1999-00000").status_code == 404


# --- fix actions -----------------------------------------------------------


@needs_data
def test_fix_actions_collapse_many_findings():
    """The unit a human acts on is the upgrade, not the finding."""
    actions = client.get("/fix-actions", params={"limit": 25}).json()
    assert actions
    assert sum(a["finding_count"] for a in actions) > len(actions)
    for a in actions:
        assert a["idempotency_key"] and a["title"]
        assert a["os_family"], "a ticket spanning packaging systems is not one ticket"


@needs_data
def test_fix_action_band_filter():
    actions = client.get("/fix-actions",
                         params={"band": "critical", "limit": 10}).json()
    assert all(a["risk_band"] == "critical" for a in actions)


# --- retrieval -------------------------------------------------------------


@needs_data
def test_search_returns_fused_ranks():
    body = client.get("/search", params={"q": "CVE-2021-44228", "k": 5}).json()
    assert body["prefilter_cves"] == ["CVE-2021-44228"]
    assert body["hits"]
    assert all(h["cve_ids"] == ["CVE-2021-44228"] for h in body["hits"]), (
        "the prefilter must make a wrong-CVE result structurally impossible")
    assert any(h["lexical_rank"] for h in body["hits"])


@needs_data
def test_search_exposes_the_dense_only_failure():
    """Documented behaviour, not a bug: dense-only retrieval for a bare CVE id
    returns the wrong CVE, which is why hybrid + prefilter exists."""
    dense = client.get("/search", params={
        "q": "CVE-2021-44228", "mode": "dense", "prefilter": False, "k": 3
    }).json()
    assert dense["hits"], "dense search still returns something -- just not the right thing"


@needs_data
def test_search_rejects_a_too_short_query():
    assert client.get("/search", params={"q": "x"}).status_code == 422


# --- the read-only guarantee ----------------------------------------------


def test_api_exposes_no_write_endpoints():
    """Scanning, scoring, planning and ticket filing are CLI/worker concerns
    with their own safety gates. An HTTP surface that could file 1,705 tickets
    is a liability, not a feature."""
    verbs = set()
    for route in app.routes:
        if hasattr(route, "methods"):
            verbs |= (route.methods - {"HEAD", "OPTIONS"})
    assert verbs == {"GET"}, f"unexpected write verbs exposed: {verbs - {'GET'}}"


@needs_data
@pytest.mark.parametrize("param,value", [
    ("band", "high"), ("team", "infra"), ("environment", "prod"),
    ("internet_facing", True), ("kev_only", True), ("overdue_only", True),
    ("package", "openssl"), ("cve_id", "CVE-2021-44228"),
])
def test_every_filter_is_queryable(param, value):
    """v_current_risk and assets share column names (hostname, owner_team,
    internet_facing, environment), so an unqualified filter is an
    AmbiguousColumn error that only appears when that filter is used."""
    r = client.get("/findings", params={param: value, "limit": 5})
    assert r.status_code == 200, r.text[:200]


# --- dashboard -------------------------------------------------------------


def test_dashboard_is_served_at_the_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "Sentinel-AI" in r.text
    assert "/static/app.js" in r.text


def test_static_assets_are_mounted():
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert "renderTourStep" in r.text


@needs_data
def test_band_distribution_is_ordered_by_severity():
    """The dashboard renders this straight into a chart, so the API owns the
    ordering rather than leaving it to client-side sorting."""
    rows = client.get("/stats/bands").json()
    order = [r["band"] for r in rows]
    expected = [b for b in ["critical", "high", "medium", "low"] if b in order]
    assert order == expected
    for r in rows:
        assert r["overdue"] <= r["findings"]
        assert r["kev"] <= r["findings"]


@needs_data
def test_backlog_buckets_are_chronological():
    rows = client.get("/stats/backlog", params={"weeks": 12}).json()
    weeks = [r["week"] for r in rows]
    assert weeks == sorted(weeks)
    for r in rows:
        assert r["urgent"] <= r["findings"]


def test_backlog_window_is_bounded():
    """A dashboard must not be able to ask for an unbounded scan."""
    assert client.get("/stats/backlog", params={"weeks": 0}).status_code == 422
    assert client.get("/stats/backlog", params={"weeks": 999}).status_code == 422


@needs_data
def test_chart_endpoints_stay_cheap():
    """These aggregate 103k rows; the dashboard calls them on every page load,
    so they must not degrade into a client-side scan."""
    import time
    for path in ("/stats/bands", "/stats/backlog"):
        t0 = time.perf_counter()
        assert client.get(path).status_code == 200
        assert time.perf_counter() - t0 < 3.0, f"{path} too slow for a page load"
