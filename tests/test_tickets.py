"""Ticket rendering, sinks, and the dry-run guarantee.

Filing is outward-facing: 937 issues in somebody's repo is not a mistake you
quietly roll back. The tests that matter most here are the ones proving
nothing is sent unless asked.
"""

from datetime import date

import pytest

from sentinel.agents.correlate import FixAction
from sentinel.tickets.memory import MemorySink
from sentinel.tickets.render import render_body, render_ticket
from sentinel.tickets.sink import MARKER_PREFIX, TicketSink, marker


def action(**over) -> FixAction:
    base = dict(
        owner_team="infra", owner_email="infra@example.com",
        package_name="org.apache.logging.log4j:log4j-core",
        fixed_version="2.25.4", risk_band="critical", due_date=date(2026, 10, 3),
        max_risk_score=96.0, asset_count=10, internet_facing_count=1, prod_count=3,
        cve_ids=["CVE-2021-44228", "CVE-2021-45046"],
        kev_cve_ids=["CVE-2021-44228"],
        finding_ids=list(range(20)),
        hostnames=[f"api-prod-{i:03d}" for i in range(10)],
        os_family="debian", environments=["prod"], max_epss=0.99999,
        version_requirements={"CVE-2021-44228": "2.15.0", "CVE-2021-45046": "2.16.0"},
    )
    base.update(over)
    return FixAction(**base)


# --- rendering -------------------------------------------------------------


def test_body_leads_with_the_action_not_the_vulnerability():
    body = render_body(action())
    first = [ln for ln in body.splitlines() if ln.strip() and not ln.startswith("<!--")][0]
    assert "**Action**" in first
    assert "2.25.4" in first


def test_body_explains_why_the_target_exceeds_any_single_cve():
    """The target is the highest across the package, so a reader who looks up
    CVE-2021-44228 and sees '2.15.0' needs to know why they are being asked
    for 2.25.4."""
    body = render_body(action())
    assert "2.15.0" in body and "2.16.0" in body, "per-CVE minimums must be shown"
    assert "highest version required" in body
    assert "pinned to an older branch" in body


def test_body_justifies_the_priority_with_evidence():
    body = render_body(action())
    assert "Known Exploited Vulnerabilities" in body
    assert "internet-facing" in body
    assert "100.00%" in body or "99.99" in body


def test_body_states_the_due_date_is_not_model_authored():
    """The audit claim, visible to whoever receives the ticket."""
    assert "not by a language model" in render_body(action())


def test_hostnames_are_truncated_rather_than_dumped():
    body = render_body(action(asset_count=400,
                              hostnames=[f"h{i:03d}" for i in range(200)]))
    assert "and 388 more" in body


def test_no_fix_case_asks_for_a_compensating_control():
    body = render_body(action(fixed_version=None, version_requirements={}))
    assert "no fixed version is published" in body.lower()
    assert "compensating control" in body


def test_ungrounded_plan_is_labelled_when_attached():
    body = render_body(action(), plan_markdown="do the thing", plan_grounded=False)
    assert "ungrounded" in body and "review before acting" in body


def test_marker_is_embedded_for_reidentification():
    a = action()
    body = render_body(a)
    assert marker(a.idempotency_key) in body
    assert MARKER_PREFIX in body


def test_labels_carry_the_routing_signals():
    labels = render_ticket(action()).labels
    assert "sentinel" in labels
    assert "sev:critical" in labels
    assert "kev" in labels
    assert "internet-facing" in labels
    assert "team:infra" in labels
    assert "no-fix-available" not in labels
    assert "no-fix-available" in render_ticket(action(fixed_version=None)).labels


# --- the memory sink -------------------------------------------------------


def test_memory_sink_satisfies_the_protocol():
    assert isinstance(MemorySink(), TicketSink)


def test_memory_sink_creates_then_updates_by_key():
    sink = MemorySink()
    tk = render_ticket(action())
    first = sink.upsert(tk)
    assert first.created is True
    second = sink.upsert(tk)
    assert second.created is False
    assert second.external_id == first.external_id
    assert len(sink.tickets) == 1


def test_memory_sink_updates_when_given_an_external_id():
    """The real path: the id comes from Postgres, not from the sink's own
    memory, so a fresh sink instance must still update."""
    tk = render_ticket(action())
    sink = MemorySink()
    sink.upsert(tk)
    fresh = MemorySink()                      # no internal state
    ref = fresh.upsert(tk, external_id="1")
    assert ref.created is False
    assert ref.external_id == "1"


# --- the dry-run guarantee -------------------------------------------------


def test_dry_run_sends_nothing_and_writes_nothing(monkeypatch):
    from sentinel.tickets import dispatch as D

    monkeypatch.setattr(D, "query_one", lambda *a, **k: None)
    recorded = []
    monkeypatch.setattr(D, "_record", lambda *a, **k: recorded.append(1))

    class ExplodingSink:
        name = "exploding"
        def ensure_ready(self):
            raise AssertionError("dry run must not prepare a sink")
        def upsert(self, *a, **k):
            raise AssertionError("dry run must not send anything")
        def close(self, *a, **k):
            raise AssertionError("dry run must not close anything")

    out = D.dispatch([action(), action(risk_band="high")], ExplodingSink())
    assert out["dry_run"] is True
    assert out["created"] == 0 and out["updated"] == 0
    assert out["previewed"] == 2
    assert recorded == [], "dry run must not touch the tickets table"


def test_dry_run_reports_create_versus_update(monkeypatch):
    from sentinel.tickets import dispatch as D
    monkeypatch.setattr(D, "query_one",
                        lambda sql, p=None: {"external_id": "7", "external_url": "u",
                                             "state": "open", "sink": "github", "id": 1}
                        if "FROM tickets" in sql else None)
    out = D.dispatch([action()], MemorySink())
    assert out["results"][0]["would"] == "update"


def test_only_grounded_plans_are_attached(monkeypatch):
    """An ungrounded plan is kept for inspection but must not reach the person
    who will act on the ticket."""
    from sentinel.tickets import dispatch as D

    def q(sql, p=None):
        if "FROM remediation_plans" in sql:
            return {"id": 3, "plan_markdown": "UPGRADE TO 9.9.9",
                    "grounding_passed": False}
        return None

    monkeypatch.setattr(D, "query_one", q)
    monkeypatch.setattr(D, "_record", lambda *a, **k: 1)
    sink = MemorySink()
    out = D.dispatch([action()], sink, dry_run=False)
    assert out["created"] == 1
    filed = next(iter(sink.tickets.values()))
    assert "9.9.9" not in filed.body, "ungrounded plan text must not be filed"
    # The plan text must not have been rendered into the ticket.
    assert out["with_grounded_plan"] == 0


@pytest.mark.parametrize("band,label", [
    ("critical", "sev:critical"), ("high", "sev:high"),
    ("medium", "sev:medium"), ("low", "sev:low"),
])
def test_every_band_maps_to_a_label(band, label):
    assert label in render_ticket(action(risk_band=band)).labels
