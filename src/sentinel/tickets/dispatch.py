"""Fix actions -> rendered tickets -> a sink, with local idempotency.

Filing a ticket is outward-facing and hard to undo at scale: 937 issues in
somebody's repo is not a mistake you quietly roll back. So `dry_run` defaults
to True everywhere and the caller has to ask for the real thing.

Idempotency lives in Postgres, not in the tracker. `tickets.idempotency_key`
is UNIQUE, so "already filed?" is a primary-key lookup -- cheaper than a
remote search, correct when the tracker is unreachable, and immune to two runs
racing a search API into filing duplicates.
"""

from __future__ import annotations

import time

import structlog

from sentinel.agents.correlate import FixAction
from sentinel.db.session import connection, query, query_one
from sentinel.tickets.render import render_ticket
from sentinel.tickets.sink import Ticket, TicketRef, TicketSink

log = structlog.get_logger()


def _existing(key: str) -> dict | None:
    return query_one(
        "SELECT id, external_id, external_url, state, sink "
        "FROM tickets WHERE idempotency_key = %s",
        (key,),
    )


def _plan_for_action(action: FixAction) -> tuple[str | None, bool, int | None]:
    """Look up a cached remediation plan for this package upgrade.

    Only a grounded plan is attached to a ticket. An ungrounded one is stored
    for inspection but must never reach the person who will act on it.
    """
    row = query_one(
        """
        SELECT id, plan_markdown, grounding_passed
        FROM remediation_plans
        WHERE package_name = %s
          AND fixed_version IS NOT DISTINCT FROM %s
          AND cve_id = ANY(%s)
        ORDER BY grounding_passed DESC, created_at DESC
        LIMIT 1
        """,
        (action.package_name, action.fixed_version, action.cve_ids),
    )
    if not row:
        return None, False, None
    return row["plan_markdown"], row["grounding_passed"], row["id"]


def _record(action: FixAction, ticket: Ticket, ref: TicketRef,
            plan_id: int | None) -> int:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tickets (idempotency_key, sink, external_id, external_url,
                                 title, body, owner_team, owner_email, risk_band,
                                 due_date, state, plan_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (idempotency_key) DO UPDATE SET
                external_id = EXCLUDED.external_id,
                external_url = EXCLUDED.external_url,
                title = EXCLUDED.title,
                body = EXCLUDED.body,
                due_date = EXCLUDED.due_date,
                state = EXCLUDED.state,
                plan_id = EXCLUDED.plan_id,
                updated_at = now()
            RETURNING id
            """,
            (ticket.idempotency_key, ref.sink, ref.external_id, ref.external_url,
             ticket.title, ticket.body, ticket.owner_team, ticket.owner_email,
             ticket.risk_band, ticket.due_date, ref.state, plan_id),
        )
        ticket_id = cur.fetchone()["id"]
        # Link the covered findings so a later run can tell when every finding
        # on a ticket is remediated and the ticket can be closed.
        cur.executemany(
            "INSERT INTO ticket_findings (ticket_id, finding_id) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            [(ticket_id, fid) for fid in action.finding_ids],
        )
    return ticket_id


def dispatch(
    actions: list[FixAction],
    sink: TicketSink,
    *,
    dry_run: bool = True,
    limit: int | None = None,
) -> dict:
    """Render and file tickets for `actions`.

    With dry_run=True nothing is sent anywhere and nothing is written to the
    tickets table -- the result reports what *would* happen.
    """
    t0 = time.perf_counter()
    if limit:
        actions = actions[:limit]

    created = updated = skipped = 0
    results: list[dict] = []

    if not dry_run:
        sink.ensure_ready()

    for action in actions:
        plan_md, grounded, plan_id = _plan_for_action(action)
        ticket = render_ticket(action, plan_markdown=plan_md if grounded else None,
                               plan_grounded=grounded)
        prior = _existing(ticket.idempotency_key)

        if dry_run:
            results.append({
                "title": ticket.title, "team": action.owner_team,
                "due": str(action.due_date), "findings": len(action.finding_ids),
                "would": "update" if prior else "create",
                "has_grounded_plan": grounded,
            })
            skipped += 1
            continue

        ref = sink.upsert(ticket, external_id=prior["external_id"] if prior else None)
        _record(action, ticket, ref, plan_id)
        created += int(ref.created)
        updated += int(not ref.created)
        results.append({"title": ticket.title, "url": ref.external_url,
                        "created": ref.created})

    out = {
        "sink": sink.name, "dry_run": dry_run,
        "actions": len(actions), "created": created, "updated": updated,
        "previewed": skipped,
        "with_grounded_plan": sum(1 for r in results if r.get("has_grounded_plan")),
        "seconds": round(time.perf_counter() - t0, 2),
        "results": results,
    }
    log.info("tickets.dispatched", **{k: v for k, v in out.items() if k != "results"})
    return out


def close_remediated(sink: TicketSink, *, dry_run: bool = True) -> dict:
    """Close tickets whose every covered finding is no longer open."""
    rows = query(
        """
        SELECT t.id, t.external_id, t.title,
               count(f.id) FILTER (WHERE f.status = 'open') AS still_open,
               count(f.id) AS total
        FROM tickets t
        JOIN ticket_findings tf ON tf.ticket_id = t.id
        JOIN findings f ON f.id = tf.finding_id
        WHERE t.state = 'open' AND t.external_id IS NOT NULL
        GROUP BY t.id, t.external_id, t.title
        HAVING count(f.id) FILTER (WHERE f.status = 'open') = 0
        """
    )
    if not dry_run:
        for r in rows:
            sink.close(r["external_id"],
                       comment=f"All {r['total']} covered findings are remediated. "
                               f"Closed automatically by Sentinel-AI.")
            with connection() as conn:
                conn.execute(
                    "UPDATE tickets SET state='closed', updated_at=now() WHERE id=%s",
                    (r["id"],),
                )
    return {"closable": len(rows), "dry_run": dry_run,
            "titles": [r["title"] for r in rows[:5]]}
