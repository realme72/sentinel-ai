"""Jira Cloud sink.

Same three operations as GitHub behind the same Protocol. Jira differs in two
ways that matter: issues carry a typed `duedate` field (so the SLA date lands
somewhere Jira can report on, rather than only in the body), and labels cannot
contain spaces or colons -- so the shared label set is rewritten.
"""

from __future__ import annotations

import httpx
import structlog

from sentinel.config import get_settings
from sentinel.tickets.sink import Ticket, TicketRef

log = structlog.get_logger()

_PRIORITY = {"critical": "Highest", "high": "High",
             "medium": "Medium", "low": "Low"}


def _jira_label(label: str) -> str:
    return label.replace(":", "-").replace(" ", "-")


class JiraSink:
    name = "jira"

    def __init__(self, url: str | None = None, email: str | None = None,
                 token: str | None = None, project: str | None = None) -> None:
        s = get_settings()
        self.url = (url or s.jira_url or "").rstrip("/")
        self.email = email or s.jira_email
        self.token = token or s.jira_token
        self.project = project or s.jira_project
        missing = [n for n, v in (("SENTINEL_JIRA_URL", self.url),
                                  ("SENTINEL_JIRA_EMAIL", self.email),
                                  ("SENTINEL_JIRA_TOKEN", self.token),
                                  ("SENTINEL_JIRA_PROJECT", self.project)) if not v]
        if missing:
            raise RuntimeError(f"Jira sink not configured: missing {', '.join(missing)}")

        self.client = httpx.Client(
            base_url=f"{self.url}/rest/api/3",
            auth=(self.email, self.token),
            headers={"Accept": "application/json"},
            timeout=30,
        )

    def ensure_ready(self) -> None:
        r = self.client.get(f"/project/{self.project}")
        r.raise_for_status()

    def _fields(self, ticket: Ticket) -> dict:
        return {
            "project": {"key": self.project},
            "summary": ticket.title[:255],
            # Jira Cloud v3 takes Atlassian Document Format, not markdown.
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": ticket.body}]}],
            },
            "issuetype": {"name": "Task"},
            "labels": [_jira_label(x) for x in ticket.labels],
            # The typed field, so Jira can report and alert on the SLA date
            # rather than it living only inside the body text.
            "duedate": ticket.due_date.isoformat(),
            "priority": {"name": _PRIORITY.get(ticket.risk_band, "Medium")},
        }

    def upsert(self, ticket: Ticket, *, external_id: str | None = None) -> TicketRef:
        if external_id:
            r = self.client.put(f"/issue/{external_id}",
                                json={"fields": self._fields(ticket)})
            r.raise_for_status()
            return TicketRef(external_id,
                             f"{self.url}/browse/{external_id}", False, self.name)

        r = self.client.post("/issue", json={"fields": self._fields(ticket)})
        r.raise_for_status()
        key = r.json()["key"]
        log.info("jira.issue_created", key=key)
        return TicketRef(key, f"{self.url}/browse/{key}", True, self.name)

    def close(self, external_id: str, *, comment: str | None = None) -> None:
        if comment:
            self.client.post(f"/issue/{external_id}/comment", json={
                "body": {"type": "doc", "version": 1,
                         "content": [{"type": "paragraph",
                                      "content": [{"type": "text", "text": comment}]}]},
            })
        # Transition ids are per-workflow, so the target is resolved by name.
        r = self.client.get(f"/issue/{external_id}/transitions")
        r.raise_for_status()
        wanted = {"done", "closed", "resolved"}
        for t in r.json().get("transitions", []):
            if t["name"].strip().lower() in wanted:
                self.client.post(f"/issue/{external_id}/transitions",
                                 json={"transition": {"id": t["id"]}})
                return
        log.warning("jira.no_close_transition", issue=external_id)
