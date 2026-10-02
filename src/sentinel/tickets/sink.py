"""The TicketSink contract.

A Protocol, as with VectorStore: GitHub and Jira are swappable, and a `memory`
sink lets the whole ticketing path be tested without touching anyone's tracker.

Idempotency is owned locally, not by the sink. `tickets.idempotency_key` is
UNIQUE in Postgres, so "have we filed this?" is a primary-key lookup rather
than a remote search -- which is cheaper, works when the tracker is down, and
cannot double-file because two runs raced a search API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Protocol, runtime_checkable

# Hidden marker carried in the issue body so a ticket can be re-identified
# even if someone renames it.
MARKER_PREFIX = "sentinel-key:"


@dataclass
class Ticket:
    idempotency_key: str
    title: str
    body: str
    owner_team: str
    owner_email: str
    risk_band: str
    due_date: date
    labels: list[str] = field(default_factory=list)


@dataclass
class TicketRef:
    external_id: str
    external_url: str
    created: bool          # False when an existing ticket was updated
    sink: str
    state: str = "open"


@runtime_checkable
class TicketSink(Protocol):
    name: str

    def ensure_ready(self) -> None:
        """Create labels/projects if needed. Idempotent."""

    def upsert(self, ticket: Ticket, *, external_id: str | None = None) -> TicketRef:
        """Create the ticket, or update it when `external_id` is supplied."""

    def close(self, external_id: str, *, comment: str | None = None) -> None:
        """Close a ticket whose findings are all remediated."""


def marker(key: str) -> str:
    return f"<!-- {MARKER_PREFIX}{key} -->"
