"""In-memory sink.

Not a stub for convenience: it is what lets the ticketing path run in CI and
in tests without creating issues in anyone's tracker. A system that files
outward-facing artefacts needs a mode where it provably files nothing.
"""

from __future__ import annotations

import itertools

from sentinel.tickets.sink import Ticket, TicketRef


class MemorySink:
    name = "memory"

    def __init__(self) -> None:
        self.tickets: dict[str, Ticket] = {}
        self.closed: list[str] = []
        self._ids = itertools.count(1)
        self._by_key: dict[str, str] = {}

    def ensure_ready(self) -> None:
        return None

    def upsert(self, ticket: Ticket, *, external_id: str | None = None) -> TicketRef:
        existing = external_id or self._by_key.get(ticket.idempotency_key)
        if existing:
            self.tickets[existing] = ticket
            return TicketRef(existing, f"memory://{existing}", False, self.name)
        new_id = str(next(self._ids))
        self.tickets[new_id] = ticket
        self._by_key[ticket.idempotency_key] = new_id
        return TicketRef(new_id, f"memory://{new_id}", True, self.name)

    def close(self, external_id: str, *, comment: str | None = None) -> None:
        self.closed.append(external_id)
