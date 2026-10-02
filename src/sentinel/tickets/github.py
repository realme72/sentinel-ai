"""GitHub Issues sink.

Uses the REST API over httpx rather than a client library: the surface needed
here is three endpoints, and the token resolution (env var, then the `gh` CLI's
stored credential) is the part worth being explicit about.
"""

from __future__ import annotations

import os
import subprocess

import httpx
import structlog

from sentinel.config import get_settings
from sentinel.tickets.sink import Ticket, TicketRef

log = structlog.get_logger()

API = "https://api.github.com"


def resolve_token() -> str | None:
    """GITHUB_TOKEN, else whatever `gh auth` already holds.

    Reusing the gh credential means local runs need no second token, and the
    failure mode when neither exists is explicit rather than a 401 later.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True,
                             text=True, timeout=10)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


class GitHubSink:
    name = "github"

    def __init__(self, repo: str | None = None, token: str | None = None) -> None:
        settings = get_settings()
        self.repo = repo or settings.github_repo
        self.token = token or resolve_token()
        if not self.token:
            raise RuntimeError(
                "no GitHub token: set GITHUB_TOKEN or run `gh auth login`"
            )
        self.client = httpx.Client(
            base_url=f"{API}/repos/{self.repo}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )

    def ensure_ready(self) -> None:
        """Create the labels Sentinel applies, so issues are filterable.

        GitHub creates issues with unknown labels silently dropped, so an
        absent label means a lost filter rather than an error.
        """
        wanted = {
            "sentinel": "0e8a16",
            "sev:critical": "b60205", "sev:high": "d93f0b",
            "sev:medium": "fbca04", "sev:low": "c5def5",
            "kev": "5319e7", "no-fix-available": "000000",
            "internet-facing": "e99695",
        }
        existing = {lbl["name"] for lbl in self._paged("/labels")}
        for name, color in wanted.items():
            if name not in existing:
                r = self.client.post("/labels", json={"name": name, "color": color})
                if r.status_code not in (201, 422):   # 422 = already exists
                    log.warning("github.label_failed", label=name,
                                status=r.status_code, body=r.text[:200])

    def _paged(self, path: str, **params) -> list[dict]:
        out, page = [], 1
        while True:
            r = self.client.get(path, params={**params, "per_page": 100, "page": page})
            r.raise_for_status()
            batch = r.json()
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    def upsert(self, ticket: Ticket, *, external_id: str | None = None) -> TicketRef:
        payload = {
            "title": ticket.title,
            "body": ticket.body,
            "labels": ticket.labels,
        }
        if external_id:
            r = self.client.patch(f"/issues/{external_id}", json=payload)
            r.raise_for_status()
            data = r.json()
            return TicketRef(str(data["number"]), data["html_url"], False,
                             self.name, data["state"])

        r = self.client.post("/issues", json=payload)
        r.raise_for_status()
        data = r.json()
        log.info("github.issue_created", number=data["number"], url=data["html_url"])
        return TicketRef(str(data["number"]), data["html_url"], True,
                         self.name, data["state"])

    def close(self, external_id: str, *, comment: str | None = None) -> None:
        if comment:
            self.client.post(f"/issues/{external_id}/comments", json={"body": comment})
        r = self.client.patch(f"/issues/{external_id}",
                              json={"state": "closed", "state_reason": "completed"})
        r.raise_for_status()
