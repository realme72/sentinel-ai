"""Rolling-window rate limiters.

A semaphore caps *concurrency*, not *rate*: with fast responses it sails
straight past a published quota. These track completion timestamps and wait
until the oldest leaves the window, which is what a "30 requests per minute"
limit actually means.

Both a sync and an async variant, because the NVD enrichment is asyncio and
the planner runs inside synchronous LangGraph nodes.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque


class RollingWindowLimiter:
    """Async: allow at most `limit` acquisitions per `window` seconds."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._times: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._times and now - self._times[0] >= self.window:
                    self._times.popleft()
                if len(self._times) < self.limit:
                    self._times.append(now)
                    return
                await asyncio.sleep(self.window - (now - self._times[0]) + 0.05)


class SyncRollingWindowLimiter:
    """Thread-safe synchronous counterpart.

    Tracks tokens as well as requests: hosted free tiers usually cap both, and
    tokens-per-minute is the binding constraint for this workload (roughly
    1,450 tokens per plan means a 6k TPM quota allows ~4 requests/min, far
    below the 30/min request limit).
    """

    def __init__(self, *, requests: int, window: float,
                 tokens: int | None = None) -> None:
        self.requests = requests
        self.window = window
        self.tokens = tokens
        self._req: deque[float] = deque()
        self._tok: deque[tuple[float, int]] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._req and now - self._req[0] >= self.window:
            self._req.popleft()
        while self._tok and now - self._tok[0][0] >= self.window:
            self._tok.popleft()

    def acquire(self, estimated_tokens: int = 0) -> float:
        """Block until a slot is free. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._prune(now)
                req_ok = len(self._req) < self.requests
                tok_ok = (
                    self.tokens is None
                    or sum(t for _, t in self._tok) + estimated_tokens <= self.tokens
                )
                if req_ok and tok_ok:
                    self._req.append(now)
                    if estimated_tokens:
                        self._tok.append((now, estimated_tokens))
                    return waited

                oldest = min(
                    [self._req[0]] if self._req else [],
                    default=now,
                ) if req_ok else (self._req[0] if self._req else now)
                if not tok_ok and self._tok:
                    oldest = min(oldest, self._tok[0][0])
                sleep_for = max(self.window - (now - oldest) + 0.05, 0.05)

            time.sleep(sleep_for)
            waited += sleep_for

    def record_actual(self, tokens: int) -> None:
        """Replace the estimate for the most recent call with the real count.

        Only correct for providers that bill what they produced. Where
        `max_tokens` is charged as a reservation (Groq), calling this with
        actual usage under-reports consumption and the limiter over-admits --
        leave the reservation in place instead.
        """
        with self._lock:
            if self._tok:
                ts, _ = self._tok.pop()
                self._tok.append((ts, tokens))
