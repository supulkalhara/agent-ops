"""
Runtime enforcement primitives for resource-based guardrails.

These are deliberately in-memory and single-node: they implement the
campaign allowances (rate limits, spend caps) without external
infrastructure. For multi-node deployments swap in a Redis-backed
implementation exposing the same interface.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

# ── Rate-limit spec parsing ───────────────────────────────────────────

_RATE_TOKENS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


def parse_rate_limit(spec: str) -> tuple[int, int]:
    """
    Parse a rate-limit spec of the form ``<n>_<unit>(s)_per_<unit>``.

    Supported forms (the unit used in `agentops.yaml` uses underscores):
      • ``100_requests_per_minute``   → (100, 60)
      • ``50_calls_per_hour``         → (50, 3600)

    Returns (max_events, window_seconds). Unparseable specs fall back
    to (0, 0), meaning "no limit enforced".
    """
    try:
        parts = spec.strip().replace("-", "_").split("_")
        if "per" not in parts:
            return (0, 0)
        per_idx = parts.index("per")
        count = int(parts[0])
        # Determine the window unit: the last token before 'per' that
        # also appears after it, e.g. per_minute
        window_token = parts[per_idx + 1].rstrip("s")
        window = _RATE_TOKENS.get(window_token)
        if window is None:
            return (0, 0)
        return (count, window)
    except (ValueError, IndexError):
        return (0, 0)


# ── Sliding-window rate limiter ───────────────────────────────────────


class RateLimiter:
    """
    Per-agent sliding-window rate limiter.

    Stateless across restarts by design — a restart resets the window,
    which is the safe direction (allowance is re-budgeted, never carry-over).
    """

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(
        self, agent_id: str, max_events: int, window_seconds: int
    ) -> bool:
        """
        Record an event for the agent and return True if it is within
        its allowance. Returns False when the sliding window is full.
        """
        if max_events <= 0 or window_seconds <= 0:
            return True  # no limit configured

        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            events = self._events[agent_id]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= max_events:
                return False
            events.append(now)
            return True


# ── Daily spend ledger ────────────────────────────────────────────────


class SpendLedger:
    """
    Tracks cumulative spend per agent per UTC day.

    ``check_transaction`` returns False when adding ``amount`` would
    exceed the agent's daily cap; ``record`` {\bf commits} the spend
    after the request is routed. Amounts reported directly on the
    request metadata (``amount_usd``) are used as the unit of account.
    """

    def __init__(self) -> None:
        self._spent: dict[tuple[str, str], float] = defaultdict(float)
        self._lock = asyncio.Lock()

    @staticmethod
    def _day_key() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _key(self, agent_id: str) -> tuple[str, str]:
        return (agent_id, self._day_key())

    async def get_day_total(self, agent_id: str) -> float:
        async with self._lock:
            return self._spent.get(self._key(agent_id), 0.0)

    async def check_transaction(
        self,
        agent_id: str,
        amount: float,
        daily_limit: float | None,
    ) -> bool:
        """Return True if this transaction fits within the daily cap."""
        if daily_limit is None:
            return True
        async with self._lock:
            current = self._spent.get(self._key(agent_id), 0.0)
            return current + amount <= daily_limit

    async def record(self, agent_id: str, amount: float) -> None:
        """Commit spend against the agent's day-total."""
        async with self._lock:
            self._spent[self._key(agent_id)] += amount

    @classmethod
    def extract_amount(cls, metadata: dict[str, Any]) -> float | None:
        """
        Extract a transaction value (USD) from request metadata.
        Looks for ``amount_usd`` or ``transaction_value``.
        """
        for key in ("amount_usd", "transaction_value"):
            value = metadata.get(key)
            if value is None:
                continue
            try:
                return max(0.0, float(value))
            except (TypeError, ValueError):
                continue
        return None
