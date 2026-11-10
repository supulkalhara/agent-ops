"""
Tests for the enforcement primitives (rate limiting, spend ledger).
"""

import pytest

from aetherwall.domain.enforcement import (
    RateLimiter,
    SpendLedger,
    parse_rate_limit,
)


class TestParseRateLimit:
    @pytest.mark.parametrize(
        "spec,expected",
        [
            ("100_requests_per_minute", (100, 60)),
            ("50_requests_per_minute", (50, 60)),
            ("1000_calls_per_hour", (1000, 3600)),
            ("10_requests_per_second", (10, 1)),
        ],
    )
    def test_valid_specs(self, spec: str, expected: tuple[int, int]) -> None:
        assert parse_rate_limit(spec) == expected

    @pytest.mark.parametrize(
        "spec",
        ["unlimited", "", "garbage_spec", "100_per", "abc_requests_per_minute"],
    )
    def test_invalid_specs_default_to_no_limit(self, spec: str) -> None:
        assert parse_rate_limit(spec) == (0, 0)


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_within_allowance_passes(self) -> None:
        limiter = RateLimiter()
        for _ in range(5):
            assert await limiter.check("agent-1", 5, 60) is True

    @pytest.mark.asyncio
    async def test_exceeds_allowance(self) -> None:
        limiter = RateLimiter()
        for _ in range(3):
            await limiter.check("agent-1", 3, 60)
        assert await limiter.check("agent-1", 3, 60) is False

    @pytest.mark.asyncio
    async def test_agents_are_isolated(self) -> None:
        limiter = RateLimiter()
        await limiter.check("agent-1", 1, 60)
        assert await limiter.check("agent-1", 1, 60) is False
        # Another agent has its own window
        assert await limiter.check("agent-2", 1, 60) is True

    @pytest.mark.asyncio
    async def test_no_limit_configured(self) -> None:
        limiter = RateLimiter()
        for _ in range(100):
            assert await limiter.check("agent-1", 0, 0) is True


class TestSpendLedger:
    @pytest.mark.asyncio
    async def test_amount_extraction(self) -> None:
        assert SpendLedger.extract_amount({"amount_usd": 42.5}) == 42.5
        assert SpendLedger.extract_amount({"transaction_value": 100}) == 100.0
        assert SpendLedger.extract_amount({"other": 1}) is None
        assert SpendLedger.extract_amount({"amount_usd": "bad"}) is None

    @pytest.mark.asyncio
    async def test_transaction_within_daily_limit(self) -> None:
        ledger = SpendLedger()
        assert await ledger.check_transaction("a", 100.0, 500.0) is True
        await ledger.record("a", 100.0)
        # cumulative 100 + 150 <= 500
        assert await ledger.check_transaction("a", 150.0, 500.0) is True
        await ledger.record("a", 150.0)
        # cumulative 250 + 300 > 500
        assert await ledger.check_transaction("a", 300.0, 500.0) is False

    @pytest.mark.asyncio
    async def test_no_daily_limit(self) -> None:
        ledger = SpendLedger()
        assert await ledger.check_transaction("a", 1e9, None) is True
