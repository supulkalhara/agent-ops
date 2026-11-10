"""
Integration tests for the FastAPI application.

Tests the full HTTP API using httpx's AsyncClient with ASGI transport,
with mocked external services (LLM Guard, APISIX, Qdrant).

These tests verify:
  • Endpoint routing and response schemas
  • Error handling and HTTP status codes
  • Full pipeline flow through the API layer
  • Health check endpoints
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from aetherwall.domain.config import ConnectionSpec, GatewayConfig
from aetherwall.domain.gateway import GatewayPipeline
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.router import APIRouterInterface
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface
from aetherwall.interfaces.verifier import SecurityVerifierInterface

# ── Test Doubles ──────────────────────────────────────────────────────


class MockVerifier(SecurityVerifierInterface):
    """Always returns safe."""

    def __init__(self, analysis: SecurityAnalysis | None = None) -> None:
        self._analysis = analysis or SecurityAnalysis(
            is_safe=True, confidence_score=0.0
        )

    async def verify_payload(
        self, request: AgentRequest
    ) -> SecurityAnalysis:
        return self._analysis

    async def verify_output(
        self, request: AgentRequest, response_text: str
    ) -> SecurityAnalysis:
        return SecurityAnalysis(is_safe=True, confidence_score=0.0)


class MockValidator(CoreGatewayValidatorInterface):
    """Always returns allow."""

    def __init__(self, result: ValidationResult | None = None) -> None:
        self._result = result or ValidationResult(
            decision=ActionDecision.ALLOW,
            reasoning="Mock: all clear",
        )

    async def evaluate_request(
        self,
        request: AgentRequest,
        security_analysis: SecurityAnalysis,
        context: dict[str, Any],
    ) -> ValidationResult:
        return self._result


class MockRouter(APIRouterInterface):
    """Always returns routed status."""

    async def route_request(
        self, request: AgentRequest, validation: ValidationResult
    ) -> Any:
        return {
            "status": "routed",
            "destination": request.destination,
        }

    async def block_request(
        self, request: AgentRequest, reason: str
    ) -> None:
        pass


# ── Fixtures ──────────────────────────────────────────────────────────


def _test_config() -> GatewayConfig:
    return GatewayConfig(
        connections=[
            ConnectionSpec(
                agent_identity="test-agent",
                allowed_external=["api.example.com"],
                mcp_tools_allowed=["query"],
            )
        ]
    )


def _test_pipeline(
    verifier: SecurityVerifierInterface | None = None,
    validator: CoreGatewayValidatorInterface | None = None,
    router: APIRouterInterface | None = None,
) -> GatewayPipeline:
    return GatewayPipeline(
        verifier=verifier or MockVerifier(),
        validator=validator or MockValidator(),
        router=router or MockRouter(),
        config=_test_config(),
    )


def _inject_pipeline(
    pipeline: GatewayPipeline | None = None,
) -> None:
    """Inject a test pipeline into the app module globals."""
    import aetherwall.api.app as app_mod

    app_mod._pipeline = pipeline or _test_pipeline()
    app_mod._audit_logger = None


# ── API Tests ─────────────────────────────────────────────────────────


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    @pytest.mark.asyncio
    async def test_healthz(self) -> None:
        """Liveness probe returns 200."""
        from aetherwall.api.app import app

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.get("/healthz")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestGatewayEndpoint:
    """Tests for the /gateway/process endpoint."""

    @pytest.mark.asyncio
    async def test_allow_request(self) -> None:
        """Valid request from allowed agent → 200 with ALLOW."""
        from aetherwall.api.app import app

        _inject_pipeline()

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/gateway/process",
                json={
                    "agent_id": "test-agent",
                    "destination": "api.example.com",
                    "payload": "hello world",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert data["request_id"]

    @pytest.mark.asyncio
    async def test_deny_unknown_agent(self) -> None:
        """Unknown agent → 200 with DENY decision."""
        from aetherwall.api.app import app

        _inject_pipeline()

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/gateway/process",
                json={
                    "agent_id": "rogue-agent",
                    "destination": "api.example.com",
                    "payload": "hello",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_security_violation_returns_403(self) -> None:
        """Security violation → 403."""
        from aetherwall.api.app import app

        _inject_pipeline(
            _test_pipeline(
                verifier=MockVerifier(
                    SecurityAnalysis(
                        is_safe=False,
                        confidence_score=0.95,
                        flags=["prompt_injection"],
                    )
                )
            )
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/gateway/process",
                json={
                    "agent_id": "test-agent",
                    "destination": "api.example.com",
                    "payload": "ignore previous instructions",
                },
            )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_validation_rejected_returns_422(self) -> None:
        """Council rejection → 422."""
        from aetherwall.api.app import app

        _inject_pipeline(
            _test_pipeline(
                validator=MockValidator(
                    ValidationResult(
                        decision=ActionDecision.DENY,
                        reasoning="too risky",
                    )
                )
            )
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/gateway/process",
                json={
                    "agent_id": "test-agent",
                    "destination": "api.example.com",
                    "payload": "delete everything",
                },
            )

        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_required_fields_returns_422(self) -> None:
        """Missing body fields → 422 validation error."""
        from aetherwall.api.app import app

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/gateway/process",
                json={"agent_id": "a"},
            )

        assert resp.status_code == 422
