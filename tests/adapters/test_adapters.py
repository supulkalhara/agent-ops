"""
Tests for concrete adapter implementations.

All tests use httpx mocking or test doubles — no real external services.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agent_ops.adapters.apisix_router import APISIXRouter
from agent_ops.adapters.llm_guard_verifier import LLMGuardVerifier
from agent_ops.adapters.qdrant_logger import (
    QdrantAuditLogger,
    _payload_to_vector,
)
from agent_ops.domain.models import (
    ActionDecision,
    AgentRequest,
    GatewayResponse,
    SecurityAnalysis,
    ValidationResult,
)

# ── Fixtures ──────────────────────────────────────────────────────────


def _make_request(
    payload: str = "hello world",
) -> AgentRequest:
    return AgentRequest(
        agent_id="test-agent",
        destination="api.example.com",
        payload=payload,
    )


# ── LLM Guard Verifier Tests ─────────────────────────────────────────


class TestLLMGuardVerifier:
    """Tests for the LLM Guard adapter."""

    @pytest.mark.asyncio
    async def test_safe_payload(self) -> None:
        """Safe payload returns is_safe=True with no flags."""
        verifier = LLMGuardVerifier(api_url="http://test:8080")

        mock_response = httpx.Response(
            200,
            json={
                "is_valid": True,
                "sanitized_prompt": "hello world",
                "results": [],
            },
            request=httpx.Request("POST", "http://test:8080/analyze/prompt"),
        )

        with patch.object(
            verifier._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await verifier.verify_payload(_make_request())

        assert result.is_safe is True
        assert result.flags == []
        assert result.confidence_score == 0.0
        assert result.redacted_payload is None

    @pytest.mark.asyncio
    async def test_unsafe_payload_with_flags(self) -> None:
        """Unsafe payload returns flags and risk score."""
        verifier = LLMGuardVerifier(api_url="http://test:8080")

        mock_response = httpx.Response(
            200,
            json={
                "is_valid": False,
                "sanitized_prompt": "[REDACTED]",
                "results": [
                    {
                        "scanner_name": "PromptInjection",
                        "risk_score": 0.95,
                        "is_detected": True,
                    },
                    {
                        "scanner_name": "Toxicity",
                        "risk_score": 0.3,
                        "is_detected": False,
                    },
                ],
            },
            request=httpx.Request("POST", "http://test:8080/analyze/prompt"),
        )

        with patch.object(
            verifier._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await verifier.verify_payload(_make_request())

        assert result.is_safe is False
        assert "prompt_injection" in result.flags
        assert "toxicity" not in result.flags  # not detected
        assert result.confidence_score == 0.95
        assert result.redacted_payload == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_http_error_fails_closed(self) -> None:
        """HTTP errors should fail closed (unsafe)."""
        verifier = LLMGuardVerifier(api_url="http://test:8080")

        mock_response = httpx.Response(
            500,
            text="Internal Server Error",
            request=httpx.Request("POST", "http://test:8080/analyze/prompt"),
        )

        with patch.object(
            verifier._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await verifier.verify_payload(_make_request())

        assert result.is_safe is False
        assert "llm_guard_error" in result.flags
        assert result.confidence_score == 1.0

    @pytest.mark.asyncio
    async def test_connection_error_fails_closed(self) -> None:
        """Connection errors should fail closed."""
        verifier = LLMGuardVerifier(api_url="http://test:8080")

        with patch.object(
            verifier._client,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("refused"),
        ):
            result = await verifier.verify_payload(_make_request())

        assert result.is_safe is False
        assert "llm_guard_unreachable" in result.flags

    @pytest.mark.asyncio
    async def test_no_redaction_when_same_payload(self) -> None:
        """No redacted_payload when sanitised == original."""
        verifier = LLMGuardVerifier(api_url="http://test:8080")

        mock_response = httpx.Response(
            200,
            json={
                "is_valid": True,
                "sanitized_prompt": "hello world",
                "results": [],
            },
            request=httpx.Request("POST", "http://test:8080/analyze/prompt"),
        )

        with patch.object(
            verifier._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await verifier.verify_payload(_make_request())

        assert result.redacted_payload is None


# ── APISIX Router Tests ───────────────────────────────────────────────


class TestAPISIXRouter:
    """Tests for the APISIX router adapter."""

    @pytest.mark.asyncio
    async def test_route_request_success(self) -> None:
        """Successful routing returns status and destination."""
        router = APISIXRouter(proxy_url="http://test:9080")
        req = _make_request()
        val = ValidationResult(
            decision=ActionDecision.ALLOW, reasoning="ok"
        )

        mock_response = httpx.Response(
            200,
            json={"result": "ok"},
            request=httpx.Request(
                "POST",
                f"http://test:9080/{req.destination}",
            ),
        )

        with patch.object(
            router._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await router.route_request(req, val)

        assert result["status"] == "routed"
        assert result["destination"] == "api.example.com"
        assert result["status_code"] == 200

    @pytest.mark.asyncio
    async def test_route_request_attaches_headers(self) -> None:
        """Verify AgentOps headers are sent."""
        router = APISIXRouter(proxy_url="http://test:9080")
        req = _make_request()
        val = ValidationResult(
            decision=ActionDecision.ALLOW, reasoning="ok"
        )

        captured_kwargs: dict = {}

        async def capture_post(
            *args: object, **kwargs: object
        ) -> httpx.Response:
            captured_kwargs.update(kwargs)
            return httpx.Response(
                200,
                json={},
                request=httpx.Request(
                    "POST", "http://test:9080/api.example.com"
                ),
            )

        with patch.object(
            router._client, "post", side_effect=capture_post
        ):
            await router.route_request(req, val)

        headers = captured_kwargs.get("headers", {})
        assert headers["X-AgentOps-Agent-ID"] == "test-agent"
        assert headers["X-AgentOps-Decision"] == "allow"
        assert "X-AgentOps-Request-ID" in headers

    @pytest.mark.asyncio
    async def test_block_request_logs(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Block request should log the event."""
        router = APISIXRouter()
        req = _make_request()

        with caplog.at_level(logging.WARNING):
            await router.block_request(req, "test reason")

        assert "BLOCKED" in caplog.text
        assert "test reason" in caplog.text


# ── Qdrant Audit Logger Tests ─────────────────────────────────────────


class TestQdrantAuditLogger:
    """Tests for the Qdrant audit logger adapter."""

    def test_payload_to_vector_deterministic(self) -> None:
        """Same input produces identical vector."""
        v1 = _payload_to_vector("hello world")
        v2 = _payload_to_vector("hello world")
        assert v1 == v2
        assert len(v1) == 48

    def test_payload_to_vector_different_inputs(self) -> None:
        """Different inputs produce different vectors."""
        v1 = _payload_to_vector("hello")
        v2 = _payload_to_vector("world")
        assert v1 != v2

    @pytest.mark.asyncio
    async def test_log_decision(self) -> None:
        """Test logging a decision to Qdrant."""
        audit = QdrantAuditLogger(
            host="test", port=6333, collection_name="test_audit"
        )

        # Mock the Qdrant client
        mock_client = AsyncMock()
        audit._client = mock_client

        response = GatewayResponse(
            decision=ActionDecision.ALLOW,
            reasoning="all clear",
            security_analysis=SecurityAnalysis(
                is_safe=True,
                confidence_score=0.1,
                flags=[],
            ),
        )

        point_id = await audit.log_decision(
            request_id="req-123",
            agent_id="agent-01",
            destination="api.example.com",
            payload="test payload",
            response=response,
        )

        assert point_id  # UUID returned
        mock_client.upsert.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_collection_creates_if_missing(self) -> None:
        """Collection should be created if it doesn't exist."""
        audit = QdrantAuditLogger(
            host="test", port=6333, collection_name="new_collection"
        )

        mock_client = AsyncMock()
        mock_collections = MagicMock()
        mock_collections.collections = []
        mock_client.get_collections.return_value = mock_collections
        audit._client = mock_client

        await audit.ensure_collection()

        mock_client.create_collection.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_collection_skips_existing(self) -> None:
        """Collection should not be recreated if it exists."""
        audit = QdrantAuditLogger(
            host="test", port=6333, collection_name="existing"
        )

        mock_client = AsyncMock()
        mock_collection = MagicMock()
        mock_collection.name = "existing"
        mock_collections = MagicMock()
        mock_collections.collections = [mock_collection]
        mock_client.get_collections.return_value = mock_collections
        audit._client = mock_client

        await audit.ensure_collection()

        mock_client.create_collection.assert_not_called()
