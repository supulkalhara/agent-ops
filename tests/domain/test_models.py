"""Tests for core domain models."""

import pytest
from pydantic import ValidationError

from agent_ops.domain.models import (
    ActionDecision,
    AgentRequest,
    GatewayResponse,
    SecurityAnalysis,
    ValidationResult,
)


class TestAgentRequest:
    """Tests for the AgentRequest model."""

    def test_minimal_creation(self) -> None:
        req = AgentRequest(agent_id="a-1", destination="api.internal", payload="hello")
        assert req.agent_id == "a-1"
        assert req.destination == "api.internal"
        assert req.payload == "hello"
        assert req.metadata == {}
        assert req.request_id  # auto-generated UUID
        assert req.timestamp is not None

    def test_unique_request_ids(self) -> None:
        r1 = AgentRequest(agent_id="a", destination="d", payload="p")
        r2 = AgentRequest(agent_id="a", destination="d", payload="p")
        assert r1.request_id != r2.request_id

    def test_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            AgentRequest(agent_id="a")  # type: ignore[call-arg]

    def test_metadata_populated(self) -> None:
        req = AgentRequest(
            agent_id="a",
            destination="d",
            payload="p",
            metadata={"key": "value", "nested": {"a": 1}},
        )
        assert req.metadata["key"] == "value"
        assert req.metadata["nested"]["a"] == 1


class TestSecurityAnalysis:
    """Tests for the SecurityAnalysis model."""

    def test_safe_analysis(self) -> None:
        sa = SecurityAnalysis(is_safe=True, confidence_score=0.99)
        assert sa.is_safe is True
        assert sa.confidence_score == 0.99
        assert sa.flags == []
        assert sa.redacted_payload is None

    def test_unsafe_analysis_with_flags(self) -> None:
        sa = SecurityAnalysis(
            is_safe=False,
            confidence_score=0.95,
            flags=["prompt_injection", "pii_detected"],
            redacted_payload="[REDACTED] payload",
        )
        assert not sa.is_safe
        assert len(sa.flags) == 2
        assert sa.redacted_payload == "[REDACTED] payload"

    def test_confidence_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            SecurityAnalysis(is_safe=True, confidence_score=1.5)
        with pytest.raises(ValidationError):
            SecurityAnalysis(is_safe=True, confidence_score=-0.1)


class TestValidationResult:
    """Tests for the ValidationResult model."""

    def test_allow_decision(self) -> None:
        vr = ValidationResult(decision=ActionDecision.ALLOW, reasoning="safe payload")
        assert vr.decision == ActionDecision.ALLOW
        assert vr.modified_payload is None

    def test_deny_decision(self) -> None:
        vr = ValidationResult(decision=ActionDecision.DENY, reasoning="malicious")
        assert vr.decision == ActionDecision.DENY

    def test_redact_with_modified_payload(self) -> None:
        vr = ValidationResult(
            decision=ActionDecision.REDACT,
            reasoning="PII found",
            modified_payload="sanitized",
        )
        assert vr.modified_payload == "sanitized"


class TestGatewayResponse:
    """Tests for the GatewayResponse model."""

    def test_minimal_response(self) -> None:
        gr = GatewayResponse(
            decision=ActionDecision.ALLOW,
            reasoning="all clear",
        )
        assert gr.route_result is None
        assert gr.security_analysis is None

    def test_full_response(self) -> None:
        analysis = SecurityAnalysis(is_safe=True, confidence_score=0.99)
        gr = GatewayResponse(
            decision=ActionDecision.ALLOW,
            reasoning="council approved",
            route_result={"status": "routed", "latency_ms": 12},
            security_analysis=analysis,
        )
        assert gr.route_result["status"] == "routed"
        assert gr.security_analysis is not None
        assert gr.security_analysis.is_safe


class TestActionDecision:
    """Tests for the ActionDecision enum."""

    def test_enum_values(self) -> None:
        assert ActionDecision.ALLOW.value == "allow"
        assert ActionDecision.DENY.value == "deny"
        assert ActionDecision.REDACT.value == "redact"
        assert ActionDecision.ESCALATE.value == "escalate"

    def test_string_comparison(self) -> None:
        assert ActionDecision.ALLOW == "allow"
        assert ActionDecision.DENY == "deny"
