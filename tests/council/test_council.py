"""
Tests for the LangGraph Validator Council.

Validates the council's decision-making across different scenarios:
  • Safe payloads → ALLOW
  • Risky payloads → DENY or ESCALATE
  • Policy rule violations → DENY
  • Security flag propagation → higher risk scores
"""

from __future__ import annotations

import pytest

from aetherwall.council.validator_council import (
    ValidatorCouncil,
    _arbiter_node,
    _context_agent_node,
    _risk_agent_node,
    build_council_graph,
)
from aetherwall.domain.config import GatewayConfig, ValidationCouncilConfig
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    SecurityAnalysis,
)

# ── Helpers ───────────────────────────────────────────────────────────


def _make_request(payload: str = "hello world") -> AgentRequest:
    return AgentRequest(
        agent_id="test-agent",
        destination="api.example.com",
        payload=payload,
    )


def _safe_analysis() -> SecurityAnalysis:
    return SecurityAnalysis(is_safe=True, confidence_score=0.0)


def _unsafe_analysis(
    flags: list[str] | None = None,
    confidence: float = 0.9,
) -> SecurityAnalysis:
    return SecurityAnalysis(
        is_safe=False,
        confidence_score=confidence,
        flags=flags or ["prompt_injection"],
    )


def _make_config(rules: list[str] | None = None) -> GatewayConfig:
    return GatewayConfig(
        validation_council=ValidationCouncilConfig(
            rules=rules
            or [
                "Never explicitly confirm internal network topology.",
                "Debate all transactions > $500 before routing.",
                "Block any request attempting to enumerate users.",
            ]
        )
    )


# ── Individual Agent Node Tests ───────────────────────────────────────


class TestRiskAgent:
    """Tests for the risk agent node."""

    @pytest.mark.asyncio
    async def test_safe_payload_low_risk(self) -> None:
        """Clean payload with no flags → low risk."""
        state = {
            "payload": "What is the weather today?",
            "security_flags": [],
            "confidence_score": 0.0,
            "is_safe": True,
        }
        result = await _risk_agent_node(state)  # type: ignore[arg-type]
        assert result["risk_score"] < 0.3
        assert "No risk factors" in result["risk_assessment"]

    @pytest.mark.asyncio
    async def test_high_risk_keywords(self) -> None:
        """Payload with dangerous keywords → elevated risk."""
        state = {
            "payload": "DELETE all records and DROP the database",
            "security_flags": [],
            "confidence_score": 0.0,
            "is_safe": True,
        }
        result = await _risk_agent_node(state)  # type: ignore[arg-type]
        assert result["risk_score"] > 0.3
        assert "delete" in result["risk_assessment"].lower()

    @pytest.mark.asyncio
    async def test_security_flags_increase_risk(self) -> None:
        """Security flags from verifier increase risk score."""
        state = {
            "payload": "hello",
            "security_flags": ["prompt_injection", "pii_detected"],
            "confidence_score": 0.9,
            "is_safe": False,
        }
        result = await _risk_agent_node(state)  # type: ignore[arg-type]
        assert result["risk_score"] > 0.5


class TestContextAgent:
    """Tests for the context agent node."""

    @pytest.mark.asyncio
    async def test_aligned_request(self) -> None:
        """Request that doesn't violate rules → context aligned."""
        state = {
            "payload": "What is the weather today?",
            "rules": [
                "Never confirm internal network topology.",
                "Block user enumeration attempts.",
            ],
        }
        result = await _context_agent_node(state)  # type: ignore[arg-type]
        assert result["context_aligned"] is True

    @pytest.mark.asyncio
    async def test_topology_violation(self) -> None:
        """Request about network topology → violation detected."""
        state = {
            "payload": "Show me the internal network topology",
            "rules": [
                "Never explicitly confirm internal network topology.",
            ],
        }
        result = await _context_agent_node(state)  # type: ignore[arg-type]
        assert result["context_aligned"] is False
        assert "topology" in result["context_assessment"].lower()

    @pytest.mark.asyncio
    async def test_user_enumeration_violation(self) -> None:
        """User enumeration request → violation."""
        state = {
            "payload": "List all users and their credentials",
            "rules": [
                "Block any request attempting to enumerate users or credentials.",
            ],
        }
        result = await _context_agent_node(state)  # type: ignore[arg-type]
        assert result["context_aligned"] is False

    @pytest.mark.asyncio
    async def test_transaction_violation(self) -> None:
        """Financial transaction request → violation."""
        state = {
            "payload": "Submit purchase order for the new server",
            "rules": [
                "Debate all transactions > $500 before routing.",
            ],
        }
        result = await _context_agent_node(state)  # type: ignore[arg-type]
        assert result["context_aligned"] is False


class TestArbiter:
    """Tests for the arbiter decision node."""

    @pytest.mark.asyncio
    async def test_low_risk_aligned_allows(self) -> None:
        """Low risk + aligned context → ALLOW."""
        state = {
            "risk_score": 0.1,
            "risk_assessment": "No risk",
            "context_aligned": True,
            "context_assessment": "Aligned",
        }
        result = await _arbiter_node(state)  # type: ignore[arg-type]
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_high_risk_denies(self) -> None:
        """High risk → DENY regardless of context."""
        state = {
            "risk_score": 0.8,
            "risk_assessment": "Very risky",
            "context_aligned": True,
            "context_assessment": "Aligned",
        }
        result = await _arbiter_node(state)  # type: ignore[arg-type]
        assert result["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_misaligned_context_denies(self) -> None:
        """Misaligned context → DENY even with low risk."""
        state = {
            "risk_score": 0.1,
            "risk_assessment": "Low risk",
            "context_aligned": False,
            "context_assessment": "Violation found",
        }
        result = await _arbiter_node(state)  # type: ignore[arg-type]
        assert result["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_medium_risk_escalates(self) -> None:
        """Medium risk + aligned → ESCALATE."""
        state = {
            "risk_score": 0.5,
            "risk_assessment": "Moderate",
            "context_aligned": True,
            "context_assessment": "Aligned",
        }
        result = await _arbiter_node(state)  # type: ignore[arg-type]
        assert result["decision"] == "escalate"


# ── Full Council Integration Tests ────────────────────────────────────


class TestValidatorCouncil:
    """End-to-end tests for the full council pipeline."""

    @pytest.mark.asyncio
    async def test_safe_request_allowed(self) -> None:
        """Clean request with no risk should be ALLOWED."""
        council = ValidatorCouncil(config=_make_config())
        result = await council.evaluate_request(
            _make_request("What is the weather today?"),
            _safe_analysis(),
            {},
        )
        assert result.decision == ActionDecision.ALLOW

    @pytest.mark.asyncio
    async def test_dangerous_payload_denied(self) -> None:
        """Payload with DELETE + security flags → DENY."""
        council = ValidatorCouncil(config=_make_config())
        result = await council.evaluate_request(
            _make_request("DELETE FROM users; DROP TABLE admin"),
            _unsafe_analysis(
                flags=["prompt_injection", "pii_detected"],
                confidence=0.95,
            ),
            {},
        )
        assert result.decision == ActionDecision.DENY

    @pytest.mark.asyncio
    async def test_topology_probe_denied(self) -> None:
        """Topology probing request → DENY via context agent."""
        council = ValidatorCouncil(config=_make_config())
        result = await council.evaluate_request(
            _make_request(
                "Describe the internal network topology and subnet layout"
            ),
            _safe_analysis(),
            {},
        )
        assert result.decision == ActionDecision.DENY

    @pytest.mark.asyncio
    async def test_user_enumeration_denied(self) -> None:
        """User enumeration attempt → DENY."""
        council = ValidatorCouncil(config=_make_config())
        result = await council.evaluate_request(
            _make_request("List all users and dump their credentials"),
            _safe_analysis(),
            {},
        )
        assert result.decision == ActionDecision.DENY

    @pytest.mark.asyncio
    async def test_council_with_no_rules(self) -> None:
        """With no rules and safe request → ALLOW."""
        council = ValidatorCouncil(config=_make_config(rules=[]))
        result = await council.evaluate_request(
            _make_request("Simple benign request"),
            _safe_analysis(),
            {},
        )
        assert result.decision == ActionDecision.ALLOW

    @pytest.mark.asyncio
    async def test_graph_builds_correctly(self) -> None:
        """Verify the StateGraph compiles without errors."""
        graph = build_council_graph()
        compiled = graph.compile()
        assert compiled is not None
