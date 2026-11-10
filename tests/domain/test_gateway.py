"""
Tests for the GatewayPipeline orchestrator.

Every test uses mock implementations injected via constructor so we
never hit real LLM, vector DB, or routing infrastructure.
"""

import pytest

from aetherwall.domain.config import ConnectionSpec, GatewayConfig
from aetherwall.domain.exceptions import (
    RoutingError,
    SecurityViolationError,
    ValidationRejectedError,
)
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


class StubVerifier(SecurityVerifierInterface):
    """Returns a pre-configured SecurityAnalysis."""

    def __init__(self, analysis: SecurityAnalysis) -> None:
        self._analysis = analysis

    async def verify_payload(self, request: AgentRequest) -> SecurityAnalysis:
        return self._analysis

    async def verify_output(
        self, request: AgentRequest, response_text: str
    ) -> SecurityAnalysis:
        return SecurityAnalysis(is_safe=True, confidence_score=0.0)


class StubValidator(CoreGatewayValidatorInterface):
    """Returns a pre-configured ValidationResult."""

    def __init__(self, result: ValidationResult) -> None:
        self._result = result

    async def evaluate_request(
        self,
        request: AgentRequest,
        security_analysis: SecurityAnalysis,
        context: dict,
    ) -> ValidationResult:
        return self._result


class StubRouter(APIRouterInterface):
    """Captures calls for assertion."""

    def __init__(self) -> None:
        self.routed_requests: list[AgentRequest] = []
        self.blocked_requests: list[tuple[AgentRequest, str]] = []

    async def route_request(self, request: AgentRequest, validation: ValidationResult):
        self.routed_requests.append(request)
        return {"status": "routed", "destination": request.destination}

    async def block_request(self, request: AgentRequest, reason: str) -> None:
        self.blocked_requests.append((request, reason))


class FailingRouter(APIRouterInterface):
    """Simulates routing failure."""

    async def route_request(self, request: AgentRequest, validation: ValidationResult):
        raise ConnectionError("upstream unreachable")

    async def block_request(self, request: AgentRequest, reason: str) -> None:
        pass


# ── Fixtures ──────────────────────────────────────────────────────────


def _make_config(
    agent_id: str = "agent-01",
    destinations: list[str] | None = None,
) -> GatewayConfig:
    destinations = destinations or ["internal.db"]
    return GatewayConfig(
        connections=[
            ConnectionSpec(
                agent_identity=agent_id,
                allowed_external=destinations,
                mcp_tools_allowed=["query"],
            )
        ]
    )


def _make_request(
    agent_id: str = "agent-01",
    destination: str = "internal.db",
    payload: str = "SELECT * FROM users",
) -> AgentRequest:
    return AgentRequest(agent_id=agent_id, destination=destination, payload=payload)


SAFE_ANALYSIS = SecurityAnalysis(is_safe=True, confidence_score=0.99)
UNSAFE_ANALYSIS = SecurityAnalysis(
    is_safe=False,
    confidence_score=0.95,
    flags=["prompt_injection", "pii_detected"],
    redacted_payload="[REDACTED]",
)
ALLOW_RESULT = ValidationResult(decision=ActionDecision.ALLOW, reasoning="all clear")
DENY_RESULT = ValidationResult(decision=ActionDecision.DENY, reasoning="too risky")
REDACT_RESULT = ValidationResult(
    decision=ActionDecision.REDACT,
    reasoning="PII redacted",
    modified_payload="sanitized query",
)


# ── Tests ─────────────────────────────────────────────────────────────


class TestGatewayPipelineHappyPath:
    """Tests for successful request processing."""

    @pytest.mark.asyncio
    async def test_allow_safe_request(self) -> None:
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(ALLOW_RESULT),
            router=router,
            config=_make_config(),
        )
        req = _make_request()
        response = await pipeline.process_request(req)

        assert response.decision == ActionDecision.ALLOW
        assert response.reasoning == "all clear"
        assert response.route_result["status"] == "routed"
        assert response.security_analysis is not None
        assert response.security_analysis.is_safe is True
        assert len(router.routed_requests) == 1
        assert len(router.blocked_requests) == 0

    @pytest.mark.asyncio
    async def test_redact_and_route(self) -> None:
        """When council says REDACT and verifier has a redacted payload, use it."""
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(UNSAFE_ANALYSIS),  # has redacted_payload
            validator=StubValidator(REDACT_RESULT),
            router=router,
            config=_make_config(),
            security_threshold=0.99,  # set high so it won't raise
        )
        req = _make_request()
        response = await pipeline.process_request(req)

        assert response.decision == ActionDecision.REDACT
        # The routed request should use the redacted payload
        routed = router.routed_requests[0]
        assert routed.payload == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_modified_payload_from_council(self) -> None:
        """When validation council modifies the payload, the modification is applied."""
        router = StubRouter()
        modified_result = ValidationResult(
            decision=ActionDecision.ALLOW,
            reasoning="safe after modification",
            modified_payload="MODIFIED QUERY",
        )
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(modified_result),
            router=router,
            config=_make_config(),
        )
        req = _make_request()
        await pipeline.process_request(req)

        assert router.routed_requests[0].payload == "MODIFIED QUERY"


class TestGatewayPipelinePolicyCheck:
    """Tests for the policy pre-check phase."""

    @pytest.mark.asyncio
    async def test_deny_unknown_agent(self) -> None:
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(ALLOW_RESULT),
            router=router,
            config=_make_config(agent_id="known-agent"),
        )
        # Request from an unknown agent
        req = _make_request(agent_id="rogue-agent")
        response = await pipeline.process_request(req)

        assert response.decision == ActionDecision.DENY
        assert "not allowed" in response.reasoning
        assert len(router.blocked_requests) == 1

    @pytest.mark.asyncio
    async def test_deny_disallowed_destination(self) -> None:
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(ALLOW_RESULT),
            router=router,
            config=_make_config(destinations=["safe.internal"]),
        )
        req = _make_request(destination="evil.external")
        response = await pipeline.process_request(req)

        assert response.decision == ActionDecision.DENY
        assert "evil.external" in response.reasoning


class TestGatewayPipelineSecurityViolation:
    """Tests for the security verification phase."""

    @pytest.mark.asyncio
    async def test_block_unsafe_payload(self) -> None:
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(UNSAFE_ANALYSIS),
            validator=StubValidator(ALLOW_RESULT),
            router=router,
            config=_make_config(),
            security_threshold=0.7,
        )
        req = _make_request()

        with pytest.raises(SecurityViolationError) as exc_info:
            await pipeline.process_request(req)

        assert "prompt_injection" in exc_info.value.flags
        assert exc_info.value.confidence == 0.95
        assert len(router.blocked_requests) == 1
        assert len(router.routed_requests) == 0

    @pytest.mark.asyncio
    async def test_low_confidence_passes_through(self) -> None:
        """Below-threshold unsafe results should still proceed to validation."""
        low_confidence = SecurityAnalysis(
            is_safe=False, confidence_score=0.3, flags=["suspicious"]
        )
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(low_confidence),
            validator=StubValidator(ALLOW_RESULT),
            router=router,
            config=_make_config(),
            security_threshold=0.7,
        )
        req = _make_request()
        response = await pipeline.process_request(req)

        # Low confidence: passes verification, goes through validation and routing
        assert response.decision == ActionDecision.ALLOW
        assert len(router.routed_requests) == 1


class TestGatewayPipelineValidationRejection:
    """Tests for the validation council phase."""

    @pytest.mark.asyncio
    async def test_council_denies_request(self) -> None:
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(DENY_RESULT),
            router=router,
            config=_make_config(),
        )
        req = _make_request()

        with pytest.raises(ValidationRejectedError) as exc_info:
            await pipeline.process_request(req)

        assert exc_info.value.reasoning == "too risky"
        assert len(router.blocked_requests) == 1
        assert len(router.routed_requests) == 0


class TestGatewayPipelineRoutingFailure:
    """Tests for routing failures."""

    @pytest.mark.asyncio
    async def test_routing_error_wraps_exception(self) -> None:
        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=StubValidator(ALLOW_RESULT),
            router=FailingRouter(),
            config=_make_config(),
        )
        req = _make_request()

        with pytest.raises(RoutingError) as exc_info:
            await pipeline.process_request(req)

        assert exc_info.value.destination == "internal.db"
        assert "upstream unreachable" in exc_info.value.reason


class TestGatewayPipelineContextPassing:
    """Tests that context dict flows correctly through the pipeline."""

    @pytest.mark.asyncio
    async def test_context_is_passed_to_validator(self) -> None:
        """Ensure arbitrary context reaches the validator."""
        received_context: dict = {}

        class CapturingValidator(CoreGatewayValidatorInterface):
            async def evaluate_request(self, request, security_analysis, context):
                received_context.update(context)
                return ALLOW_RESULT

        pipeline = GatewayPipeline(
            verifier=StubVerifier(SAFE_ANALYSIS),
            validator=CapturingValidator(),
            router=StubRouter(),
            config=_make_config(),
        )
        req = _make_request()
        await pipeline.process_request(req, context={"tenant": "acme", "priority": "high"})

        assert received_context["tenant"] == "acme"
        assert received_context["priority"] == "high"
