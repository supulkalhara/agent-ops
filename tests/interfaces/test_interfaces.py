import pytest

from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.router import APIRouterInterface
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface
from aetherwall.interfaces.verifier import SecurityVerifierInterface


class MockRouter(APIRouterInterface):
    async def route_request(self, request, validation):
        return {"status": "routed"}

    async def block_request(self, request, reason):
        return None

class MockVerifier(SecurityVerifierInterface):
    async def verify_payload(self, request):
        return SecurityAnalysis(is_safe=True, confidence_score=0.99)

class MockValidator(CoreGatewayValidatorInterface):
    async def evaluate_request(self, request, security_analysis, context):
        return ValidationResult(decision=ActionDecision.ALLOW, reasoning="Mock validation passed")

@pytest.mark.asyncio
async def test_interfaces_mock_instantiation():
    """Test that our abstract base classes can be successfully implemented."""
    router = MockRouter()
    verifier = MockVerifier()
    validator = MockValidator()

    req = AgentRequest(
        agent_id="agent-01", destination="internal.db", payload="SELECT * FROM users"
    )

    analysis = await verifier.verify_payload(req)
    assert analysis.is_safe is True

    val_result = await validator.evaluate_request(req, analysis, {})
    assert val_result.decision == ActionDecision.ALLOW

    route_status = await router.route_request(req, val_result)
    assert route_status["status"] == "routed"
