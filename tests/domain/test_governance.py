"""
Governance tests: authentication, kill switch, tool allow-lists,
rate & spend limits, monitor mode, fail modes, decision thresholds,
and the human-in-the-loop approval flow.

Complements test_gateway.py (core pipeline) and test_enforcement.py
(primitives) — this file focuses on governance *behaviour*.
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from aetherwall.domain.approvals import (
    ApprovalExpiredError,
    ApprovalStateError,
)
from aetherwall.domain.config import (
    ConnectionSpec,
    GatewayConfig,
    GovernanceConfig,
    load_config,
)
from aetherwall.domain.exceptions import ConfigurationError, SecurityViolationError
from aetherwall.domain.gateway import GatewayPipeline
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface
from aetherwall.interfaces.verifier import SecurityVerifierInterface
from tests.domain.test_gateway import StubRouter

# ── Test Doubles ──────────────────────────────────────────────────────


class StaticVerifier(SecurityVerifierInterface):
    """Configurable verifier for fail-mode tests."""

    def __init__(self, analysis: SecurityAnalysis) -> None:
        self._analysis = analysis

    async def verify_payload(self, request: AgentRequest) -> SecurityAnalysis:
        return self._analysis

    async def verify_output(
        self, request: AgentRequest, response_text: str
    ) -> SecurityAnalysis:
        return SecurityAnalysis(is_safe=True, confidence_score=0.0)


class EchoValidator(CoreGatewayValidatorInterface):
    """Echoes back the decision configured for the test."""

    def __init__(self, decision: ActionDecision) -> None:
        self._decision = decision

    async def evaluate_request(
        self, request: AgentRequest, security_analysis: SecurityAnalysis, context: dict
    ) -> ValidationResult:
        return ValidationResult(decision=self._decision, reasoning="echo")


# ── Fixtures / helpers ────────────────────────────────────────────────


def _conn(agent_id: str = "agent-01", **kwargs) -> ConnectionSpec:
    kwargs.setdefault("allowed_external", ["api.example.com"])
    kwargs.setdefault("mcp_tools_allowed", ["query"])
    return ConnectionSpec(agent_identity=agent_id, **kwargs)


def _make_config(connections: list[ConnectionSpec]) -> GatewayConfig:
    return GatewayConfig(connections=connections)


def _request(
    agent_id: str = "agent-01",
    destination: str = "api.example.com",
    payload: str = "hello world",
    metadata: dict | None = None,
) -> AgentRequest:
    return AgentRequest(
        agent_id=agent_id,
        destination=destination,
        payload=payload,
        metadata=metadata or {},
    )


def _pipeline(
    config: GatewayConfig,
    analysis: SecurityAnalysis | None = None,
    decision: ActionDecision = ActionDecision.ALLOW,
) -> GatewayPipeline:
    return GatewayPipeline(
        verifier=StaticVerifier(
            analysis or SecurityAnalysis(is_safe=True, confidence_score=0.0)
        ),
        validator=EchoValidator(decision),
        router=StubRouter(),
        config=config,
    )


# ── Authentication ────────────────────────────────────────────────────


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_valid_credential_allowed(self) -> None:
        config = _make_config([_conn(credential="tok-123")])
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StaticVerifier(SecurityAnalysis(is_safe=True, confidence_score=0.0)),
            validator=EchoValidator(ActionDecision.ALLOW),
            router=router,
            config=config,
        )
        resp = await pipeline.process_request(_request(), auth_token="tok-123")
        assert resp.decision == ActionDecision.ALLOW
        assert len(router.routed_requests) == 1

    @pytest.mark.asyncio
    async def test_missing_credential_denied(self) -> None:
        config = _make_config([_conn(credential="tok-123")])
        pipeline = _pipeline(config)
        resp = await pipeline.process_request(_request())
        assert resp.decision == ActionDecision.DENY
        assert "Authentication failed" in resp.reasoning

    @pytest.mark.asyncio
    async def test_wrong_credential_denied(self) -> None:
        config = _make_config([_conn(credential="tok-123")])
        pipeline = _pipeline(config)
        resp = await pipeline.process_request(_request(), auth_token="wrong")
        assert resp.decision == ActionDecision.DENY


# ── Kill switch ───────────────────────────────────────────────────────


class TestKillSwitch:
    @pytest.mark.asyncio
    async def test_disabled_agent_denied(self) -> None:
        config = _make_config([_conn(enabled=False)])
        pipeline = _pipeline(config)
        resp = await pipeline.process_request(_request())
        assert resp.decision == ActionDecision.DENY
        assert "disabled" in resp.reasoning

    @pytest.mark.asyncio
    async def test_kill_switch_enforced_even_in_monitor_mode(self) -> None:
        config = _make_config([_conn(enabled=False, mode="monitor")])
        pipeline = _pipeline(config)
        resp = await pipeline.process_request(_request())
        assert resp.decision == ActionDecision.DENY


# ── MCP tool allow-list ───────────────────────────────────────────────


class TestToolAllowList:
    @pytest.mark.asyncio
    async def test_allowed_tool_routes(self) -> None:
        pipeline = _pipeline(_make_config([_conn()]))
        resp = await pipeline.process_request(
            _request(metadata={"tool_name": "query"})
        )
        assert resp.decision == ActionDecision.ALLOW

    @pytest.mark.asyncio
    async def test_disallowed_tool_denied(self) -> None:
        pipeline = _pipeline(_make_config([_conn()]))
        resp = await pipeline.process_request(
            _request(metadata={"tool_name": "delete_database"})
        )
        assert resp.decision == ActionDecision.DENY
        assert "delete_database" in resp.reasoning

    @pytest.mark.asyncio
    async def test_tool_not_in_any_list_denied(self) -> None:
        # No mcp_tools_allowed configured → all tool calls denied
        conn = _conn()
        conn.mcp_tools_allowed = []
        pipeline = _pipeline(_make_config([conn]))
        resp = await pipeline.process_request(
            _request(metadata={"tool_name": "anything"})
        )
        assert resp.decision == ActionDecision.DENY


# ── Financial guardrails ──────────────────────────────────────────────


class TestSpendLimits:
    @pytest.mark.asyncio
    async def test_transaction_over_limit_denied(self) -> None:
        pipeline = _pipeline(_make_config([_conn(transaction_limit_usd=100.0)]))
        resp = await pipeline.process_request(
            _request(metadata={"amount_usd": 500.0})
        )
        assert resp.decision == ActionDecision.DENY
        assert "exceeds" in resp.reasoning.lower()

    @pytest.mark.asyncio
    async def test_daily_spend_accumulates(self) -> None:
        pipeline = _pipeline(_make_config([_conn(daily_spend_limit_usd=300.0)]))
        resp1 = await pipeline.process_request(
            _request(metadata={"amount_usd": 200.0})
        )
        assert resp1.decision == ActionDecision.ALLOW
        resp2 = await pipeline.process_request(
            _request(metadata={"amount_usd": 200.0})
        )
        assert resp2.decision == ActionDecision.DENY
        assert "daily" in resp2.reasoning.lower()


# ── Monitor mode ──────────────────────────────────────────────────────


class TestMonitorMode:
    @pytest.mark.asyncio
    async def test_monitor_mode_routes_flagged_traffic(self) -> None:
        """A detected threat is recorded, not blocking, in monitor mode."""
        threat = SecurityAnalysis(
            is_safe=False, confidence_score=0.95, flags=["prompt_injection"]
        )
        config = GatewayConfig(
            connections=[_conn()],
            governance=GovernanceConfig(default_mode="monitor"),
        )
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StaticVerifier(threat),
            validator=EchoValidator(ActionDecision.DENY),
            router=router,
            config=config,
            security_threshold=0.7,
        )
        resp = await pipeline.process_request(_request())
        # Traffic flowed, with the would-have-been decision recorded
        assert resp.decision == ActionDecision.ALLOW
        assert resp.monitor_mode is True
        assert resp.would_decision == ActionDecision.DENY
        assert len(router.routed_requests) == 1
        assert len(router.blocked_requests) == 0

    @pytest.mark.asyncio
    async def test_allow_lists_enforced_in_monitor_mode(self) -> None:
        config = GatewayConfig(
            connections=[_conn()],
            governance=GovernanceConfig(default_mode="monitor"),
        )
        pipeline = _pipeline(config)
        resp = await pipeline.process_request(_request(destination="evil.com"))
        assert resp.decision == ActionDecision.DENY

    @pytest.mark.asyncio
    async def test_rate_limit_log_only_in_monitor_mode(self) -> None:
        config = GatewayConfig(
            connections=[_conn(rate_limit="1_requests_per_minute")],
            governance=GovernanceConfig(default_mode="monitor"),
        )
        pipeline = _pipeline(config)
        await pipeline.process_request(_request())
        r2 = await pipeline.process_request(_request())
        # Both allowed in monitor mode; would DENY recorded on second
        assert r2.decision == ActionDecision.ALLOW


# ── Fail mode ─────────────────────────────────────────────────────────


class TestFailMode:
    @pytest.mark.asyncio
    async def test_fail_closed_blocks_on_verifier_error(self) -> None:
        broken = SecurityAnalysis(
            is_safe=False, confidence_score=1.0, flags=["llm_guard_unreachable"]
        )
        pipeline = _pipeline(
            _make_config([_conn()]), analysis=broken
        )
        with pytest.raises(SecurityViolationError):
            await pipeline.process_request(_request())

    @pytest.mark.asyncio
    async def test_fail_open_defers_to_council(self) -> None:
        broken = SecurityAnalysis(
            is_safe=False, confidence_score=1.0, flags=["llm_guard_unreachable"]
        )
        config = GatewayConfig(
            connections=[_conn()],
            governance=GovernanceConfig(default_fail_mode="fail_open"),
        )
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StaticVerifier(broken),
            validator=EchoValidator(ActionDecision.ALLOW),
            router=router,
            config=config,
            security_threshold=0.7,
        )
        resp = await pipeline.process_request(_request())
        assert resp.decision == ActionDecision.ALLOW
        assert len(router.routed_requests) == 1


# ── Human-in-the-loop approvals ───────────────────────────────────────


class TestHumanApprovalFlow:
    @pytest.mark.asyncio
    async def test_escalate_holds_and_resumes(self) -> None:
        router = StubRouter()
        pipeline = _pipeline(_make_config([_conn()]))
        pipeline.validator = EchoValidator(ActionDecision.ESCALATE)
        pipeline.router = router

        req = _request()
        held = await pipeline.process_request(req)

        assert held.decision == ActionDecision.ESCALATE
        assert held.approval_id is not None
        assert len(router.routed_requests) == 0  # not routed while pending

        # Human approves
        resumed = await pipeline.resolve_approval(
            held.approval_id, approved=True, reviewer="sec-team"
        )
        assert resumed is not None
        assert resumed.decision == ActionDecision.ALLOW
        assert len(router.routed_requests) == 1

    @pytest.mark.asyncio
    async def test_reject_blocks_request(self) -> None:
        router = StubRouter()
        pipeline = _pipeline(_make_config([_conn()]))
        pipeline.validator = EchoValidator(ActionDecision.ESCALATE)
        pipeline.router = router

        held = await pipeline.process_request(_request())
        rejected = await pipeline.resolve_approval(
            held.approval_id, approved=False, reviewer="sec-team"
        )
        assert rejected is not None
        assert rejected.decision == ActionDecision.DENY
        assert len(router.routed_requests) == 0

    @pytest.mark.asyncio
    async def test_double_resolution_conflict(self) -> None:
        pipeline = _pipeline(_make_config([_conn()]))
        pipeline.validator = EchoValidator(ActionDecision.ESCALATE)
        held = await pipeline.process_request(_request())
        await pipeline.resolve_approval(
            held.approval_id, approved=True, reviewer="a"
        )
        with pytest.raises(ApprovalStateError):
            await pipeline.resolve_approval(
                held.approval_id, approved=False, reviewer="b"
            )

    @pytest.mark.asyncio
    async def test_disabled_hitl_denies_escalated_requests(self) -> None:
        """With human_approval disabled, ESCALATE becomes a hard deny."""
        from aetherwall.domain.config import HumanApprovalConfig
        from aetherwall.domain.exceptions import ValidationRejectedError

        config = GatewayConfig(
            connections=[_conn()],
            governance=GovernanceConfig(
                human_approval=HumanApprovalConfig(enabled=False)
            ),
        )
        router = StubRouter()
        pipeline = GatewayPipeline(
            verifier=StaticVerifier(
                SecurityAnalysis(is_safe=True, confidence_score=0.0)
            ),
            validator=EchoValidator(ActionDecision.ESCALATE),
            router=router,
            config=config,
        )
        with pytest.raises(ValidationRejectedError):
            await pipeline.process_request(_request())
        assert len(router.blocked_requests) == 1
        assert len(router.routed_requests) == 0

    @pytest.mark.asyncio
    async def test_unknown_approval_id(self) -> None:
        pipeline = _pipeline(_make_config([_conn()]))
        assert await pipeline.resolve_approval(
            "no-such-id", approved=True, reviewer="a"
        ) is None

    @pytest.mark.asyncio
    async def test_expired_approval_denies_by_default(self) -> None:
        router = StubRouter()
        pipeline = _pipeline(_make_config([_conn()]))
        pipeline.validator = EchoValidator(ActionDecision.ESCALATE)
        pipeline.router = router
        # Force expiry through a store with a zero timeout-like record

        pending = await pipeline.approval_store.pending()
        assert pending == []  # nothing escalated yet

        pipeline.validator = EchoValidator(ActionDecision.ESCALATE)
        held = await pipeline.process_request(_request())
        pending = await pipeline.approval_store.pending()
        assert len(pending) == 1
        # Manually expire the record
        pending[0].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(ApprovalExpiredError):
            await pipeline.approval_store.resolve(
                held.approval_id, approved=True, reviewer="a"
            )
        # Lazily settled on next touch — denied (on_timeout=deny default)
        settled = await pipeline._settle_expired(held.approval_id, reviewer="timeout")
        assert settled.decision == ActionDecision.DENY


# ── Config v1.1 loading ───────────────────────────────────────────────


class TestConfigV11:
    def test_v11_minimal_loads(self, tmp_path) -> None:
        f = tmp_path / "aether.yaml"
        f.write_text("aetherwall_gateway:\n  version: '1.1'\n")
        config = load_config(f)
        assert config.version == "1.1"
        assert config.governance.default_fail_mode == "fail_closed"
        assert config.governance.decision_thresholds.deny_risk == 0.7

    def test_unsupported_version_20_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Unsupported config version"):
            GatewayConfig(version="2.0")

    def test_env_credential_expansion(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("AGENT_TOKEN", "s3cret")
        f = tmp_path / "aether.yaml"
        f.write_text(
            "aetherwall_gateway:\n"
            "  version: '1.0'\n"
            "  connections:\n"
            "    - agent_identity: a\n"
            "      allowed_external: [x.com]\n"
            "      credential: ${AGENT_TOKEN}\n"
        )
        config = load_config(f)
        assert config.connections[0].credential == "s3cret"

    def test_missing_env_credential_raises(self, monkeypatch, tmp_path) -> None:
        monkeypatch.delenv("AGENT_TOKEN", raising=False)
        f = tmp_path / "aether.yaml"
        f.write_text(
            "aetherwall_gateway:\n"
            "  version: '1.0'\n"
            "  connections:\n"
            "    - agent_identity: a\n"
            "      credential: ${AGENT_TOKEN}\n"
        )
        with pytest.raises(ConfigurationError):
            load_config(f)

    def test_mode_resolution(self) -> None:
        config = _make_config(
            [
                _conn("a", mode="monitor"),
                _conn("b", mode="enforce"),
                _conn("c"),
            ]
        )
        assert config.effective_mode("a") == "monitor"
        # connection mode is the default 'enforce' → fall back to global
        assert config.effective_mode("b") == "enforce"
        assert config.effective_mode("c") == "enforce"

        config.governance.default_mode = "monitor"
        assert config.effective_mode("b") == "monitor"
        assert config.effective_mode("c") == "monitor"

    def test_kill_switch_lookup(self) -> None:
        config = _make_config([_conn("a", enabled=False), _conn("b")])
        assert config.is_agent_enabled("a") is False
        assert config.is_agent_enabled("b") is True
        assert config.is_agent_enabled("ghost") is False
