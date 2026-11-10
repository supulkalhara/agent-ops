"""
Core gateway pipeline — the heart of AetherWall.

Orchestrates the governed security flow:

  0. Governance gate — authentication, kill switch, allow-lists
     (destinations + MCP tools), rate limits and spend caps.
  1. Verification    — stateless inspection via LLM Guard.
  2. Validation      — council deliberation via LangGraph.
  3. Routing         — edge routing via APISIX + LiteLLM, or a pending
     human approval for ESCALATE decisions.
  4. Output check    — optional response-side verification after
     routing (guards the return path).

This module depends only on interfaces and domain models, never on
concrete adapter implementations, ensuring decoupling per Clean
Architecture.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from aetherwall.domain.approvals import (
    ApprovalExpiredError,
    ApprovalStore,
)
from aetherwall.domain.config import ConnectionSpec, GatewayConfig
from aetherwall.domain.enforcement import (
    RateLimiter,
    SpendLedger,
    parse_rate_limit,
)
from aetherwall.domain.exceptions import (
    RoutingError,
    SecurityViolationError,
    ValidationRejectedError,
)
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    ApprovalRecord,
    GatewayResponse,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.router import APIRouterInterface
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface
from aetherwall.interfaces.verifier import SecurityVerifierInterface

logger = logging.getLogger(__name__)

# Flags emitted by the verifier adapter when the verification service
# itself is unavailable. Governed by the fail-mode setting — these say
# nothing about the content of the request.
INFRASTRUCTURE_FLAGS = frozenset({"llm_guard_error", "llm_guard_unreachable"})

Mode = str  # "enforce" | "monitor"


@dataclass
class GatewayPipeline:
    """
    Dependency-injected gateway orchestrator.

    All collaborators are injected as ports so the pipeline can be
    tested with mocks and swapped at runtime without touching business
    logic.
    """

    verifier: SecurityVerifierInterface
    validator: CoreGatewayValidatorInterface
    router: APIRouterInterface
    config: GatewayConfig
    security_threshold: float = field(default=0.7)
    approval_store: ApprovalStore | None = field(default=None)
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    spend_ledger: SpendLedger = field(default_factory=SpendLedger)

    def __post_init__(self) -> None:
        if self.approval_store is None:
            self.approval_store = ApprovalStore(
                timeout_minutes=self.config.governance.human_approval.timeout_minutes
            )

    @property
    def _store(self) -> ApprovalStore:
        """Post-initialised approval store (never None at runtime)."""
        assert self.approval_store is not None
        return self.approval_store

    async def process_request(
        self,
        request: AgentRequest,
        context: dict[str, Any] | None = None,
        auth_token: str | None = None,
    ) -> GatewayResponse:
        """
        Execute the full governed pipeline on an inbound request.

        Phases
        ------
        0. Governance gate — authenticate, kill switch, allow-lists,
           rate limits, spend caps.
        1. Verification    — stateless payload scanning.
        2. Validation      — council deliberation; ESCALATE pauses for
           human approval when enabled.
        3. Routing         — approved requests forwarded.
        4. Output check    — optional response-side verification.
        """
        context = context or {}

        # ── Phase 0: Governance gate ──────────────────────────────
        gate = await self._run_identity_gate(request, auth_token)
        if isinstance(gate, GatewayResponse):
            return gate
        mode = self.config.effective_mode(request.agent_id)

        blocked = await self._run_policy_gate(request)
        if blocked is not None:
            return await self._deny(request, blocked)

        blocked = await self._run_limits(request, mode)
        if blocked is not None:
            return await self._deny(request, blocked)

        # ── Phase 1: Verification ──────────────────────────────────
        analysis = await self.verifier.verify_payload(request)
        response = await self._apply_verification(
            request, analysis, mode
        )
        if response is not None:
            return response

        # ── Phase 2: Validation ─────────────────────────────────────
        logger.info(
            "Submitting to validation council for agent=%s", request.agent_id
        )
        validation = await self.validator.evaluate_request(
            request, analysis, context
        )

        if mode == "monitor":
            return await self._route_monitor(
                request,
                context,
                analysis,
                would_decision=validation.decision,
            )

        escalation = await self._apply_council_decision(
            request, context, analysis, validation
        )
        if escalation is not None:
            return escalation

        # ── Phase 3: Routing ────────────────────────────────────────
        effective_request = self._effective_request(request, validation, analysis)
        route_result = await self._route(effective_request, validation)

        # ── Phase 4: Output verification (optional) ─────────────────
        output_analysis = await self._verify_output(
            request, route_result
        )

        # Commit spend after successful routing so failed requests
        # don't consume budget.
        amount = SpendLedger.extract_amount(request.metadata)
        if amount is not None:
            await self.spend_ledger.record(request.agent_id, amount)

        return GatewayResponse(
            decision=validation.decision,
            reasoning=validation.reasoning,
            route_result=route_result,
            security_analysis=analysis,
            output_analysis=output_analysis,
        )

    async def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        reviewer: str,
        comment: str | None = None,
    ) -> GatewayResponse | None:
        """
        Resume a request held for human approval.

        Returns None when the approval id is unknown. Raises
        ApprovalExpiredError when the record cannot be settled.
        """
        try:
            record: ApprovalRecord | None = await self._store.resolve(
                approval_id,
                approved=approved,
                reviewer=reviewer,
                comment=comment,
            )
        except ApprovalExpiredError:
            # Lazy expiry settlement: without a background job, the
            # timeout decision applies the moment the lapsed approval
            # is touched.
            return await self._settle_expired(approval_id, reviewer)

        if record is None:
            return None

        if not approved:
            await self.router.block_request(
                record.request,
                f"Rejected by reviewer '{reviewer}': "
                f"{record.validation.reasoning}",
            )
            return GatewayResponse(
                decision=ActionDecision.DENY,
                reasoning=(
                    f"Rejected by reviewer '{reviewer}': "
                    f"{record.validation.reasoning}"
                ),
                security_analysis=record.security_analysis,
            )

        effective_request = self._effective_request(
            record.request, record.validation, record.security_analysis
        )
        route_result = await self._route(effective_request, record.validation)

        return GatewayResponse(
            decision=ActionDecision.ALLOW,
            reasoning=(
                f"Approved by reviewer '{reviewer}' — "
                f"{record.validation.reasoning}"
            ),
            route_result=route_result,
            security_analysis=record.security_analysis,
        )

    # ── Phase implementations ────────────────────────────────────────

    async def _run_identity_gate(
        self, request: AgentRequest, auth_token: str | None
    ) -> GatewayResponse | ConnectionSpec:
        """Authentication + kill switch. Returns the connection or a deny."""
        conn = self.config.get_connection(request.agent_id)

        if conn is None:
            return await self._deny(
                request,
                f"Agent '{request.agent_id}' is unknown; "
                "destination not allowed",
            )

        # Kill switch — revocation is enforced in every mode, including
        # monitor mode. A revoked agent gets no traffic, no exceptions.
        if not conn.enabled:
            return await self._deny(
                request, f"Agent '{request.agent_id}' is disabled (revoked)"
            )

        # Authentication: if a credential is configured, the caller must
        # present a matching token. Self-asserted identity is not trust.
        if conn.credential and auth_token != conn.credential:
            logger.warning(
                "Authentication failed for agent=%s request=%s",
                request.agent_id,
                request.request_id,
            )
            return await self._deny(
                request,
                "Authentication failed: missing or invalid credential",
            )

        return conn

    async def _run_policy_gate(self, request: AgentRequest) -> str | None:
        """Hard allow-lists: destinations and MCP tools."""
        if not self.config.is_destination_allowed(
            request.agent_id, request.destination
        ):
            return (
                f"Destination '{request.destination}' "
                f"not allowed for agent '{request.agent_id}'"
            )

        tool_name = request.metadata.get("tool_name")
        if tool_name is not None and not self.config.is_mcp_tool_allowed(
            request.agent_id, str(tool_name)
        ):
            return (
                f"MCP tool '{tool_name}' "
                f"not allowed for agent '{request.agent_id}'"
            )
        return None

    async def _run_limits(
        self, request: AgentRequest, mode: Mode
    ) -> str | None:
        """
        Resource guardrails: rate limits, transaction caps, daily spend.
        Soft guardrails — recorded (not blocking) in monitor mode.
        """
        conn = self.config.get_connection(request.agent_id)
        assert conn is not None  # guaranteed by identity gate

        max_events, window_seconds = parse_rate_limit(conn.rate_limit)
        within_allowance = await self.rate_limiter.check(
            request.agent_id, max_events, window_seconds
        )
        if not within_allowance and mode == "enforce":
            return f"Rate limit exceeded ({conn.rate_limit})"
        if not within_allowance:
            logger.info(
                "MONITOR: agent=%s exceeded rate limit (%s) — allowed",
                request.agent_id,
                conn.rate_limit,
            )

        amount = SpendLedger.extract_amount(request.metadata)
        if amount is None:
            return None

        if (
            conn.transaction_limit_usd is not None
            and amount > conn.transaction_limit_usd
        ):
            if mode == "enforce":
                return (
                    f"Transaction ${amount:.2f} exceeds agent limit "
                    f"${conn.transaction_limit_usd:.2f}"
                )
            logger.info(
                "MONITOR: agent=%s transaction $%.2f exceeds limit — allowed",
                request.agent_id,
                amount,
            )

        if (
            conn.daily_spend_limit_usd is not None
            and not await self.spend_ledger.check_transaction(
                request.agent_id, amount, conn.daily_spend_limit_usd
            )
        ):
            if mode == "enforce":
                return (
                    f"Daily spend limit of "
                    f"${conn.daily_spend_limit_usd:.2f} exceeded "
                    f"for agent '{request.agent_id}'"
                )
            logger.info(
                "MONITOR: agent=%s exceeds daily spend limit — allowed",
                request.agent_id,
            )
        return None

    async def _apply_verification(
        self, request: AgentRequest, analysis: SecurityAnalysis, mode: Mode
    ) -> GatewayResponse | None:
        """
        Act on verification output.

        Returns a GatewayResponse only when the request can/should be
        settled immediately; None to continue the pipeline. Raises
        SecurityViolationError for hard blocks (after recording the
        edge block).
        """
        violating = (
            not analysis.is_safe
            and analysis.confidence_score >= self.security_threshold
        )
        if not violating:
            return None

        infra_failure = (
            bool(analysis.flags) and set(analysis.flags) <= INFRASTRUCTURE_FLAGS
        )
        fail_open = self.config.governance.default_fail_mode == "fail_open"

        if infra_failure and fail_open:
            # Fail-open: verification infrastructure is down. Let the
            # council decide, keeping flags in the audit trail.
            logger.warning(
                "FAIL-OPEN: verification unavailable for agent=%s — "
                "passing flags %s to council",
                request.agent_id,
                analysis.flags,
            )
            return None

        if mode == "monitor":
            logger.info(
                "MONITOR: would block agent=%s for %s — routing anyway",
                request.agent_id,
                analysis.flags,
            )
            return None

        logger.warning(
            "Security violation: flags=%s confidence=%.2f",
            analysis.flags,
            analysis.confidence_score,
        )
        await self.router.block_request(
            request, f"Security violation: {', '.join(analysis.flags)}"
        )
        raise SecurityViolationError(
            flags=list(analysis.flags),
            confidence=analysis.confidence_score,
        )

    async def _apply_council_decision(
        self,
        request: AgentRequest,
        context: dict[str, Any],
        analysis: SecurityAnalysis,
        validation: ValidationResult,
    ) -> GatewayResponse | None:
        """
        Act on a council decision in enforce mode.

        Returns a settled GatewayResponse (DENY raise / ESCALATE hold)
        or None to continue to routing.
        """
        if validation.decision == ActionDecision.DENY:
            logger.warning("Validation council denied: %s", validation.reasoning)
            await self.router.block_request(request, validation.reasoning)
            raise ValidationRejectedError(reasoning=validation.reasoning)

        if validation.decision == ActionDecision.ESCALATE:
            if not self.config.governance.human_approval.enabled:
                # HITL disabled: an escalation is a conservative deny.
                logger.warning(
                    "Council escalated but human approval disabled — "
                    "denying agent=%s: %s",
                    request.agent_id,
                    validation.reasoning,
                )
                await self.router.block_request(
                    request, "Escalated request denied (HITL disabled)"
                )
                raise ValidationRejectedError(reasoning=validation.reasoning)

            # Human-in-the-loop: hold the request pending review.
            approval = await self._store.create(
                request,
                validation,
                security_analysis=analysis,
                context=context,
            )
            logger.info(
                "Request %s ESCALATED — pending approval %s",
                request.request_id,
                approval.approval_id,
            )
            return GatewayResponse(
                decision=ActionDecision.ESCALATE,
                reasoning=(
                    f"{validation.reasoning} — held pending human approval "
                    f"({approval.approval_id})"
                ),
                security_analysis=analysis,
                approval_id=approval.approval_id,
            )

        return None

    async def _verify_output(
        self, request: AgentRequest, route_result: Any
    ) -> SecurityAnalysis | None:
        """Optional return-path verification after routing succeeded."""
        if not self.config.security.verify_responses:
            return None
        response_text = self._extract_response_text(route_result)
        if response_text is None:
            return None
        output_analysis = await self.verifier.verify_output(
            request, response_text
        )
        if not output_analysis.is_safe:
            # The response has already been delivered to the caller —
            # flag loudly for audit/incident response.
            logger.warning(
                "OUTPUT VIOLATION on request %s: %s",
                request.request_id,
                output_analysis.flags,
            )
        return output_analysis

    async def _settle_expired(
        self, approval_id: str, reviewer: str
    ) -> GatewayResponse:
        """
        Settle a lapsed approval according to governance.human_approval.
        on_timeout ("deny" by default; "allow" routes the held request).
        """
        record = await self._store.get(approval_id)
        if record is None:
            raise ApprovalExpiredError(f"Unknown approval {approval_id}")

        if self.config.governance.human_approval.on_timeout == "allow":
            effective_request = self._effective_request(
                record.request, record.validation, record.security_analysis
            )
            route_result = await self._route(effective_request, record.validation)
            return GatewayResponse(
                decision=ActionDecision.ALLOW,
                reasoning=(
                    f"Approval {approval_id} expired — routed per "
                    f"on_timeout=allow policy"
                ),
                route_result=route_result,
                security_analysis=record.security_analysis,
            )

        await self.router.block_request(
            record.request,
            f"Approval {approval_id} expired — denied after timeout",
        )
        return GatewayResponse(
            decision=ActionDecision.DENY,
            reasoning=(
                f"Approval {approval_id} expired without review — denied "
                f"(on_timeout=deny policy)"
            ),
            security_analysis=record.security_analysis,
        )

    def _effective_request(
        self,
        request: AgentRequest,
        validation: ValidationResult,
        analysis: SecurityAnalysis | None,
    ) -> AgentRequest:
        """Apply council/verifier payload modifications before routing."""
        effective = request
        if validation.modified_payload is not None:
            effective = effective.model_copy(
                update={"payload": validation.modified_payload}
            )
        if (
            validation.decision == ActionDecision.REDACT
            and analysis is not None
            and analysis.redacted_payload
        ):
            effective = effective.model_copy(
                update={"payload": analysis.redacted_payload}
            )
        return effective

    async def _route(
        self, request: AgentRequest, validation: ValidationResult
    ) -> Any:
        logger.info("Routing request for agent=%s", request.agent_id)
        try:
            return await self.router.route_request(request, validation)
        except Exception as exc:
            raise RoutingError(
                destination=request.destination,
                reason=str(exc),
            ) from exc

    async def _deny(self, request: AgentRequest, reason: str) -> GatewayResponse:
        """Deny at the governance gate and record the block."""
        logger.warning(
            "Policy denied: agent=%s destination=%s reason=%s",
            request.agent_id,
            request.destination,
            reason,
        )
        await self.router.block_request(request, reason)
        return GatewayResponse(decision=ActionDecision.DENY, reasoning=reason)

    async def _route_monitor(
        self,
        request: AgentRequest,
        context: dict[str, Any],
        analysis: SecurityAnalysis | None,
        would_decision: ActionDecision | None = None,
    ) -> GatewayResponse:
        """
        Monitor mode: traffic flows; the decision that *would* have
        been enforced is attached for the audit trail. Council analysis
        still runs so monitors see realistic signals.
        """
        try:
            validation = await self.validator.evaluate_request(
                request,
                analysis or SecurityAnalysis(is_safe=True, confidence_score=0.0),
                context,
            )
            if would_decision is None:
                would_decision = validation.decision
            reasoning = validation.reasoning
        except Exception as exc:  # noqa: BLE001 — monitor must never break traffic
            logger.warning(
                "MONITOR: council error for agent=%s (%s)", request.agent_id, exc
            )
            would_decision = would_decision or ActionDecision.ESCALATE
            reasoning = f"council error in monitor mode: {exc}"

        try:
            route_result = await self._route(
                request,
                ValidationResult(
                    decision=ActionDecision.ALLOW, reasoning=reasoning
                ),
            )
        except RoutingError:
            raise

        logger.info(
            "MONITOR: routed agent=%s (would_decision=%s)",
            request.agent_id,
            would_decision.value,
        )
        return GatewayResponse(
            decision=ActionDecision.ALLOW,
            reasoning=f"MONITOR MODE: routed with flags — {reasoning}",
            route_result=route_result,
            security_analysis=analysis,
            monitor_mode=True,
            would_decision=would_decision,
        )

    @staticmethod
    def _extract_response_text(route_result: Any) -> str | None:
        """Best-effort extraction of response text from a route result."""
        if isinstance(route_result, str):
            return route_result
        if isinstance(route_result, dict):
            candidate = route_result.get("response") or route_result.get("body")
            if isinstance(candidate, str) and candidate:
                return candidate
        return None
