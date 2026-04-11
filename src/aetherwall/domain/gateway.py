"""
Core gateway pipeline — the heart of AetherWall.

Orchestrates the three-phase security flow:
  1. Verification  (stateless inspection via LLM Guard)
  2. Validation     (council deliberation via LangGraph)
  3. Routing        (edge routing via APISIX + LiteLLM)

This module depends only on interfaces and domain models, never on
concrete adapter implementations, ensuring decoupling per Clean Architecture.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from aetherwall.domain.config import GatewayConfig
from aetherwall.domain.exceptions import (
    RoutingError,
    SecurityViolationError,
    ValidationRejectedError,
)
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    GatewayResponse,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.router import APIRouterInterface
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface
from aetherwall.interfaces.verifier import SecurityVerifierInterface

logger = logging.getLogger(__name__)


@dataclass
class GatewayPipeline:
    """
    Dependency-injected gateway orchestrator.

    All three collaborators are injected as abstract interfaces so the
    pipeline can be tested with mocks and swapped at runtime without
    touching business logic.
    """

    verifier: SecurityVerifierInterface
    validator: CoreGatewayValidatorInterface
    router: APIRouterInterface
    config: GatewayConfig
    security_threshold: float = field(default=0.7)

    async def process_request(
        self,
        request: AgentRequest,
        context: dict[str, Any] | None = None,
    ) -> GatewayResponse:
        """
        Execute the full security pipeline on an inbound request.

        Phases
        ------
        1. **Policy check** — verify agent and destination against config.
        2. **Verification** — stateless payload scanning (PII, toxicity, jailbreak).
        3. **Validation** — council deliberation on complex/risky requests.
        4. **Routing** — approved requests are forwarded; denied ones are blocked.

        Returns
        -------
        GatewayResponse with the outcome and audit details.
        """
        context = context or {}

        # ── Phase 0: Policy Pre-Check ──────────────────────────────────
        if not self.config.is_destination_allowed(request.agent_id, request.destination):
            logger.warning(
                "Policy denied: agent=%s destination=%s",
                request.agent_id,
                request.destination,
            )
            await self.router.block_request(
                request, f"Destination '{request.destination}' not in allow-list"
            )
            reason = (
                f"Destination '{request.destination}' "
                f"not allowed for agent '{request.agent_id}'"
            )
            return GatewayResponse(
                decision=ActionDecision.DENY,
                reasoning=reason,
            )

        # ── Phase 1: Verification ──────────────────────────────────────
        logger.info("Verifying payload for agent=%s", request.agent_id)
        analysis: SecurityAnalysis = await self.verifier.verify_payload(request)

        if not analysis.is_safe and analysis.confidence_score >= self.security_threshold:
            logger.warning(
                "Security violation: flags=%s confidence=%.2f",
                analysis.flags,
                analysis.confidence_score,
            )
            await self.router.block_request(
                request,
                f"Security violation: {', '.join(analysis.flags)}",
            )
            raise SecurityViolationError(
                flags=analysis.flags,
                confidence=analysis.confidence_score,
            )

        # ── Phase 2: Validation ────────────────────────────────────────
        logger.info("Submitting to validation council for agent=%s", request.agent_id)
        validation: ValidationResult = await self.validator.evaluate_request(
            request, analysis, context
        )

        if validation.decision == ActionDecision.DENY:
            logger.warning("Validation council denied: %s", validation.reasoning)
            await self.router.block_request(request, validation.reasoning)
            raise ValidationRejectedError(reasoning=validation.reasoning)

        # ── Phase 3: Routing ───────────────────────────────────────────
        # If the validation council requested a payload modification (e.g. redaction),
        # apply it before routing.
        effective_request = request
        if validation.modified_payload is not None:
            effective_request = request.model_copy(
                update={"payload": validation.modified_payload}
            )

        if validation.decision == ActionDecision.REDACT and analysis.redacted_payload:
            effective_request = effective_request.model_copy(
                update={"payload": analysis.redacted_payload}
            )

        logger.info("Routing request for agent=%s", request.agent_id)
        try:
            route_result = await self.router.route_request(effective_request, validation)
        except Exception as exc:
            raise RoutingError(
                destination=request.destination,
                reason=str(exc),
            ) from exc

        return GatewayResponse(
            decision=validation.decision,
            reasoning=validation.reasoning,
            route_result=route_result,
            security_analysis=analysis,
        )
