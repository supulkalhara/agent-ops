"""
AgentOps FastAPI Application.

Exposes the gateway pipeline as REST endpoints:
  • POST /gateway/process  — process an inbound agent request
  • GET  /healthz          — liveness probe
  • GET  /readyz           — readiness probe (checks Qdrant)
  • GET  /audit/search     — semantic search over audit logs
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from agent_ops.api.dependencies import (
    get_audit_logger,
    get_config,
    get_pipeline,
)
from agent_ops.domain.approvals import ApprovalStateError
from agent_ops.domain.exceptions import (
    AgentOpsError,
    RoutingError,
    SecurityViolationError,
    ValidationRejectedError,
)
from agent_ops.domain.models import (
    AgentRequest,
    GatewayResponse,
)

logger = logging.getLogger(__name__)

# ── Module-level singletons (initialised in lifespan) ─────────────────
_pipeline = None
_audit_logger = None


# ── Lifespan ──────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle for the FastAPI app."""
    global _pipeline, _audit_logger

    # Configure logging
    log_level = os.environ.get("AGENTOPS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    logger.info("🛡️  AgentOps starting up...")

    # Build the pipeline
    _pipeline = get_pipeline()
    _audit_logger = get_audit_logger()

    # Ensure Qdrant collection exists
    try:
        await _audit_logger.ensure_collection()
        logger.info("Qdrant audit collection ready")
    except Exception:
        logger.warning(
            "Qdrant not available at startup — audit logging disabled"
        )

    logger.info("🛡️  AgentOps ready — pipeline assembled")

    yield

    # Cleanup
    logger.info("🛡️  AgentOps shutting down...")
    if _audit_logger:
        await _audit_logger.close()


# ── App ───────────────────────────────────────────────────────────────


app = FastAPI(
    title="AgentOps",
    description="Enterprise Agent-to-[Agent/MCP] Security Gateway",
    version="0.1.0",
    lifespan=lifespan,
)


# ── Request / Response Schemas ────────────────────────────────────────


class ProcessRequest(BaseModel):
    """Inbound request to the gateway."""

    agent_id: str = Field(..., description="ID of the requesting agent")
    destination: str = Field(
        ..., description="Target endpoint or MCP tool"
    )
    payload: str = Field(
        ..., description="The raw prompt or JSON payload"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context info (tool_name, amount_usd, ...)",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Context for validation council",
    )


class ProcessResponse(BaseModel):
    """Response from the gateway pipeline."""

    request_id: str
    decision: str
    reasoning: str
    route_result: Any | None = None
    security_flags: list[str] = Field(default_factory=list)
    confidence_score: float | None = None
    output_flags: list[str] = Field(default_factory=list)
    # Human-in-the-loop: set when decision == escalate
    approval_id: str | None = None
    # Monitor-mode bookkeeping
    monitor_mode: bool = False
    would_decision: str | None = None


class ErrorResponse(BaseModel):
    """Error response from the gateway."""

    error: str
    error_type: str
    detail: str | None = None
    request_id: str | None = None


# ── Gateway Endpoint ──────────────────────────────────────────────────


@app.post(
    "/gateway/process",
    response_model=ProcessResponse,
    responses={
        403: {"model": ErrorResponse, "description": "Security violation"},
        422: {"model": ErrorResponse, "description": "Validation rejected"},
        502: {"model": ErrorResponse, "description": "Routing error"},
    },
    summary="Process an agent request through the security pipeline",
    tags=["Gateway"],
)
async def process_request(
    body: ProcessRequest,
    x_agent_ops_auth: str | None = Header(
        default=None,
        alias="X-Agentops-Auth",
        description="Agent credential verifying its identity (when configured)",
    ),
) -> ProcessResponse:
    """
    Process an inbound agent request through the full governed pipeline.

    Phases:
    0. Governance gate (auth, kill switch, allow-lists, limits)
    1. Payload verification (LLM Guard)
    2. Council validation (LangGraph)
    3. Routing (APISIX) — ESCALATE decisions pause for human approval
    """
    if _pipeline is None:
        raise HTTPException(
            status_code=503,
            detail="Gateway pipeline not initialized",
        )

    # Build the domain request
    agent_request = AgentRequest(
        agent_id=body.agent_id,
        destination=body.destination,
        payload=body.payload,
        metadata=body.metadata,
    )

    try:
        response: GatewayResponse = await _pipeline.process_request(
            agent_request,
            context=body.context,
            auth_token=x_agent_ops_auth,
        )

        # Log to Qdrant (fire-and-forget, don't block the response)
        if _audit_logger:
            try:
                await _audit_logger.log_decision(
                    request_id=agent_request.request_id,
                    agent_id=agent_request.agent_id,
                    destination=agent_request.destination,
                    payload=agent_request.payload,
                    response=response,
                )
            except Exception:
                logger.warning(
                    "Failed to log audit for request %s",
                    agent_request.request_id,
                    exc_info=True,
                )

        return ProcessResponse(
            request_id=agent_request.request_id,
            decision=response.decision.value,
            reasoning=response.reasoning,
            route_result=response.route_result,
            security_flags=(
                response.security_analysis.flags
                if response.security_analysis
                else []
            ),
            confidence_score=(
                response.security_analysis.confidence_score
                if response.security_analysis
                else None
            ),
            output_flags=(
                response.output_analysis.flags
                if response.output_analysis
                else []
            ),
            approval_id=response.approval_id,
            monitor_mode=response.monitor_mode,
            would_decision=(
                response.would_decision.value
                if response.would_decision
                else None
            ),
        )

    except SecurityViolationError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "error": str(exc),
                "error_type": "security_violation",
                "flags": exc.flags,
                "confidence": exc.confidence,
                "request_id": agent_request.request_id,
            },
        ) from exc

    except ValidationRejectedError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": str(exc),
                "error_type": "validation_rejected",
                "reasoning": exc.reasoning,
                "request_id": agent_request.request_id,
            },
        ) from exc

    except RoutingError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": str(exc),
                "error_type": "routing_error",
                "destination": exc.destination,
                "request_id": agent_request.request_id,
            },
        ) from exc

    except AgentOpsError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "error": str(exc),
                "error_type": "gateway_error",
                "request_id": agent_request.request_id,
            },
        ) from exc


# ── Audit Search ──────────────────────────────────────────────────────


@app.get(
    "/audit/search",
    summary="Search audit logs semantically",
    tags=["Audit"],
)
async def search_audit(
    q: str = Query(..., description="Search query text"),
    limit: int = Query(10, ge=1, le=100, description="Max results"),
) -> dict[str, Any]:
    """Semantic search over past gateway decisions stored in Qdrant."""
    if _audit_logger is None:
        raise HTTPException(
            status_code=503,
            detail="Audit logger not initialized",
        )

    try:
        results = await _audit_logger.search_similar(q, limit=limit)
        return {"query": q, "count": len(results), "results": results}
    except Exception as exc:
        logger.error("Audit search failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Audit search failed: {exc}",
        ) from exc


# ── Governance Endpoints ─────────────────────────────────────────────


class ApprovalDecisionRequest(BaseModel):
    """Reviewer's decision on a pending escalation."""

    action: str = Field(..., description="approve | reject")
    reviewer: str = Field(..., description="Who is reviewing")
    comment: str | None = Field(None, description="Optional review note")


@app.get(
    "/governance/approvals",
    summary="List pending human approvals",
    tags=["Governance"],
)
async def list_pending_approvals() -> dict[str, Any]:
    """
    List all requests ESCALATEd by the validation council and awaiting
    human review, oldest first.
    """
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    pending = await _pipeline._store.pending()
    return {
        "count": len(pending),
        "approvals": [
            {
                "approval_id": rec.approval_id,
                "agent_id": rec.request.agent_id,
                "destination": rec.request.destination,
                "payload": rec.request.payload,
                "reasoning": rec.validation.reasoning,
                "created_at": rec.created_at.isoformat(),
                "expires_at": (
                    rec.expires_at.isoformat() if rec.expires_at else None
                ),
            }
            for rec in pending
        ],
    }


@app.post(
    "/governance/approvals/{approval_id}/decision",
    summary="Approve or reject a pending escalation",
    tags=["Governance"],
)
async def resolve_pending_approval(
    approval_id: str,
    decision: ApprovalDecisionRequest,
) -> dict[str, Any]:
    """
    Resolve a pending approval. Approving resumes routing of the held
    request; rejecting blocks it. Expired approvals settle according to
    the configured ``on_timeout`` policy.
    """
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    if decision.action not in {"approve", "reject"}:
        raise HTTPException(
            status_code=422,
            detail="action must be 'approve' or 'reject'",
        )

    approved = decision.action == "approve"
    try:
        response = await _pipeline.resolve_approval(
            approval_id,
            approved=approved,
            reviewer=decision.reviewer,
            comment=decision.comment,
        )
    except ApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Approval resolution failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Approval resolution failed: {exc}"
        ) from exc

    if response is None:
        raise HTTPException(
            status_code=404, detail=f"Unknown approval '{approval_id}'"
        )

    # Audit the human decision too
    if _audit_logger:
        try:
            await _audit_logger.log_decision(
                request_id=f"approval-{approval_id}",
                agent_id=decision.reviewer,
                destination="governance/human-review",
                payload=f"{decision.action} by {decision.reviewer}",
                response=response,
            )
        except Exception:  # noqa: BLE001 — audit is best-effort
            logger.warning(
                "Failed to audit approval decision %s", approval_id, exc_info=True
            )

    return {
        "approval_id": approval_id,
        "action": decision.action,
        "reviewer": decision.reviewer,
        "decision": response.decision.value,
        "reasoning": response.reasoning,
        "route_result": response.route_result,
    }


@app.post(
    "/config/reload",
    summary="Hot-reload agentops.yaml (kill switches, policy changes)",
    tags=["Governance"],
)
async def reload_config() -> dict[str, Any]:
    """
    Reload the gateway configuration without restarting the service.

    This makes kill switches and policy changes take effect immediately:
    set ``enabled: false`` for an agent in agentops.yaml, call this
    endpoint, and the agent is revoked on the next request.
    """
    global _pipeline
    try:
        # Clear the cached config and rebuild the pipeline from disk.
        get_config.cache_clear()
        _pipeline = get_pipeline()
        return {
            "status": "reloaded",
            "config_version": get_config().version,
        }
    except Exception as exc:
        logger.error("Config reload failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Config reload failed: {exc}"
        ) from exc


# ── Health Check Endpoints ────────────────────────────────────────────


@app.get(
    "/healthz",
    summary="Liveness probe",
    tags=["Health"],
)
async def healthz() -> dict[str, str]:
    """Liveness probe — returns OK if the process is running."""
    return {"status": "ok"}


@app.get(
    "/readyz",
    summary="Readiness probe",
    tags=["Health"],
)
async def readyz() -> dict[str, Any]:
    """
    Readiness probe — checks if all dependencies are reachable.
    """
    checks: dict[str, str] = {}

    # Check pipeline
    checks["pipeline"] = "ok" if _pipeline is not None else "not_ready"

    # Check config
    try:
        config = get_config()
        checks["config"] = "ok"
        checks["config_version"] = config.version
    except Exception:
        checks["config"] = "error"

    overall = all(v == "ok" for k, v in checks.items() if k != "config_version")

    if not overall:
        raise HTTPException(status_code=503, detail=checks)

    return {"status": "ready", "checks": checks}
