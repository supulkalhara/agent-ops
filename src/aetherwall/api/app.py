"""
AetherWall FastAPI Application.

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

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from aetherwall.api.dependencies import (
    get_audit_logger,
    get_config,
    get_pipeline,
)
from aetherwall.domain.exceptions import (
    AetherWallError,
    RoutingError,
    SecurityViolationError,
    ValidationRejectedError,
)
from aetherwall.domain.models import (
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
    log_level = os.environ.get("AETHERWALL_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    logger.info("🛡️  AetherWall starting up...")

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

    logger.info("🛡️  AetherWall ready — pipeline assembled")

    yield

    # Cleanup
    logger.info("🛡️  AetherWall shutting down...")
    if _audit_logger:
        await _audit_logger.close()


# ── App ───────────────────────────────────────────────────────────────


app = FastAPI(
    title="AetherWall",
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
        description="Additional context info",
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
async def process_request(body: ProcessRequest) -> ProcessResponse:
    """
    Process an inbound agent request through the full security pipeline.

    Phases:
    1. Policy pre-check (agent + destination allow-list)
    2. Payload verification (LLM Guard)
    3. Council validation (LangGraph)
    4. Routing (APISIX)
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
            agent_request, context=body.context
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

    except AetherWallError as exc:
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
