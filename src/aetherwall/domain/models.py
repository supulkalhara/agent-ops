from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActionDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    ESCALATE = "escalate"


class AgentRequest(BaseModel):
    """Inbound request from an external or internal agent."""

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for tracing this request through the pipeline",
    )
    agent_id: str = Field(..., description="ID of the agent initiating the request")
    destination: str = Field(..., description="Target endpoint or MCP tool")
    payload: str = Field(..., description="The raw prompt or JSON payload")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context info")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the request was received",
    )


class SecurityAnalysis(BaseModel):
    """Output of the stateless security verification phase."""

    is_safe: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    flags: list[str] = Field(
        default_factory=list, description="Detected threats like prompt injection"
    )
    redacted_payload: str | None = None


class ValidationResult(BaseModel):
    """Output of the validation council phase."""

    decision: ActionDecision
    reasoning: str
    modified_payload: str | None = None


class GatewayResponse(BaseModel):
    """
    Complete response from the gateway pipeline.

    Captures the final decision, reasoning, optional route result,
    and the security analysis for a full audit trail.
    """

    decision: ActionDecision
    reasoning: str
    route_result: Any | None = None
    security_analysis: SecurityAnalysis | None = None
