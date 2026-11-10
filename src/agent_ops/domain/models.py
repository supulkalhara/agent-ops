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


class ApprovalStatus(str, Enum):
    """Lifecycle of a human-in-the-loop approval."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRecord(BaseModel):
    """
    A request held for human review by the governance layer.

    Created when the validation council ESCALATEs and human approval
    is enabled. Stores the full original request and validation result
    so the gateway can resume routing exactly where it paused.
    """

    approval_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this approval",
    )
    request: AgentRequest
    validation: ValidationResult
    security_analysis: SecurityAnalysis | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = None
    reviewer: str | None = None
    review_comment: str | None = None
    resolved_at: datetime | None = None


class GatewayResponse(BaseModel):
    """
    Complete response from the gateway pipeline.

    Captures the final decision, reasoning, optional route result,
    and the security analysis for a full audit trail. In monitor mode,
    ``would_decision`` records the decision that *would* have been
    enforced while traffic was allowed to proceed.
    """

    decision: ActionDecision
    reasoning: str
    route_result: Any | None = None
    security_analysis: SecurityAnalysis | None = None
    # Human-in-the-loop: populated when decision == escalate.
    approval_id: str | None = None
    # Monitor mode bookkeeping (never affects traffic).
    monitor_mode: bool = False
    would_decision: ActionDecision | None = None
    # Output verification: analysis of what was routed back.
    output_analysis: SecurityAnalysis | None = None
