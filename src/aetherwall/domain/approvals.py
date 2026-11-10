"""
Human-in-the-loop approval store.

Holds requests ESCALATEd by the validation council until a human
reviewer approves or rejects them through the governance API.
This is an in-memory implementation suitable for a single node;
swap for a durable (Redis/Postgres) store in production HA setups.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    ApprovalRecord,
    ApprovalStatus,
    SecurityAnalysis,
    ValidationResult,
)

logger = logging.getLogger(__name__)


class ApprovalExpiredError(Exception):
    """Raised when a pending approval has passed its expiry."""


class ApprovalStateError(Exception):
    """Raised when an approval is resolved twice or from a final state."""


class ApprovalStore:
    """
    In-memory pending-approval queue for the gateway.

    Bounds are enforced: at most ``max_size`` pending approvals are kept
    (oldest pending is expired first) so an attacker cannot exhaust
    memory by spamming escalate-worthy traffic.
    """

    def __init__(self, timeout_minutes: int = 60, max_size: int = 500) -> None:
        self.timeout_minutes = timeout_minutes
        self.max_size = max_size
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        request: AgentRequest,
        validation: ValidationResult,
        security_analysis: SecurityAnalysis | None = None,
        context: dict[str, Any] | None = None,
    ) -> ApprovalRecord:
        """Queue a request for human review."""
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=self.timeout_minutes
        )
        record = ApprovalRecord(
            request=request,
            validation=validation,
            security_analysis=security_analysis,
            context=context or {},
            expires_at=expires_at,
        )

        async with self._lock:
            # Evict the oldest pending record if over capacity.
            if len(self._records) >= self.max_size:
                oldest = min(
                    self._records.values(),
                    key=lambda r: r.created_at,
                )
                if oldest.status == ApprovalStatus.PENDING:
                    oldest.status = ApprovalStatus.EXPIRED
                    logger.warning(
                        "Approval store full — evicted oldest pending "
                        "approval %s as expired",
                        oldest.approval_id,
                    )
            self._records[record.approval_id] = record

        logger.info(
            "Approval %s created for agent=%s destination=%s (expires=%s)",
            record.approval_id,
            request.agent_id,
            request.destination,
            expires_at.isoformat(),
        )
        return record

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)

    async def resolve(
        self,
        approval_id: str,
        approved: bool,
        reviewer: str,
        comment: str | None = None,
    ) -> ApprovalRecord | None:
        """
        Resolve a pending approval.

        Returns the updated record, or None when the approval does not
        exist. Raises ApprovalExpiredError when the record has lapsed.
        """
        record = self._records.get(approval_id)
        if record is None:
            return None

        now = datetime.now(timezone.utc)

        if record.status != ApprovalStatus.PENDING:
            raise ApprovalStateError(
                f"Approval {approval_id} already {record.status.value}"
            )
        if record.expires_at is not None and now > record.expires_at:
            record.status = ApprovalStatus.EXPIRED
            record.resolved_at = now
            raise ApprovalExpiredError(
                f"Approval {approval_id} expired at {record.expires_at.isoformat()}"
            )

        record.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        record.reviewer = reviewer
        record.review_comment = comment
        record.resolved_at = now

        logger.info(
            "Approval %s %s by %s",
            approval_id,
            record.status.value,
            reviewer,
        )
        return record

    async def pending(self) -> list[ApprovalRecord]:
        """
        List pending approvals in creation order, oldest first.
        Lapsed records are lazily expired on read.
        """
        now = datetime.now(timezone.utc)
        out: list[ApprovalRecord] = []
        for record in self._records.values():
            if record.status != ApprovalStatus.PENDING:
                continue
            if record.expires_at is not None and now > record.expires_at:
                record.status = ApprovalStatus.EXPIRED
                record.resolved_at = now
                continue
            out.append(record)
        return sorted(out, key=lambda r: r.created_at)

    @staticmethod
    def effective_decision(record: ApprovalRecord) -> ActionDecision:
        """Map a resolved approval record onto a pipeline decision."""
        if record.status == ApprovalStatus.APPROVED:
            return ActionDecision.ALLOW
        return ActionDecision.DENY
