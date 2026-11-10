"""
Dependency injection wiring for the FastAPI application.

All concrete adapters are instantiated here and injected into the
GatewayPipeline. This is the only module that knows about concrete
implementations — everything else depends on interfaces.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

from agent_ops.adapters.apisix_router import APISIXRouter
from agent_ops.adapters.llm_guard_verifier import LLMGuardVerifier
from agent_ops.adapters.qdrant_logger import QdrantAuditLogger
from agent_ops.council.validator_council import ValidatorCouncil
from agent_ops.domain.approvals import ApprovalStore
from agent_ops.domain.config import GatewayConfig, load_config
from agent_ops.domain.gateway import GatewayPipeline

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_config() -> GatewayConfig:
    """Load the gateway config from the path in env vars (cached)."""
    config_path = os.environ.get(
        "AGENTOPS_CONFIG_PATH",
        "/etc/agentops/agentops.yaml",
    )
    path = Path(config_path)

    if path.exists():
        logger.info("Loading config from %s", config_path)
        return load_config(path)

    logger.warning(
        "Config file %s not found, using defaults", config_path
    )
    return GatewayConfig()


def get_verifier() -> LLMGuardVerifier:
    """Create the LLM Guard verifier adapter."""
    return LLMGuardVerifier(
        api_url=os.environ.get("LLM_GUARD_API", "http://llm-guard:8080"),
        timeout=float(os.environ.get("LLM_GUARD_TIMEOUT", "10")),
    )


def get_validator() -> ValidatorCouncil:
    """Create the LangGraph validator council."""
    return ValidatorCouncil(config=get_config())


def get_router() -> APISIXRouter:
    """Create the APISIX router adapter."""
    return APISIXRouter(
        admin_url=os.environ.get(
            "APISIX_ADMIN_API", "http://apisix:9180"
        ),
        admin_key=os.environ.get("APISIX_ADMIN_KEY", ""),
        proxy_url=os.environ.get(
            "APISIX_PROXY_URL", "http://apisix:9080"
        ),
    )


def get_audit_logger() -> QdrantAuditLogger:
    """Create the Qdrant audit logger."""
    return QdrantAuditLogger(
        host=os.environ.get("QDRANT_HOST", "qdrant"),
        port=int(os.environ.get("QDRANT_PORT", "6333")),
        api_key=os.environ.get("QDRANT_API_KEY", ""),
        collection_name=os.environ.get(
            "QDRANT_COLLECTION", "agentops_audit"
        ),
    )


def get_pipeline() -> GatewayPipeline:
    """Assemble the full gateway pipeline with all concrete adapters."""
    config = get_config()
    threshold = float(
        os.environ.get("AGENTOPS_SECURITY_THRESHOLD", "0.7")
    )

    approval_store = ApprovalStore(
        timeout_minutes=config.governance.human_approval.timeout_minutes,
    )

    return GatewayPipeline(
        verifier=get_verifier(),
        validator=get_validator(),
        router=get_router(),
        config=config,
        security_threshold=threshold,
        approval_store=approval_store,
    )
