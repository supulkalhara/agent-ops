"""
Configuration models for AgentOps gateway deployment.

Parses and validates the declarative `agentops.yaml` spec that controls
how internal agents interact with external entities, including security
policies, rate limits, spend limits, human-approval settings, and
validation council rules.

Spec versions:
  • 1.0 — original routing + security + council configuration.
  • 1.1 — adds the governance layer: authentication, kill switches,
          enforce/monitor modes, fail-closed/fail-open behaviour,
          decision thresholds, spend limits, and human-approval
          workflow (all optional, fully backward compatible).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

# ── Supported spec versions ───────────────────────────────────────────
SUPPORTED_VERSIONS = {"1.0", "1.1"}

# Matches `${VAR_NAME}` secret references
_ENV_REF_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class DecisionThresholds(BaseModel):
    """
    Risk thresholds used by the validation-council arbiter.

    risk <= escalate_risk              → ALLOW
    escalate_risk < risk <= deny_risk  → ESCALATE (human review)
    risk >  deny_risk                  → DENY
    """

    deny_risk: float = Field(default=0.7, ge=0.0, le=1.0)
    escalate_risk: float = Field(default=0.3, ge=0.0, le=1.0)


class HumanApprovalConfig(BaseModel):
    """
    Human-in-the-loop approval settings.

    When ``enabled`` is true, requests the council ESCALATEs are held
    in a pending queue and must be approved via the governance API
    before they are routed. If the approval is not given within
    ``timeout_minutes``, the request is settled according to
    ``on_timeout`` (``deny`` keeps the system safe, ``allow`` favours
    availability).
    """

    enabled: bool = True
    timeout_minutes: int = Field(default=60, ge=1, le=24 * 60)
    on_timeout: Literal["deny", "allow"] = "deny"


class GovernanceConfig(BaseModel):
    """
    Governed behaviour defaults for the whole gateway.

    ``default_fail_mode``:
      • ``fail_closed`` — if a security component errors, block traffic
        (safe default).
      • ``fail_open``   — if a security component errors, let traffic
        proceed but flag it (availability first).

    ``default_mode``:
      • ``enforce`` — decisions block traffic as configured.
      • ``monitor`` — detection runs but traffic continues; what *would*
        have been blocked is recorded in the audit trail. Allow-lists and
        kill switches are still enforced in monitor mode.
    """

    default_fail_mode: Literal["fail_closed", "fail_open"] = "fail_closed"
    default_mode: Literal["enforce", "monitor"] = "enforce"
    decision_thresholds: DecisionThresholds = Field(
        default_factory=DecisionThresholds
    )
    human_approval: HumanApprovalConfig = Field(
        default_factory=HumanApprovalConfig
    )


class ConnectionSpec(BaseModel):
    """Defines policies for a single agent connection."""

    agent_identity: str

    # ── Identity & lifecycle (v1.1) ──────────────────────────────
    # Secret token used to authenticate the agent. Supports `${ENV_VAR}`
    # references; empty means authentication is not required.
    credential: str = ""
    # Kill switch — set to false to instantly revoke an agent's access.
    enabled: bool = True
    # Per-connection mode override: enforce | monitor.
    mode: Literal["enforce", "monitor"] = "enforce"

    # ── Connectivity policy ──────────────────────────────────────
    allowed_external: list[str] = Field(default_factory=list)
    mcp_tools_allowed: list[str] = Field(default_factory=list)
    rate_limit: str = "100_requests_per_minute"

    # ── Financial guardrails (v1.1) ──────────────────────────────
    # Maximum single-transaction value (USD) inferred from
    # request metadata ``amount_usd``. None = unlimited.
    transaction_limit_usd: float | None = Field(default=None, ge=0.0)
    # Rolling-daily cumulative spend cap (USD). None = unlimited.
    daily_spend_limit_usd: float | None = Field(default=None, ge=0.0)


class PIIRedactionConfig(BaseModel):
    """PII redaction engine configuration."""

    enabled: bool = True
    engine: str = "llm_guard"
    block_entities: list[str] = Field(
        default_factory=lambda: [
            "CREDIT_CARD", "SSN", "INTERNAL_IP", "EMAIL", "PHONE_NUMBER",
        ]
    )


class SecurityConfig(BaseModel):
    """Top-level security configuration."""

    pii_redaction: PIIRedactionConfig = Field(default_factory=PIIRedactionConfig)
    # Scan outbound/response payloads after successful routing.
    # Covers the OWASP-mitigation class of responses returning
    # malicious content or exfiltrated data to the calling agent.
    verify_responses: bool = False


class ValidationCouncilConfig(BaseModel):
    """LangGraph validation council settings."""

    enabled: bool = True
    engine: str = "langgraph"
    local_model: str = "ollama/qwen3:8b"
    rules: list[str] = Field(default_factory=list)


class RoutingConfig(BaseModel):
    """Core routing engine configuration."""

    primary_router: str = "apisix"
    ai_translation: str = "litellm"


class GatewayConfig(BaseModel):
    """
    Root configuration model for `agentops.yaml`.

    This is the single source of truth for all gateway behaviour — routing
    policies, connection specs, security settings, governance defaults,
    and validation rules.
    """

    version: str = "1.0"
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    connections: list[ConnectionSpec] = Field(default_factory=list)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    validation_council: ValidationCouncilConfig = Field(
        default_factory=ValidationCouncilConfig
    )
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if v not in SUPPORTED_VERSIONS:
            msg = f"Unsupported config version '{v}'. Supported: {sorted(SUPPORTED_VERSIONS)}"
            raise ValueError(msg)
        return v

    # ── Lookups ──────────────────────────────────────────────────────

    def get_connection(self, agent_id: str) -> ConnectionSpec | None:
        """Look up connection spec by agent identity."""
        for conn in self.connections:
            if conn.agent_identity == agent_id:
                return conn
        return None

    # ── Policy checks ────────────────────────────────────────────────

    def is_destination_allowed(self, agent_id: str, destination: str) -> bool:
        """Check if the given agent is allowed to reach the destination."""
        conn = self.get_connection(agent_id)
        if conn is None:
            return False
        return destination in conn.allowed_external

    def is_mcp_tool_allowed(self, agent_id: str, tool_name: str) -> bool:
        """Check if the given agent is allowed to invoke the MCP tool."""
        conn = self.get_connection(agent_id)
        if conn is None:
            return False
        if not conn.mcp_tools_allowed:
            # No tool allow-list configured → tools are not permitted.
            return False
        return tool_name in conn.mcp_tools_allowed

    def is_agent_enabled(self, agent_id: str) -> bool:
        """Kill-switch check for an agent connection."""
        conn = self.get_connection(agent_id)
        return conn is not None and conn.enabled

    def effective_mode(self, agent_id: str) -> Literal["enforce", "monitor"]:
        """
        Resolve the effective mode for an agent: per-connection override
        falls back to the governance default.
        """
        conn = self.get_connection(agent_id)
        if conn is not None and conn.mode == "monitor":
            return "monitor"
        return self.governance.default_mode


def expand_env_ref(value: str, name: str) -> str:
    """
    Expand `${ENV_VAR}` references inside a config string value.

    Raises ConfigurationError if the referenced variable is unset —
    a missing secret must fail loudly, not silently disable auth.
    """
    match = _ENV_REF_PATTERN.match(value.strip())
    if match is None:
        return value

    env_var = match.group(1)
    resolved = os.environ.get(env_var)
    if resolved is None:
        from agent_ops.domain.exceptions import ConfigurationError

        raise ConfigurationError(
            f"Connection '{name}' references secret ${{{env_var}}} "
            f"which is not set in the environment"
        )
    return resolved


def load_config(path: str | Path) -> GatewayConfig:
    """Load and validate a GatewayConfig from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    # Accept both spec root keys: `agentops_gateway` (current) and the
    # legacy `aetherwall_gateway` from the pre-rename AetherWall era.
    if "agentops_gateway" in raw:
        raw = raw["agentops_gateway"]
    elif "aetherwall_gateway" in raw:
        raw = raw["aetherwall_gateway"]

    config = GatewayConfig(**raw)

    # Expand `${ENV_VAR}` credential references after validation.
    for conn in config.connections:
        if conn.credential:
            conn.credential = expand_env_ref(conn.credential, conn.agent_identity)

    return config
