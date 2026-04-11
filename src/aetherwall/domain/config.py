"""
Configuration models for AetherWall gateway deployment.

Parses and validates the declarative `aether.yaml` spec that controls
how internal agents interact with external entities, including security
policies, rate limits, and validation council rules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ConnectionSpec(BaseModel):
    """Defines policies for a single agent connection."""

    agent_identity: str
    allowed_external: list[str] = Field(default_factory=list)
    mcp_tools_allowed: list[str] = Field(default_factory=list)
    rate_limit: str = "100_requests_per_minute"


class PIIRedactionConfig(BaseModel):
    """PII redaction engine configuration."""

    enabled: bool = True
    engine: str = "llm_guard"
    block_entities: list[str] = Field(
        default_factory=lambda: ["CREDIT_CARD", "SSN", "INTERNAL_IP"]
    )


class SecurityConfig(BaseModel):
    """Top-level security configuration."""

    pii_redaction: PIIRedactionConfig = Field(default_factory=PIIRedactionConfig)


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
    Root configuration model for `aether.yaml`.

    This is the single source of truth for all gateway behavior — routing
    policies, connection specs, security settings, and validation rules.
    """

    version: str = "1.0"
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    connections: list[ConnectionSpec] = Field(default_factory=list)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    validation_council: ValidationCouncilConfig = Field(default_factory=ValidationCouncilConfig)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        supported = {"1.0"}
        if v not in supported:
            msg = f"Unsupported config version '{v}'. Supported: {supported}"
            raise ValueError(msg)
        return v

    def get_connection(self, agent_id: str) -> ConnectionSpec | None:
        """Look up connection spec by agent identity."""
        for conn in self.connections:
            if conn.agent_identity == agent_id:
                return conn
        return None

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
        return tool_name in conn.mcp_tools_allowed


def load_config(path: str | Path) -> GatewayConfig:
    """Load and validate a GatewayConfig from a YAML file."""
    path = Path(path)
    if not path.exists():
        msg = f"Config file not found: {path}"
        raise FileNotFoundError(msg)

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    # The YAML may nest everything under `aetherwall_gateway`
    if "aetherwall_gateway" in raw:
        raw = raw["aetherwall_gateway"]

    return GatewayConfig(**raw)
