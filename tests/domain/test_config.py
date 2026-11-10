"""Tests for the gateway configuration models and loader."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_ops.domain.config import (
    ConnectionSpec,
    GatewayConfig,
    PIIRedactionConfig,
    RoutingConfig,
    SecurityConfig,
    ValidationCouncilConfig,
    load_config,
)

SAMPLE_YAML = """\
agentops_gateway:
  version: "1.0"

  routing:
    primary_router: apisix
    ai_translation: litellm

  connections:
    - agent_identity: "Internal-Procurement"
      allowed_external: ["moltbook.com/api", "vendor-agents.com"]
      mcp_tools_allowed: ["check_budget", "submit_po"]
      rate_limit: 100_requests_per_minute

    - agent_identity: "Internal-Research"
      allowed_external: ["arxiv.org/api"]
      mcp_tools_allowed: ["search_papers"]
      rate_limit: 50_requests_per_minute

  security:
    pii_redaction:
      enabled: true
      engine: llm_guard
      block_entities: [CREDIT_CARD, SSN, INTERNAL_IP]

  validation_council:
    enabled: true
    engine: langgraph
    local_model: ollama/qwen3:8b
    rules:
      - "Never explicitly confirm internal network topology."
      - "Debate all transactions > $500 before routing."
"""


class TestGatewayConfig:
    """Tests for the GatewayConfig model."""

    def test_default_config(self) -> None:
        config = GatewayConfig()
        assert config.version == "1.0"
        assert config.routing.primary_router == "apisix"
        assert config.connections == []
        assert config.security.pii_redaction.enabled is True
        assert config.validation_council.enabled is True

    def test_unsupported_version(self) -> None:
        with pytest.raises(ValidationError, match="Unsupported config version"):
            GatewayConfig(version="2.0")

    def test_get_connection_found(self) -> None:
        conn = ConnectionSpec(
            agent_identity="agent-a",
            allowed_external=["api.example.com"],
        )
        config = GatewayConfig(connections=[conn])
        result = config.get_connection("agent-a")
        assert result is not None
        assert result.agent_identity == "agent-a"

    def test_get_connection_not_found(self) -> None:
        config = GatewayConfig()
        assert config.get_connection("nonexistent") is None

    def test_is_destination_allowed(self) -> None:
        conn = ConnectionSpec(
            agent_identity="agent-a",
            allowed_external=["api.example.com", "api2.example.com"],
        )
        config = GatewayConfig(connections=[conn])
        assert config.is_destination_allowed("agent-a", "api.example.com") is True
        assert config.is_destination_allowed("agent-a", "evil.com") is False
        assert config.is_destination_allowed("unknown-agent", "api.example.com") is False

    def test_is_mcp_tool_allowed(self) -> None:
        conn = ConnectionSpec(
            agent_identity="agent-a",
            mcp_tools_allowed=["check_budget", "submit_po"],
        )
        config = GatewayConfig(connections=[conn])
        assert config.is_mcp_tool_allowed("agent-a", "check_budget") is True
        assert config.is_mcp_tool_allowed("agent-a", "delete_database") is False
        assert config.is_mcp_tool_allowed("unknown", "check_budget") is False


class TestLoadConfig:
    """Tests for YAML config loading."""

    def test_load_full_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "agentops.yaml"
        config_file.write_text(SAMPLE_YAML)

        config = load_config(config_file)
        assert config.version == "1.0"
        assert config.routing.primary_router == "apisix"
        assert config.routing.ai_translation == "litellm"
        assert len(config.connections) == 2
        assert config.connections[0].agent_identity == "Internal-Procurement"
        assert "moltbook.com/api" in config.connections[0].allowed_external
        assert config.security.pii_redaction.engine == "llm_guard"
        assert config.validation_council.local_model == "ollama/qwen3:8b"
        assert len(config.validation_council.rules) == 2

    def test_load_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.yaml")

    def test_load_minimal_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "agentops.yaml"
        config_file.write_text("agentops_gateway:\n  version: '1.0'\n")
        config = load_config(config_file)
        assert config.version == "1.0"
        assert config.connections == []


class TestConnectionSpec:
    """Tests for individual ConnectionSpec model."""

    def test_defaults(self) -> None:
        c = ConnectionSpec(agent_identity="test")
        assert c.allowed_external == []
        assert c.mcp_tools_allowed == []
        assert c.rate_limit == "100_requests_per_minute"


class TestSubConfigs:
    """Tests for individual sub-configuration models."""

    def test_pii_redaction_defaults(self) -> None:
        pii = PIIRedactionConfig()
        assert pii.enabled is True
        assert pii.engine == "llm_guard"
        assert "CREDIT_CARD" in pii.block_entities

    def test_routing_defaults(self) -> None:
        r = RoutingConfig()
        assert r.primary_router == "apisix"
        assert r.ai_translation == "litellm"

    def test_validation_council_defaults(self) -> None:
        vc = ValidationCouncilConfig()
        assert vc.enabled is True
        assert vc.engine == "langgraph"
        assert vc.rules == []

    def test_security_defaults(self) -> None:
        s = SecurityConfig()
        assert s.pii_redaction.enabled is True
