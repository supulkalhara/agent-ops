# 🛡️ AetherWall

**The Enterprise Agent-to-MCP Gateway**

AetherWall is an open-source, edge-deployable gateway for securing agent-to-agent and agent-to-MCP communications. It provides a production-grade security pipeline combining traffic inspection, LLM-powered validation, and policy-based routing.

---

## Architecture

```
┌──────────────┐     ┌─────────────┐     ┌────────────────────┐     ┌──────────────┐
│  External    │────▶│   APISIX    │────▶│   AetherWall       │────▶│  Internal    │
│  Agent       │     │  (Edge      │     │   Gateway          │     │  Services    │
│              │◀────│   Router)   │◀────│                    │◀────│  / MCP       │
└──────────────┘     └─────────────┘     │  ┌──────────────┐  │     └──────────────┘
                                         │  │  LLM Guard   │  │
                                         │  │  (Verifier)  │  │
                                         │  ├──────────────┤  │
                                         │  │  LangGraph   │  │
                                         │  │  (Validator) │  │
                                         │  ├──────────────┤  │
                                         │  │  Qdrant      │  │
                                         │  │  (Memory)    │  │
                                         │  └──────────────┘  │
                                         └────────────────────┘
```

### Security Pipeline Flow

1. **Policy Pre-Check** — Verify agent identity and destination against `aether.yaml` allow-lists
2. **Verification** — Stateless payload scanning via LLM Guard (PII, toxicity, prompt injection)
3. **Validation** — LangGraph council deliberation for complex/risky requests
4. **Routing** — Approved requests forwarded via APISIX + LiteLLM translation

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/supulkalhara/aether.git
cd aetherwall
cp .env.sample .env   # Edit with your secrets

# 2. Start the full stack
docker compose up -d

# 3. Pull a local model (first run only)
docker compose exec ollama ollama pull qwen3:8b
```

---

## Development

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint & type check
ruff check src tests
mypy src
```

---

## Project Structure

```
aetherwall/
├── src/aetherwall/
│   ├── domain/          # Core business logic (framework-free)
│   │   ├── models.py    # Pydantic domain models
│   │   ├── config.py    # aether.yaml parsing & validation
│   │   ├── gateway.py   # Pipeline orchestrator
│   │   └── exceptions.py
│   └── interfaces/      # Abstract base classes (ports)
│       ├── router.py    # Routing interface
│       ├── validator.py # Validation council interface
│       └── verifier.py  # Security verification interface
├── tests/
│   ├── domain/          # Unit tests for core logic
│   └── interfaces/      # Interface contract tests
├── config/
│   ├── apisix/          # APISIX edge router config
│   └── litellm/         # LiteLLM proxy config
├── aether.yaml          # Gateway deployment specification
├── docker-compose.yml   # Full stack (7 services)
├── Dockerfile           # Multi-stage production build
└── pyproject.toml       # Project & tooling config
```

---

## Configuration

### `aether.yaml` — Gateway Policy

Define agent connections, allow-lists, security settings, and validation rules:

```yaml
aetherwall_gateway:
  version: "1.0"
  connections:
    - agent_identity: "Internal-Procurement"
      allowed_external: ["vendor-agents.com"]
      mcp_tools_allowed: ["check_budget"]
      rate_limit: 100_requests_per_minute
  security:
    pii_redaction:
      enabled: true
      engine: llm_guard
  validation_council:
    enabled: true
    engine: langgraph
    rules:
      - "Debate all transactions > $500 before routing."
```

### `.env` — Secrets

See [`.env.sample`](.env.sample) for all available variables.

---

## Stack

| Service | Purpose | Port |
|---------|---------|------|
| **AetherWall** | Core gateway | `8000` |
| **APISIX** | Edge router | `9080` |
| **LiteLLM** | LLM translation proxy | `4000` |
| **Ollama** | Local LLM inference | `11434` |
| **Qdrant** | Vector DB (audit logs) | `6333` |
| **LLM Guard** | Security scanner | `8080` |
| **etcd** | APISIX config store | `2379` |

---

## License

MIT
