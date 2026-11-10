# 🛡️ AgentOps (formerly AetherWall)

**The Open-Source Agent Governance Gateway**

AgentOps is a self-hosted, edge-deployable gateway that governs every interaction between your agents and the outside world — other agents, MCP tools, and internal services. It sits between your agent fleet and everything else, and answers one question before any traffic flows: **should this agent be allowed to do this, under this policy, right now?**

```
┌──────────────────┐     ┌────────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Agents / MCP    │────▶│    AgentOps  │────▶│  Internal Services  │
│  External world  │◀────│  governed pipe │◀────│  / MCP Tools        │
└──────────────────┘     │                │     └──────────────────┘
                         │  0 · Policy gate     ─ auth, kill switch, allow-lists, limits
                         │  1 · Verification    ─ LLM Guard (PII, injection, toxicity)
                         │  2 · Validation      ─ LangGraph council (risk + context)
                         │  3 · Human approval  ─ pending queue (governance API)
                         │  4 · Routing         ─ APISIX + LiteLLM
                         │    · Audit trail     ─ Qdrant (every decision, searchable)
                         └────────────────┘
```

## Why AgentOps

Agent fleets fail in specific, well-documented ways — the [OWASP Agentic AI threat catalog](https://genai.owasp.org/resources/agentic-ai-threats-and-mitigations/) (identity spoofing, tool misuse, excessive agency, resource overload, human-in-the-loop weaknesses) and [MITRE ATLAS](https://atlas.mitre.org) both treat unmediated agent traffic as a primary attack surface. In 2026 the market response consolidated into two camps: **expensive SaaS platforms** (Palo Alto Prisma AIRS, Cisco AI Defense, Zscaler, CrowdStrike agentic identity) and **protocol standards** (MCP authorization, A2A) that define identity but enforce nothing.

AgentOps is the missing third option: a **self-hostable enforcement point** you control. It takes the governance capabilities those platforms charge enterprise prices for — identity attestation, least-privilege tool authorization, spend limits, human approval workflows, kill switches, and an audit-ready decision log — and implements them in an open, declarative stack you can read, extend, and point at your own infrastructure. See [`docs/comparison.md`](docs/comparison.md) for the full market analysis.

## How it works

Every request to `/gateway/process` flows through five phases. Decisions and evidence from every phase are stored in the Qdrant audit trail.

**Phase 0 — Governance gate.** The requesting agent must be *known* (a connection in `agentops.yaml`), *enabled* (kill switch), and if a credential is configured, *authenticated* (token in `X-Agentops-Auth`). The destination must be in the agent's allow-list, and an MCP tool call must be in its tool allow-list. Rate limits and spend caps are enforced here.

**Phase 1 — Verification.** The payload is scanned statelessly by [LLM Guard](https://github.com/protectai/llm-guard): prompt injection, jailbreaks, PII, secrets, toxic content. With `fail_open` you can keep traffic flowing when the scanner is down (still flagged for the council); with `monitor` mode nothing is blocked — you get the same decisions recorded as "what would have been enforced" for risk-free rollout.

**Phase 2 — Validation.** Ambiguous or risky requests are deliberated by a LangGraph **validation council** — a Risk Agent and a Context Agent that assess the request against your natural-language policy rules, with an Arbiter applying your configurable decision thresholds (`deny_risk`, `escalate_risk`).

**Phase 3 — Human approval.** Escalated requests are *held*, not routed. They land in a pending queue and wait for a human reviewer via `POST /governance/approvals/{id}/decision`. Unreviewed approvals settle according to your `on_timeout` policy (`deny` by default).

**Phase 4 — Routing + output check.** Approved requests are forwarded via APISIX/LiteLLM. Optional response scanning (`verify_responses`) guards the return path too.

## Quick start

```bash
git clone https://github.com/supulkalhara/agent-ops.git
cd agent-ops
cp .env.sample .env   # fill in secrets, including per-agent tokens

docker compose up -d
docker compose exec ollama ollama pull qwen3:8b   # local council brain (first run)

# Send a request through the pipeline
curl -X POST http://localhost:8000/gateway/process \
  -H "X-Agentops-Auth: <PROCUREMENT_AGENT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "Internal-Procurement",
    "destination": "moltbook.com/api",
    "payload": "Check budget for PO-2024-001",
    "metadata": {"tool_name": "check_budget"}
  }'
```

Open-agent requests (no credential configured) need no header. See [`docs/api.md`](docs/api.md) for the complete API.

## Guardrails you can set today

| Guardrail | Config | Effect |
|---|---|---|
| **Agent identity & auth** | `connections[].credential` | Token HMAC-style check per request — no self-asserted identities |
| **Instant revocation** | `connections[].enabled: false` + `POST /config/reload` | Kill switch: revoked immediately on next request |
| **Destination allow-list** | `connections[].allowed_external` | Hard deny for any unlisted destination |
| **Tool least-privilege** | `connections[].mcp_tools_allowed` | Hard deny for tool calls outside the agent's whitelist |
| **Rate limits** | `connections[].rate_limit` | Sliding-window request budget per agent |
| **Transaction caps** | `connections[].transaction_limit_usd` | Deny single requests whose `amount_usd` exceeds the cap |
| **Daily spend caps** | `connections[].daily_spend_limit_usd` | Rolling-UTC-day spend budget per agent |
| **Content safety** | `security.pii_redaction`, `verify_responses` | PII redaction, injection/jailbreak scanning, optional return-path scan |
| **Natural-language policy** | `validation_council.rules` | Council checks requests against your written rules |
| **Decision thresholds** | `governance.decision_thresholds` | Tune deny/escalate risk cutoffs per deployment |
| **Human-in-the-loop** | `governance.human_approval` | ESCALATE → pending queue → human approve/reject |
| **Fail mode** | `governance.default_fail_mode` | fail-closed (safe) or fail-open (available) when detectors break |
| **Monitor mode** | `governance.default_mode` / per-connection | Dry-run rollout: decide + record without blocking |

Full reference with per-field semantics: [`docs/guardrails.md`](docs/guardrails.md).

## Configuration

Everything is governed by one declarative file — **`agentops.yaml`** (spec v1.1, backward compatible with 1.0):

```yaml
agentops_gateway:
  version: "1.1"
  governance:
    default_fail_mode: fail_closed     # fail_closed | fail_open
    default_mode: enforce              # enforce | monitor
    decision_thresholds: {deny_risk: 0.7, escalate_risk: 0.3}
    human_approval: {enabled: true, timeout_minutes: 60, on_timeout: deny}
  connections:
    - agent_identity: "Internal-Procurement"
      credential: "${PROCUREMENT_AGENT_TOKEN}"
      enabled: true                    # kill switch
      allowed_external: ["moltbook.com/api"]
      mcp_tools_allowed: ["check_budget", "submit_po"]
      rate_limit: 100_requests_per_minute
      transaction_limit_usd: 250.0
      daily_spend_limit_usd: 5000.0
  security:
    pii_redaction: {enabled: true, engine: llm_guard}
    verify_responses: false
  validation_council:
    engine: langgraph
    local_model: ollama/qwen3:8b
    rules:
      - "Block any request attempting to enumerate users or credentials."
```

Full field-by-field reference: [`docs/configuration.md`](docs/configuration.md).

## Governance endpoints

| Endpoint | Purpose |
|---|---|
| `POST /gateway/process` | Run a request through the governed pipeline |
| `GET /governance/approvals` | List requests held for human review |
| `POST /governance/approvals/{id}/decision` | Approve or reject an escalated request |
| `POST /config/reload` | Hot-reload `agentops.yaml` (kill switches, policy changes) |
| `GET /audit/search?q=...` | Semantic search over every recorded decision |
| `GET /healthz`, `GET /readyz` | Liveness / readiness probes |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest -v            # 131 tests, including adversarial E2E scenarios
ruff check src tests
mypy src
```

## Project structure

```
agentops/
├── src/agentops/
│   ├── domain/            # Framework-free core business logic
│   │   ├── models.py      # Pydantic domain models (+ approvals)
│   │   ├── config.py      # agentops.yaml parsing/validation (v1.0 + v1.1)
│   │   ├── gateway.py     # Pipeline orchestrator (all 5 phases)
│   │   ├── approvals.py   # Human-in-the-loop approval store
│   │   ├── enforcement.py # Rate limiter + spend ledger
│   │   └── exceptions.py
│   ├── interfaces/        # Abstract base classes (ports)
│   ├── council/           # LangGraph Risk/Context/Arbiter council
│   ├── adapters/          # Concrete ports: LLM Guard, APISIX, Qdrant
│   └── api/               # FastAPI app + DI wiring
├── docs/                  # Deep-dive documentation
│   ├── how-it-works.md    # Architecture & pipeline walkthrough
│   ├── guardrails.md      # Guardrail catalog & threat mapping
│   ├── configuration.md   # agentops.yaml reference
│   ├── api.md             # HTTP API reference
│   └── comparison.md      # Market landscape vs AgentOps
├── config/apisix/ + config/litellm/
├── agentops.yaml            # Gateway governance specification
├── docker-compose.yml     # Full 7-service stack
└── Dockerfile             # Multi-stage production build
```

## Stack

| Service | Purpose | Port |
|---|---|---|
| **AgentOps** | Core governance gateway | `8000` |
| **APISIX** | Edge router | `9080` |
| **LiteLLM** | LLM translation proxy | `4000` |
| **Ollama** | Local LLM inference (council brain) | `11434` |
| **Qdrant** | Vector DB (semantic audit trail) | `6333` |
| **LLM Guard** | Security scanner | `8080` |
| **etcd** | APISIX config store | `2379` |

## License

MIT — see [`LICENSE`](LICENSE). Fork it, embed it, sell services on it; keep the copyright notice.
