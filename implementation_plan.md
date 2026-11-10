# 🛡️ AetherWall: The Enterprise Agent-to-[Agent/MCP] Gateway

## The Name & Market Reality
*I have conducted deep research on the 2026 market landscape:*
1. **The Name:** "AetherWall" represents an invisible, omnipresent protective barrier. It is completely unique in the 2026 AI landscape, giving you a strong brand identity that stands apart from generic terms.
2. **Existing Solutions:** Commercial solutions like *CloudMatos* and *AgentGateway.dev* exist as expensive SaaS products. However, there is **no open-source, self-hosted, edge-deployable equivalent** that combines LangGraph agent validation, MCP protocol termination, and APISIX routing. AetherWall will be the open-source pioneer.

## How It Bundles All Previous Concepts
AetherWall is not just a dumb router; it is the ultimate culmination of all the projects we discussed earlier:

*   **MCP Integration (SynapseDB):** AetherWall natively implements the Model Context Protocol (MCP). It exposes internal enterprise tools (databases, APIs) as secure MCP endpoints, allowing external agents to connect only via authorized channels.
*   **The Internal Agent Council (LangGraph):** When a request comes in, it isn't just checked by a regex. It triggers a LangGraph **Validation Council** (Internal Agents). These agents debate whether the inbound/outbound request is safe, making logical decisions based on context.
*   **AgentShield (Adversarial Defense):** The concepts from AgentShield are built directly into the gateway's traffic inspection layer. It uses LLM Guard to dynamically detect prompt injections, multi-agent hijacks, and context poisoning attempts in real-time.
*   **Domain Expertise (MedGraph/LidLens):** By defining `aether.yaml` profiles, a bank can use it to secure LidLens finance transactions, or a hospital can use it to secure medical record requests.

---

## 🏗️ Technical Architecture & Open Source Stack

We will build an "untouchable" production-grade deployment emphasizing **loose coupling, high cohesion, and minimal complexity**.

### 1. The Core Edge Router
*   **Tool:** **Apache APISIX** + **LiteLLM**
*   **Decoupled Routing:** APISIX handles thousands of agent connections, rate-limiting, and mTLS auth independently.
*   **Adapter Pattern:** LiteLLM acts as the translation layer, decoupling the gateway from specific LLM provider APIs (OpenAI, Anthropic, or local Ollama) without rewriting internal logic.

### 2. The Verification & Redaction Engine
*   **Tool:** **LLM Guard** (ProtectAI)
*   **Stateless Inspection:** Scans all A2A traffic independently at the edge. It redacts PII going out, blocks toxic prompts coming in, and detects complex jailbreaks without tying into core business logic.

### 3. The Validation Council (Internal Agents)
*   **Tool:** **LangGraph** (Python) + **Ollama** (Local Inference)
*   **Modular Agents:** For complex requests (e.g., an external agent asking to negotiate a $5k software license), the LangGraph team spins up. Agents (Risk, Context) are highly cohesive, single-purpose entities interacting through clearly defined state schemas.

### 4. Memory & MCP
*   **Tool:** **Qdrant** (Vector DB) + **Official MCP SDK**
*   **Interface Segregation:** Qdrant stores logs. The MCP SDK acts as a universal interface, completely decoupled from internal business logic, allowing Claude Desktop, Cursor, and any platform to interface cleanly.

---

## 🛠️ Engineering Principles: Best Practices & Low Complexity

To ensure a robust, maintainable, and easily testable system, AetherWall will strictly adhere to the following principles:

1. **Finetuned Builds:** Multi-stage Docker builds for minimal production image sizes. Secure base images (e.g., distroless or alpine). Optimized dependency installation leveraging built-in Docker layer caching.
2. **Decoupling & Cohesion:** 
   - **Dependency Injection** to separate component creation from behavior.
   - **Adapter/Facade Patterns** for external services (LLMs, Vector databases) to swap them out seamlessly.
   - Core domain logic will remain entirely independent of web frameworks (FastAPI) and routing layers (APISIX).
3. **Clean Code:** Enforcement of strict linting (Ruff), formatting (Black), and static type checking (MyPy) to reduce cognitive load, catch bugs early, and minimize code complexity.

---

## 🧪 Testing All The Way (TDD & Automation)

Testing is a first-class citizen in AetherWall, integrated at every layer to guarantee stability:

- **Unit Testing (Pytest):** Targeting 100% coverage on core domain logic, validators, and LangGraph agents using mocked LLM responses (preventing flaky network tests).
- **Integration Testing:** Testing the interaction boundaries between components (e.g., the FastAPI middleware communicating with Qdrant and LiteLLM) using isolated environments like `TestContainers`.
- **Contract Testing:** Ensuring MCP endpoints conform strictly to expected input/output schemas.
- **E2E / Gateway Testing:** Simulating adversarial agents attempting to breach APISIX to verify that LLM Guard and the Validation Council successfully intercept and block the payload.
- **Continuous Integration (CI):** Automated GitHub Actions pipelines running tests, linting, and security audits on every single PR/commit.

---

## ⚙️ Configuration Strategy

### 1. Global Secrets (`.env`)
All sensitive keys live here.
```env
# .env
LITELLM_MASTER_KEY=sk-aether-1234
GROQ_API_KEY=gsk_xxx
QDRANT_API_KEY=xxx
APISIX_ADMIN_KEY=xxx
```

### 2. Gateway Deployment Spec (`aether.yaml`)
This declarative file dictates exactly how internal agents interact with external entities.
```yaml
# aether.yaml
aetherwall_gateway:
  version: "1.0"
  
  routing:
    primary_router: apisix
    ai_translation: litellm

  connections:
    - agent_identity: "Internal-Procurement"
      allowed_external: ["moltbook.com/api", "vendor-agents.com"]
      mcp_tools_allowed: ["check_budget", "submit_po"]
      rate_limit: 100_requests_per_minute
      
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
```

---

## 🚀 Execution Progress

### Step 1: Repository Setup & CI/CD Pipeline ✅
- `[x]` Initialize Git repository
- `[x]` Create base directory structure (`src`, `tests`, `.github/workflows`)
- `[x]` Create `pyproject.toml` with Ruff, MyPy, and Pytest configs
- `[x]` Create comprehensive `.gitignore`
- `[x]` Create initial CI/CD pipeline (`.github/workflows/ci.yml`)

### Step 2: Core Domain & Unit Tests (TDD) ✅
- `[x]` Define interfaces for Routing (`router.py`)
- `[x]` Define interfaces for Verification (`verifier.py`)
- `[x]` Define interfaces for Validation (`validator.py`)
- `[x]` Write unit tests for core interfaces
- `[x]` Implement core domain logic (`gateway.py`, `config.py`, `exceptions.py`, `models.py`)
- `[x]` Write comprehensive unit tests — **39 tests, 97% coverage**

### Step 3: Docker Topology & Finetuned Builds ✅
- `[x]` Create multi-stage `Dockerfile`
- `[x]` Create `.env.sample` and `aether.yaml` skeleton
- `[x]` Create `docker-compose.yml` (APISIX, LiteLLM, Ollama, Qdrant, LLM Guard)
- `[x]` Create APISIX and LiteLLM config files

### Step 4: FastAPI Service & Integration Testing ✅
- `[x]` Build FastAPI application (`api/app.py`) with health check and gateway endpoint
- `[x]` Build LangGraph Validator Council (Risk Agent + Context Agent + Arbiter)
- `[x]` Build concrete adapters (LLM Guard verifier, APISIX router, Qdrant logger)
- `[x]` Build DI wiring (`api/dependencies.py`) — single composition root
- `[x]` Write adapter unit tests — **13 tests**
- `[x]` Write council unit tests — **17 tests**
- `[x]` Write API integration tests — **6 tests**

### Step 5: E2E Traffic Simulation & Security Testing ✅
- `[x]` Build simulated LLM Guard verifier with realistic pattern matching
- `[x]` Build recording router for assertion-based verification
- `[x]` Run 13 adversarial E2E scenarios:
  - `[x]` Benign traffic → ALLOW
  - `[x]` Prompt injection → SecurityViolationError
  - `[x]` Jailbreak (DAN mode) → SecurityViolationError
  - `[x]` Topology probing → ValidationRejectedError
  - `[x]` User/credential enumeration → ValidationRejectedError
  - `[x]` PII exfiltration → SecurityViolationError
  - `[x]` Unknown agent → Policy DENY
  - `[x]` Unauthorised destination → Policy DENY
  - `[x]` Cross-agent isolation → Policy DENY
  - `[x]` SQL injection (DELETE/DROP) → ESCALATE
  - `[x]` Maximum risk payload → ValidationRejectedError
  - `[x]` Innocent-wrapper malicious payload → SecurityViolationError

### Final Quality Report
- **88 tests** across 7 test modules
- **86% code coverage** (19 source files)
- **Ruff** — All checks passed
- **MyPy** — No issues found in 19 source files
- **0.61s** total test execution time

---

## 🏛️ Step 6: Market-Driven Governance Layer (spec v1.1) ✅

*November 2026 — driven by a fresh market research pass covering protocols
(MCP, A2A, MITRE ATLAS, OWASP Agentic), open-source enforcement points
(agentgateway, LiteLLM, Portkey, OPA/Cedar/OpenFGA) and the commercial
platform landscape (see `docs/comparison.md`).*

### Defects fixed
- **ESCALATE routed as ALLOW** — escalated requests were forwarded without
  human review. Now held in a pending queue; v1.0's most dangerous gap.
- **`mcp_tools_allowed` was dead config** — tool allow-lists are now enforced
  whenever `metadata.tool_name` is present.
- **`rate_limit` was dead config** — sliding-window limiter now enforced per agent.
- **No authentication** — `agent_id` was self-asserted. Connections now carry
  `credential:` (with `${ENV_VAR}` resolution) checked via `X-Aetherwall-Auth`.

### Capabilities added (mapped to market expectations)
- Kill switch per agent (`enabled: false`) + `POST /config/reload` hot-reload
- Enforce / monitor modes, global and per-connection (`would_decision` audit)
- Fail-open / fail-closed posture for verifier outages
- Configurable council decision thresholds (`governance.decision_thresholds`)
- Human-in-the-loop approval workflow with expiry + `on_timeout` policy
- Transaction limits (`transaction_limit_usd`) + daily spend ledger
- Optional return-path (response) verification (`verify_responses`)
- Approval store with memory bounds and expiry semantics

### Quality after v1.1
- **131 tests** across 8 test modules (governance + enforcement suites added)
- **83% code coverage** (21 source files)
- **Ruff** — All checks passed · **MyPy** — No issues in 21 source files
