# Project State & Plan — AgentOps (formerly AgentOps)

> Single source of truth for where the project is and what happens next.
> Update this file at the end of every work session; the git log and this doc together record full progress.

---

## Identity

| Item | Value |
|---|---|
| **Product name** | **AgentOps** |
| **Repo name** | `agent-ops` (github.com/supulkalhara/agent-ops) |
| **Python package** | `agent_ops` (import: `from agent_ops import ...`) |
| **PyPI distribution** | `agent-ops` (distinct from the existing `agentops` package — PEP 503 normalization keeps them separate) |
| **Governance spec** | `agentops.yaml` (v1.1; loader still accepts legacy `agentops.yaml` files and the legacy `agentops_gateway` root key) |
| **License** | MIT (see `LICENSE`) |
| **History** | Built as AgentOps · renamed to AgentOps in Nov 2026 |

## Positioning (why this exists)

Open-source, self-hostable **agent governance gateway**: every agent→tool/agent→agent/service call flows through one governed pipeline — identity, least-privilege tools, budgets, content scanning, LLM council, human approvals, audit trail. The Nov-2026 market analysis (`docs/comparison.md`) showed this exact capability bundle is only available in SaaS/cloud-locked vendor products today.

---

## Roadmap

### Phase 0 — Rename & open-source ✅ (Nov 2026)
- [x] Rename package `agentops` → `agent_ops`, product → AgentOps, repo → `agent-ops`
- [x] Governance spec renamed `agentops.yaml` → `agentops.yaml` (legacy keys still accepted)
- [x] MIT LICENSE added
- [x] Docs rebranded (README + docs/)
- [x] Push + rename GitHub repo

### Phase 1 — Generic configuration (in progress / next)
Make the config *generic-with-guardrails* instead of demo-shaped:
- [ ] `connections[]` → generalized resources: arbitrary agent identities, free-form destinations (prefix/glob matching, not exact strings), user-defined tool lists and metadata
- [ ] **Role-based access control (RBAC)**: roles (`admin`, `operator`, `reviewer`, `agent`), role→agent capability mapping, role definitions in `agentops.yaml`; agents inherit permissions from their role instead of hand-listed blocks; admin override rules per connection
- [ ] Policy inheritance: global defaults → role → connection, three-tier override
- [ ] Validation of user-authored configs with actionable error messages

### Phase 2 — Config UI (LiteLLM-style)
- [ ] Self-hosted web UI shipped in the same container/port, behind username+password set by the user (first-run setup, stored hashed locally)
- [ ] UI covers: connection CRUD, role assignment, thresholds/fail-mode/monitor toggles, spend limits, kill switches, approvals queue with one-click approve/reject
- [ ] UI writes the same `agentops.yaml` (+ audit log of who changed what); API tokens minted per agent from the UI
- [ ] Optional: read-only public dashboard of decisions counters

### Phase 3 — MCP native connection
- [ ] Expose the gateway as a **real MCP server** (stdio + streamable HTTP) so Claude Code, Cursor, Codex, Gemini CLI, Cline etc. connect directly by adding one entry
- [ ] Govern outbound tool calls as MCP tool invocations (already supported via `metadata.tool_name` — wire the MCP transport in front of the pipeline)
- [ ] Ship a `mcp.json` / installer snippet that registers AgentOps into the user's IDE agent config automatically

### Phase 4 — One-command install anywhere, any laptop
- [ ] `pipx install agent-ops` (or `uv tool install`) → `agentops` CLI
- [ ] `agentops init` wizard → writes `agentops.yaml`, starts server; `agentops up` (single binary-container, SQLite/Qdrant optional)
- [ ] `curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash` and a Homebrew tap for macOS
- [ ] Cursor / Claude Code / VS Code extension snippets in the README quick start
- [ ] Default embedded mode: zero external services required to run (local council optional, audit to local files)

### Phase 5 — Hardening & ecosystem
- [ ] Durable approval store (Redis/Postgres) for HA
- [ ] OPA/Cedar/Rego decision hooks (same phase-0 interface)
- [ ] OTel GenAI spans export (Phoenix/LangSmith/AgentOps-compatible)
- [ ] MCP server supply-chain scanning before allow-listing tools
- [ ] Crypto-level agent identity (JWT claims / mTLS) beyond bearer tokens

---

## Session progress log

### 2026-11-10 — Session 1
- Market research: `docs/comparison.md` (3 camps, capability matrix, compliance mapping).
- Governance layer built per research (spec v1.1): auth, kill switch + hot reload, enforce/monitor modes, fail-open/fail-closed, HITL approval queue, spend/rate limits, tool least-privilege enforcement, response scanning, config thresholds. 131 tests green, ruff+mypy clean.
- **Session 2 (same day):** project renamed to **AgentOps**; repo `agent-ops`; MIT license added; docs rebranded; §"Identity" rewritten; legacy `agentops.yaml` / `agentops_gateway` configs still load.

---

## Principles we're keeping through the rename and beyond

1. Domain stays framework-free (`src/agent_ops/domain/` knows nothing about FastAPI/UI).
2. Declarative first: everything the UI can do, `agentops.yaml` can do — the UI is an editor for the same file plus APIs.
3. Deny by default, evidence always.
4. Self-hostable by default; no SaaS dependency to run.
