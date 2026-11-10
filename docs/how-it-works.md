# How AetherWall Works

A deep dive into the architecture and the governed pipeline. This document is the "why it's built this way" companion to the [configuration reference](configuration.md).

## 1. The position of the gateway

AetherWall is an **enforcement point**: a process that stands between agent traffic and whatever agents want to reach. It is deliberately different from three other layers it gets confused with:

| Layer | Examples | What it does | What it does NOT do |
|---|---|---|---|
| **Protocols** | MCP authorization spec, A2A | Define identity handshake and interoperability | Enforce anything at runtime |
| **Policy engines** | OPA/Rego, Cedar, OpenFGA | Evaluate policy logic over any subject | Own identity, detectors, quotas, or audit |
| **Detectors/scanners** | LLM Guard, NeMo Guardrails, Lakera | Classify content | Authorize agents, budget spend, or queue humans |
| **AetherWall** | — | Orchestrate all of the above in one pipeline | — |

The design insight: none of those single layers stops an agent from doing the wrong thing **in sequence** — an authenticated-looking agent calling an allowed tool with a poisoned payload to spend an unbounded amount, escalated by nobody. AetherWall's pipeline is the sequence.

## 2. The five phases

```
Phase 0 · Governance gate      ── identity, lifecycle, hard allow-lists, limits
Phase 1 · Verification         ── stateless content inspection (LLM Guard)
Phase 2 · Validation           ── council deliberation (LangGraph Risk/Context/Arbiter)
Phase 3 · Human approval       ── held requests pending reviewer decision
Phase 4 · Routing + output     ── APISIX/LiteLLM forwarding + optional return-path scan
         Audit · Qdrant        ── every decision recorded, semantically searchable
```

Order matters, and each phase is cheap-to-fail-fast at the top:

### Phase 0 — Governance gate (`gateway.py::_run_identity_gate`, `_run_policy_gate`, `_run_limits`)

Cheap, deterministic checks run **before any LLM or network cost**:

1. **Unknown agent → deny.** If `agent_id` has no connection spec, there is no policy for it. Default-deny is the whole game: the OWASP agentic taxonomy lists *identity spoofing & repudiation* as a top threat, and anonymous traffic in cannot be attributed in an audit.
2. **Kill switch.** `enabled: false` in `aether.yaml` — enforced in *every* mode including monitor. A disabled agent gets a DENY response with no scanning, no council, no exceptions. Reload with `POST /config/reload` to apply without restarts.
3. **Authentication.** If a connection declares `credential: "${TOKEN}"`, the request must carry the matching `X-Aetherwall-Auth` header. Self-asserted `agent_id` in a request body is treated as untrusted input, not identity — the token is the identity.
4. **Destination allow-list.** Hard deny, enforced even in monitor mode.
5. **Tool allow-list.** When `metadata.tool_name` is present, it is checked against `mcp_tools_allowed`. This is least-privilege at tool granularity — the MCP-ecosystem equivalent of per-resource RBAC.
6. **Rate limits.** Sliding-window limiter keyed by agent (`domain/enforcement.py::RateLimiter`); `100_requests_per_minute` parses via `parse_rate_limit`. This is the OWASP *unbounded consumption* guardrail.
7. **Financial caps.** If the request metadata carries `amount_usd` (or `transaction_value`), it is checked against `transaction_limit_usd` (single request) and a UTC-day cumulative ledger (`SpendLedger`). Spend is **committed only after successful routing** — failed/blocked requests never consume budget.

### Phase 1 — Verification (`_apply_verification`)

LLM Guard (`adapters/llm_guard_verifier.py`) scans the payload statelessly — each request is an independent scan, so the verifier scales horizontally. Flags map to `SecurityAnalysis(is_safe, confidence_score, flags, redacted_payload)`.

Three behaviours govern what happens when a threat is detected (or the detector itself is broken):

- **Hard block** (`mode: enforce`): when `confidence_score ≥ security_threshold`, the request is recorded as blocked at the edge and `SecurityViolationError` propagates as HTTP 403.
- **Fail mode**: LLM Guard being *down* is different from a payload being *bad*. Flags like `llm_guard_unreachable` are infrastructure flags. With `default_fail_mode: fail_closed` (default), they block — an unscanable payload cannot enter. With `fail_open`, the request continues to the council with the infrastructure flags attached to the audit trail: availability with visibility, never silence.
- **Monitor mode**: detections are logged and the request proceeds. `GatewayResponse.monitor_mode=True` and `would_decision=<what would have been enforced>` let you measure a policy's blast radius before turning it on. Allow-lists and the kill switch stay enforced in monitor mode — you can dry-run the *detectors*, not the *identity policy*.

### Phase 2 — Validation (`council/validator_council.py`)

Ambiguous requests — everything the cheap phases passed — go to the LangGraph council:

```
START ──▶ Risk Agent ──▶ Context Agent ──▶ Arbiter ──▶ END
```

- **Risk Agent** scores financial/security risk from the verifier flags, and high-risk patterns (destructive SQL, transfers, credential terms, etc.).
- **Context Agent** checks the payload against your natural-language `validation_council.rules` (topology disclosure, transaction debates, enumeration attempts).
- **Arbiter** applies the configured decision matrix using `governance.decision_thresholds` from `aether.yaml`:

```
risk ≤ escalate_risk               → ALLOW
escalate_risk < risk ≤ deny_risk   → ESCALATE (held for human review)
risk > deny_risk, or discounted    → DENY
context violations                 → DENY regardless of risk score
```

Thresholds are configuration, not code — raise `escalate_risk` to reduce the human queue in a noisy deployment, leave the code untouched.

### Phase 3 — Human approval (`domain/approvals.py`)

This is the phase most gateways skip, and where AetherWall differs from traffic-shaping. OWASP's agentic catalog explicitly lists *human-in-the-loop weakness* as a threat class, because an "escalation" that then routes anyway is worse than no escalation — it teaches attackers that entering the zone is free.

ESCAlATEd requests are therefore **never auto-routed**. `ApprovalStore` holds the full original `AgentRequest` + `ValidationResult` + security analysis:

- Reviewers see the queue at `GET /governance/approvals` and settle them at `POST /governance/approvals/{id}/decision` with approve/reject. Approving resumes routing the exact held request (with council/verifier payload modifications intact).
- Approvals **expire** (`timeout_minutes`). Without a background job, expiry settles lazily: the first touch of a lapsed approval applies `on_timeout` — `deny` (default, safe) or `allow` (configure only when you prefer availability).
- Pending queue is memory-bounded (`max_size=500`, oldest-first eviction marked expired) so an attacker cannot memory-exhaust the gateway by spamming escalate-worthy payloads.

### Phase 4 — Routing and output check

Approved requests are forwarded through APISIX (edge routing, mTLS) with identity/decision headers (`X-AetherWall-Agent-ID`, `X-AetherWall-Request-ID`, `X-AetherWall-Decision`). Then, if `security.verify_responses: true`, the **return path** is scanned (`/analyze/output`): responses are a live attack channel (exfiltrated data, malicious content, instruction injection flowing back to the agent — OWASP LLM02/LLM05). Output violations cannot recall an already-delivered response, so they're flagged loudly in the log/audit rather than misreported as blocked.

### Audit — everything is recorded

Every allowed, denied, escalated, and review decision is written to Qdrant as a vector point (`adapters/qdrant_logger.py`). That gives the ops team something rare: *"show me every attempt this week that resembles that topology-probe pattern"* via `GET /audit/search?q=...`. In monitor mode the audit trail also carries `would_decision`, making it a policy rehearsal log.

## 3. Design principles

1. **Clean architecture / hexagonal.** `domain/` knows nothing about FastAPI, APISIX, or LangChain. The pipeline depends purely on the three intrinsic ports (`interfaces/`). Concrete adapters are wired in one place (`api/dependencies.py`) and swapped without touching the pipeline.
2. **Declarative governance.** All policy lives in `aether.yaml` (v1.1). Governance behaviour is configuration: thresholds, fail modes, kill switches, spend caps, approval settings. No code changes to change policy.
3. **Cheap checks first, expensive checks last.** Everything in Phase 0 is deterministic and O(1)-ish; the LLM council only sees what everything cheap missed. This keeps per-request latency and inference cost down.
4. **Deny by default, evidence always.** Unknown agents, unknown tools, unknown destinations → DENY. Known or unknown, everything gets an audit entry.
5. **Graduated response.** Block, redact, escalate — not just binary accept/reject. A moderate-risk destructive SQL request deserve human eyes, not an auto-kill that hides the forensic context.
6. **Testability at every seam.** Every port has a stub in the test suite; adversarial E2E tests replay real attack strings through the real pipeline with only the oversized I/O mocked.

## 4. The multi-node caveat (and why it's honest)

`RateLimiter`, `SpendLedger`, and `ApprovalStore` are in-memory and single-node by design: correct for one instance, and honest about being placeholders for HA deployments. The interface shape (`check/record/resolve`) is deliberately simple to re-implement over Redis — the rest of the pipeline is unchanged by that swap.

## 5. Where to look in code

| Question | File |
|---|---|
| Orchestration order and phases | `src/aetherwall/domain/gateway.py::GatewayPipeline.process_request` |
| What is/should be denied | `gateway.py::_run_identity_gate`, `_run_policy_gate`, `_run_limits` |
| Why a request was escalated | `council/validator_council.py` (Risk/Context/Arbiter nodes) |
| What happens on ESCALATE | `domain/approvals.py`, `gateway.py::resolve_approval` |
| How the scanner is consulted | `adapters/llm_guard_verifier.py`, `interfaces/verifier.py` |
| How the config becomes behaviour | `domain/config.py` |
