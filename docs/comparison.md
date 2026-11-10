# Market Landscape: Agent Governance Frameworks (Nov 2026) — and Where AgentOps Fits

This is the market research behind AgentOps's v1.1 governance layer: what exists, what it does well, what it leaves as gaps, and which capabilities were adopted into AgentOps as a result. Sources were verified against live vendor/docs pages in November 2026.

---

## 1. The three camps

### Camp 1 — Protocols & standards (define, don't enforce)

| Framework | Maintainer | Governance contribution | Enforcement? |
|---|---|---|---|
| **MCP** (Model Context Protocol) | Anthropic → open governance ([modelcontextprotocol.io](https://modelcontextprotocol.io)) | OAuth 2.1 authorization, PKCE, RFC 8707 token audience binding, RFC 9728 protected-resource metadata, token passthrough forbidden, consent flows for consequential actions, security best-practices doc (confused deputy, SSRF, tool-description poisoning, rug-pull mutations) | ❌ spec-level only |
| **A2A** (Agent2Agent) | Linux Foundation / Agentic AI Foundation ([a2a-protocol.org](https://a2a-protocol.org)) | Agent Cards for capability discovery, cross-agent interoperability, Identity & Trust working group porting agent identity | ❌ (deep policy explicitly out of scope) |
| **AGENTS.md** | OpenAI → LF/AAIF ([agents.md](https://agents.md)) | Per-repo "policy for agents" conventions; adopted by 60k+ projects and every major coding agent | ❌ discretionary |
| **OTel GenAI semantic conventions** | CNCF ([semconv-genai](https://github.com/open-telemetry/semantic-conventions-genai)) | Standard spans/metrics for GenAI + MCP operations — the observability substrate | ❌ telemetry only |
| **MITRE ATLAS v6** | MITRE ([atlas.mitre.org](https://atlas.mitre.org)) | TTP threat catalogue with a first-class **Agentic AI platform** tag; monthly YAML releases; mitigations categorized Policy / Technical | ❌ knowledge base |
| **OWASP Agentic AI Threats & Mitigations** | OWASP ASI ([genai.owasp.org](https://genai.owasp.org/resources/agentic-ai-threats-and-mitigations/)) | Canonical agentic threat classes: memory poisoning, tool misuse, privilege compromise, resource overload, HITL weaknesses, cascading hallucination, identity spoofing | ❌ taxonomy |
| **EU AI Act / NIST AI RMF / ISO 42001** | EU / NIST / ISO | Regulatory obligations (Art. 14 human oversight, Art. 12 logging, Art. 15 robustness) and management-system frames | ❌ compliance targets |

**Takeaway:** the identity and threat-model layers are solved and public. What is missing is a piece of software that turns them into behavior. That is Camp 2 and 3.

### Camp 2 — Open-source enforcement points

| Tool | Maintainer | Strong at | Weak at |
|---|---|---|---|
| **agentgateway** | LF/AAIF, Rust ([agentgateway.dev](https://agentgateway.dev)) | Multi-protocol gateway (MCP, A2A, LLM, HTTP); per-tool allow/deny; tool-call signing; token budgets; redaction; OTel-native | No council-style LLM judgement; no human-approval queue; no spend valuation of transactions |
| **LiteLLM** | BerriAI ([docs.litellm.ai](https://docs.litellm.ai)) | Virtual keys with budgets/quotas; MCP gateway with tool policies + guardrails; kill switch; OWASP mapping doc | LLM-proxy centric — traffic it sees is LLM API calls; agent-to-service traffic is not its model |
| **Portkey Gateway** | Portkey ([github.com/Portkey-AI/gateway](https://github.com/Portkey-AI/gateway)) | 1,600+ routes; guardrails on prompts/outputs; MCP gateway; Gateway 2.0 enterprise features OSS | SaaS product gravity; governance reads as per-key budgets more than policy-as-code |
| **OPA / Cedar / OpenFGA** | CNCF / AWS / CNCF | The proper authorization brains (Rego / verified Cedar / ReBAC) — decision engines agents can call | Everything else: identity issuance, detectors, quotas, HITL, audit trail — you integrate them |
| **Docker MCP Toolkit/Gateway** | Docker | Signed catalog MCP servers, container isolation, OAuth brokering, secret interception | Desktop-developer oriented; no org-level policy language or governance queue |
| **Cisco mcp-scanner / Snyk Agent Scan (ex-Invariant mcp-scan)** | Cisco AI Defense / Snyk | Supply-chain scanning of MCP servers and agent configs (YARA + LLM + API analyzers) | Scanners, not runtime enforcement |
| **E2B** | e2b.dev | Sandboxed microVM execution with egress allow/deny, workload identity, secrets-at-egress | Execution-scope governance only |
| **Y Oss guardrail libraries (NVIDIA NeMo Guardrails, Llama Guard)** | NVIDIA / Meta | Input/output/topic/jailbreak rails, execution rails on tool calls; self-hostable | Framework-internal; no gateway, no audit-grade trail, no identity |

**Takeaway:** the open enforcement layer exists and is good — but is either a *proxy primitive* (agentgateway/LiteLLM), an *authorization brain* (OPA/Cedar/OpenFGA), or a *scanner*. No OSS project combines them with a **deliberation council, held-approval queue, and transaction-spend valuation**.

### Camp 3 — Commercial platforms (the enterprise fences)

Key verification notes from November 2026: Lakera is under Check Point; Prompt Security is under SentinelOne; Invariant Labs is under Snyk; SplxAI under Zscaler; SGNL under CrowdStrike; Protect AI under Palo Alto; Wiz under Google. Consolidation in this category is faster than any other 2025–26 security category.

| Platform | What it sells for agent governance | Self-hostable? |
|---|---|---|
| **Palo Alto Prisma AIRS** (+ Idira Agent Identity, Oct 2026) | Cryptographic agent identities, identity-aware MCP/tool authorization, agent registry, AI Gateway control plane | ❌ SaaS |
| **CrowdStrike Falcon agentic identity** (Fal.Con EU 2026) | Agentic Identity Provider, short-lived scoped access, dynamic revocation + SGNL continuous evaluation | ❌ SaaS |
| **Microsoft Entra Agent ID + Agent 365 + Purview** | First-class agent principals, sponsors/owners, agent inactivity policy (auto revolving), Conditional Access for agents, compliance via Purview | ❌ M365-ecosystem SaaS |
| **AWS Bedrock AgentCore** (Gateway, Identity, Policy/Dogwood-Cedar, Payments with spend limits, Registry with approval workflow, OTEL observability) | The most complete managed agentic control plane; deterministic tool-call interception | ❌ AWS-locked serverless |
| **Zscaler AI Security** (+ SplxAI) | MCP/A2A brokers with per-agent policies, AI Access Graph, 5,000-scenario red teaming, ATLAS/NIST/EU mapping | ❌ SaaS/SSE |
| **Cisco AI Defense** | Network-embedded runtime protection, red teaming, NIST/ATLAS/OWASP mapping | ❌ SaaS |
| **IBM watsonx.governance** | Governance suites of record: agent registries, 620+ controls, EU AI Act/NIST/ISO packs, human approval gates, evidence trails | ◐ SaaS + on-prem (Cloud Pak) |
| **Credo AI / Holistic AI / Saidot / Relyance** | Governance platforms-of-record: agent catalogues (owner/purpose/autonomy level), policy-to-code, approval workflows, Holistic's in-flight Operative agents, Relyance's allow/mask/escalate/block guard on agent actions | ❌ SaaS |
| **Nightfall / Lasso / Lakera / Prompt Security** | GenAI DLP for agents, MCP gateways with default-deny + per-tool policies, prompt-injection interception, runtime guardrails | ❌ SaaS |

**Takeaway:** the commercial market has converged on a checklist buyers expect:

1. **Identity attestation** (agent = cryptographic principal) — everyone now ships this.
2. **Least-privilege tool authorization** (identity/policy-aware MCP interception).
3. **Human approval workflows** with named reviewers and expiry.
4. **Kill switch / revocation** of burned agents.
5. **Audit-ready decision logs** mapped to compliance regimes (EU AI Act Art. 12/14, NIST AI RMF, ISO 42001).
6. **Spend/transaction budgets** — least-served capability; only AgentCore Payments and Relyance block concrete dollar values.

Everything in that list is SaaS or cloud-locked — **none of it is open and self-hostable** end-to-end.

---

## 2. Capability matrix: AgentOps vs the field

| Capability | AgentOps v1.1 | agentgateway | LiteLLM | Portkey | AgentCore | Prisma AIRS / CrowdStrike / Entra | watsonx.governance |
|---|---|---|---|---|---|---|---|
| Agent identity verification | ● token-checked per request | ◐ (token budgets per key) | ● (virtual keys) | ● | ● | ● (crypto IDs) | ◐ |
| Instant revocation / kill switch | ● per-agent + hot reload | ○ | ● | ◐ | ◐ | ● | ◐ |
| Destination allow-list | ● | ● | ◐ (per-key models) | ◐ | ◐ | ● | ◐ |
| Tool-level allow-list (MCP) | ● | ● | ● | ● | ● | ● | ◐ |
| Rate limits | ● per agent | ● | ● | ● | — | ◐ | ◐ |
| Transaction/spend caps | ● `amount_usd` per request + UTC-day ledger | ◐ (token budgets) | ◐ (token $ budgets) | ◐ | ● (Payments) | ○ | ◐ |
| Content detection (injection/PII/jailbreak) | ● LLM Guard, both directions configurable | ◐ | ● | ● | ◐ (via Guardrails) | ● | ◐ |
| malice-free return path scan | ◐ opt-in `verify_responses` | ◐ | ◐ | ● | ◐ | ● | ○ |
| Council-style deliberation | ● LangGraph Risk+Context+Arbiter with tunable thresholds | ○ | ◐ (extended spend limits only) | ○ | ○ | ○ | ◐ (eval automation) |
| Human-in-the-loop approval queue | ● pending queue + approve/reject API + expiry policy | ○ | ◐ | ◐ | ◐ (Registry approval) | ● (Entra sponsors/Agent365) | ● |
| Fail-open/fail-closed posture | ● config | ○ | ◐ | ◐ | — | — | — |
| Monitor mode | ● global/per-agent (`would_decision` A/B) | ○ | ◐ | ◐ | ○ | — | — |
| Audit trail (semantic) | ● Qdrant + `would_decision` | ● | ● | ● | ● (OTEL) | ● | ● |
| A2A/MCP protocol fluency | ◐ (MCP-style tool calls today) | ● | ● | ◐ | ● | ● | ○ |
| Threat-model mapping | ● OWASP-LM/Agentic + ATLAS-tagged in docs | ◐ | ● (own doc) | ◐ | ◐ | ● | ● |
| Self-hostable | ● FOSS, docker-compose to one binary | ● | ● | ◐ (OSS core) | ❌ | ❌ | ◐ |
| L4-L7 edge routing (mTLS, WAF-class) | ○ (delegated to APISIX in the reference stack) | ● | ◐ | ○ | ◐ | ● | ○ |

Legend: ● native · ◐ partial/adjacent · — absent. Others' assessments use vendor-published capabilities; corrections welcome via PR.

---

## 3. What this research changed in AgentOps (v1.1)

The comparison produced a concrete defect list and a concrete feature set; v1.1 fixes or adds each:

| Finding in the market | Gap in AgentOps v1.0 | v1.1 fix |
|---|---|---|
| Everyone (MCP spec, AgentCore, Entra, CrowdStrike) treats identity verification as the foundation; a self-asserted `agent_id` is untrustable | Connection existed but any request could claim any `agent_id` | `credential:` per connection + `X-Agentops-Auth` header; `${ENV_VAR}` resolution; hard config-error on missing secrets |
| Kill switch / revocation is table stakes in every 2026 product launch | Could only edit config and restart, agent's next request unaffected until restart | `enabled:` flag, `enabled:false` = instant deny, `POST /config/reload` |
| Tool least-privilege: OPA/Cedar/OpenFGA power, AgentCore Dogwood intercepts *every* tool call; LiteLLM has tool policies | `mcp_tools_allowed` was never enforced (dead config) | Enforced in phase 0 whenever `metadata.tool_name` is present; empty list = no tools |
| Budgets least-served capability market-wide | `rate_limit` declared but never enforced; no transaction value control | Sliding-window RateLimiter; `transaction_limit_usd`; UTC-day `daily_spend_limit_usd` ledger committing only on successful route |
| HITL weakness (OWASP-A): escalation that routes anyway | **ESCALATE decisions were routed as if ALLOWed** — the biggest v1.0 defect | Pending-approval store + queue + reviewer API, expiry with `on_timeout` policy; HITL disabled means ESCALATE = deny, never silent route |
| Fail-mode posture distinguishes detector-breakage from payload-danger (every serious vendor documents this) | Hardcoded fail-closed | `fail_open` / `fail_closed` config, applied only to infrastructure flags |
| Monitor-mode rollout capability (policy rehearsal, "would-block" telemetry) | — | global + per-agent `mode: monitor`, response records `would_decision`, allow-lists/kill switch still enforced |
| Return-path blind spot (OWASP LLM05/LLM02 on responses) | Only request-side scanning | optional `verify_responses` with `verify_output` on the verifier port |
| Council thresholds are deployment-specific | Hardcoded 0.3 / 0.7 in the arbiter | `governance.decision_thresholds` pulls from config |
| Regulatory mapping (EU AI Act Art. 12 logging / Art. 14 HITL / Art. 15 robustness; NIST AI RMF Measure/Manage) | No language for it | Audit semantics named; mapping documented here (§4) |

## 4. Compliance mapping (draft)

| Requirement | Where AgentOps evidences it |
|---|---|
| EU AI Act **Art. 14** (human oversight) | `governance.human_approval` + approval queue API; council arbiter escalation semantics |
| EU AI Act **Art. 12** (logging/record-keeping) | every decision → Qdrant audit; monitor-mode rehearsal records; reviewer actions audited |
| EU AI Act **Art. 15** (robustness/cybersecurity) | allow-lists, tool least-privilege, rate/spend caps, fail-closed default |
| EU AI Act **Art. 50** (transparency) | not addressed — out of a traffic gateway's scope |
| NIST AI RMF **Measure** | detection flags + confidence, council scores, `would_decision` telemetry |
| NIST AI RMF **Govern/Manage** | `agentops.yaml` as the auditable policy artefact; kill switch as rapid response |
| OWASP LLM10 / Agentic resource-overload | rate limits, daily spend caps |
| OWASP LLM01/02 + Agentic identity spoofing | verifier scanners; per-connection credentials; default-deny |

## 5. AgentOps's honest gaps (and a roadmap)

Ordered by what the market says buyers will hit first:

1. **A2A fluency** — gateway speaks "tool-ish" requests today; native Agent Card discovery + A2A task mediation belongs on the roadmap (agentgateway shows how).
2. **Policy-engine integration** — OPA/Rego or Cedar decision hooks behind the same phase-0 interface for orgs that have written policies there.
3. **Durable approval store** — swap Redis/Postgres behind `ApprovalStore` for HA (interface is already swap-shaped).
4. **Observability natively in OTel** — emit OTel GenAI/MCP spans alongside the Qdrant audit (Phoenix/AgentOps-compatible).
5. **Supply-chain scanning** — Cisco mcp-scanner / Snyk Agent Scan-class checks of which MCP servers/tools are declared in `agentops.yaml` (tool-reputation before phase-0 lets them through).
6. **Stronger crypto attribution** — mTLS or signed-claims (JWT with agent claims, e.g. LiteLLM's ID-JAG) rather than bearer tokens once the deployment deserves it.
7. **Sandboxed egress** — E2B-class egress allow/deny at the network layer beneath destination allow-lists.
8. **Rule evaluation upgrade** — replace keyword-scoring in the Context Agent with LLM-model rule adjudication (the intended next iteration of the council).

## 6. Sources

Primary vendor/docs pages verified November 2026 for each item cited above: modelcontextprotocol.io · a2a-protocol.org · agents.md · aaif.io · agentgateway.dev · docs.litellm.ai · github.com/Portkey-AI/gateway · docs.docker.com · docs.aws.amazon.com (Bedrock Guardrails, AgentCore) · developers.cloudflare.com/ai-gateway · github.com (Lasso, Cisco mcp-scanner, snyk/agent-scan, openfga, cedar, OPA, E2B, meta-llama/PurpleLlama, AgentOps, Arize Phoenix) · e2b.dev docs · paloaltonetworks.com · cisco.com · zscaler.com (+ splx.ai) · lakera.ai · prompt.security · snyk.io · invariantlabs.ai · crowdstrike.com · docs.nvidia.com/nemo/guardrails · mindgard.ai · learn.microsoft.com (Entra Agent ID, Agent 365) · cloud.google.com (Model Armor; Wiz) · aws.amazon.com/bedrock · ibm.com/products/watsonx-governance · credo.ai · holisticai.com · saidot.ai · relyance.ai · nightfall.ai · auth0.com/ai · genai.owasp.org · atlas.mitre.org (+ mitre-atlas/atlas-data) · nist.gov · artificialintelligenceact.eu · iso.org/standard/42001.
