# Guardrails Catalog

Every guardrail AetherWall ships, how to configure it, what it defends against, and the method it fails-safe under.

Legends for mapping: **[OWASP-A]** = [OWASP Agentic AI Threats & Mitigations](https://genai.owasp.org/resources/agentic-ai-threats-and-mitigations/) threat class · **[OWASP-LLM]** = [OWASP Top 10 for LLM Apps](https://genai.owasp.org) · **[ATLAS]** = MITRE ATLAS technique family · **[MCP]** = MCP security best-practice guidance.

---

## 1. Identity guardrails

### 1.1 Agent authentication
- **Config:** `connections[].credential: "${ENV_VAR_OR_LITERAL}"` (empty = auth not required).
- **Behavior:** caller must present the matching token in `X-Aetherwall-Auth`. Credentials support `${ENV_VAR}` references resolved at load time; a missing env var is a hard configuration error (never silently disable auth).
- **Defends against:** identity spoofing [OWASP-A], repudiation [OWASP-A] — every decision is attributable to a verified principal, not a self-asserted `agent_id`. This is the scoped-down, gateway-centric version of what enterprise products now sell as "Agent Identity".
- **Fails safe when:** token missing/mismatched → DENY.

### 1.2 Kill switch / instant revocation
- **Config:** `connections[].enabled: false`, then `POST /config/reload`.
- **Behavior:** revoked agent gets an immediate DENY on its next request. Enforced in **all modes** including monitor.
- **Defends against:** a hijacked or misbehaving agent [OWASP-A privilege compromise], the "agent is burned, now what?" problem every enterprise platform added 2026 feature-launch support for (Entra inactivity policy, CrowdStrike revocation, AgentCore policy interception).
- **Fails safe when:** — the switch is the safe state.

### 1.3 Default-deny for unknown agents
- **Behavior:** no connection spec → immediate DENY. You cannot be governed if you are not declared.
- **Defends against:** shadow agents [OWASP-A supply chain], first-contact attacks.

## 2. Connectivity guardrails

### 2.1 Destination allow-list
- **Config:** `connections[].allowed_external: [...]`
- **Behavior:** hard DENY for any destination not listed. Enforced in monitor mode too.
- **Defends against:** data exfiltration to attacker-controlled endpoints [OWASP-LLM02], cross-agent lateral access, SSRF-flavored escalation [MCP best practices].

### 2.2 MCP tool least-privilege
- **Config:** `connections[].mcp_tools_allowed: [...]`
- **Behavior:** when `metadata.tool_name` is present, it must be in this list or the call is DENYed. An agent with no list may not call tools at all.
- **Defends against:** tool misuse [OWASP-A], excessive agency [OWASP-LLM06], confused-deputy tool attacks [MCP]. This is enforcement of the "*tool* neither available nor callable" principle that policy engines (Cedar/OpenFGA/OPA) provide long-hand.

## 3. Resource guardrails

### 3.1 Rate limits
- **Config:** `connections[].rate_limit: "<n>_<unit>s_per_<unit>"` (e.g. `100_requests_per_minute`; unparseable specs are treated as unlimited — validate your deployments).
- **Behavior:** sliding-window limiter keyed by agent. Exceeding it DENYs the request (records it in monitor mode).
- **Defends against:** resource overload / unbounded consumption [OWASP-LLM10, OWASP-A], runaway loops.

### 3.2 Transaction caps
- **Config:** `connections[].transaction_limit_usd: <float>`
- **Behavior:** request metadata carrying `amount_usd` (or `transaction_value`) above the cap is DENYed before it costs anything.
- **Defends against:** the "$12,400 unauthorized refund" class of failure — the gap the 2026 market treats as least-served (only AgentCore Payments and Relyance Guard are comparable, both commercial).

### 3.3 Daily spend caps
- **Config:** `connections[].daily_spend_limit_usd: <float>`
- **Behavior:** UTC-day cumulative ledger per agent; a transaction that would breach the cap is DENYed. Spend commits only after successful routing — denies don't consume budget, and cost attribution is exact.
- **Defends against:** cumulative exfiltration-by-many-small-transfers, budget runaway, day-scale attacks that evade per-request caps.

## 4. Content guardrails

### 4.1 Inbound payload scanning (request path)
- **Config:** `security.pii_redaction.{enabled,engine,block_entities}`; global threshold via `AETHERWALL_SECURITY_THRESHOLD` env (default 0.7).
- **Behavior:** LLM Guard scans for prompt injection, jailbreaks, PII, secrets, toxic/gibberish content; produces flags, a confidence score, and (when a scanner supports it) a redacted payload the pipeline routes downstream.
- **Defends against:** prompt injection [OWASP-LLM01, OWASP-A], sensitive data in transit [OWASP-LLM02], jailbreaks [ATLAS].

### 4.2 Response scanning (return path, optional)
- **Config:** `security.verify_responses: true` (default false — costs a second scan per request).
- **Behavior:** after routing, the response body is scanned at the LLM Guard output endpoint. Violations are flagged loudly in logs/audit — the bytes already left, so blocking is impossible, but detection enables response-side incident response.
- **Defends against:** indirect/second-stage attacks via return traffic [OWASP-A memory-poisoning/incidental channel], exfiltration acknowledgment — the blind spot of most request-only gateways.

### 4.3 Natural-language policy rules (council input)
- **Config:** `validation_council.rules: ["..."]`
- **Behavior:** the Context Agent evaluates requests against your written rules (topology disclosure, enumeration attempts, transaction thresholds) as scored policy signals.
- **Defends against:** org-specific policy that no generic scanner knows about (what information you may confirm, in which terms).

## 5. Decision-in-depth guardrails

### 5.1 Council thresholds
- **Config:** `governance.decision_thresholds: {deny_risk: 0.7, escalate_risk: 0.3}`
- **Behavior:** tunable risk cutoffs in the arbiter's decision matrix; lower `escalate_risk` for a bigger human-review queue in sensitive deployments, or raise it when the queue overflows.
- **Defends against:** one-size-fits-all risk appetite — thresholds are deployment-taste dependent, not code constants.

### 5.2 Human-in-the-loop approvals
- **Config:** `governance.human_approval: {enabled: true, timeout_minutes: 60, on_timeout: deny|allow}`
- **Behavior:** ESCALATE → held pending (`ApprovalStore`), reviewer queue/API, expiry settles per the configured policy. Memory-bounded queue (oldest-expired eviction).
- **Defends against:** HITL weaknesses [OWASP-A] — the anti-pattern of "escalated but routed anyway". Expired approvals do not silently turn into routing; they become DENY by default.
- **Fails safe when:** reviewer doesn't respond → DENY (default).

### 5.3 Fail mode (detector outage posture)
- **Config:** `governance.default_fail_mode: fail_closed` (default) or `fail_open`.
- **Behavior:** governs what happens when the *verifier itself* is down/unreachable — block (fail-closed) or defer to the council with flags attached (fail-open). Never silently: both paths log + audit.
- **Defends against:** the "detector outage turns into either an outage for legitimate traffic or a silent bypass" dilemma. Choose fail-closed for regulated/financial zones, fail-open for availability-critical ones.

### 5.4 Monitor mode (policy dry-run)
- **Config:** `governance.default_mode: monitor` (global) or `connections[].mode: monitor` (per-connection).
- **Behavior:** every decision computed and recorded (`would_decision` in the response + audit), while traffic flows. Hard allow-lists and kill switches stay enforced — you roll out *detection*, not identity policy.
- **Defends against:** policy regression risk when changing thresholds/rules on live traffic — measure then enforce.

---

## 6. Guardrails by rollout phase

A recommended sequence when bringing an agent fleet under governance:

1. **Phase A — discover.** Global `default_mode: monitor`, everything allowed. Run 1–2 weeks; read the audit trail for `would_decision` density and false positives.
2. **Phase B — constrain.** Tighten allow-lists and tool lists (still enforced in monitor). Tune `decision_thresholds` against observed traffic.
3. **Phase C — enforce.** `default_mode: enforce` for benign agents; keep any risky agent in monitor until its patterns are understood; enable `verify_responses` for sensitive destinations.
4. **Phase D — govern.** Enable `human_approval` with a realistic `timeout_minutes` and `on_timeout: deny`. Wire `/governance/approvals` into your ops channel/Slack review bot.

Each phase is configuration + a `POST /config/reload`.
