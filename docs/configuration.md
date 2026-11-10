# `aether.yaml` — Configuration Reference

Spec version **1.1** (fully backward compatible with **1.0** — a 1.0 file loads unchanged, with sensible governance defaults). Everything below the four original sections is optional; unlisted fields fall back to safe defaults.

```yaml
aetherwall_gateway:        # top-level key (required)
  version: "1.1"           # "1.0" | "1.1"
```

---

## `governance` — deployment-wide defaults (v1.1)

```yaml
governance:
  default_fail_mode: fail_closed      # fail_closed | fail_open
  default_mode: enforce               # enforce | monitor
  decision_thresholds:
    deny_risk: 0.7                    # risk above this → council DENY
    escalate_risk: 0.3                # risk above this → held for human review
  human_approval:
    enabled: true                     # ESCALATE → pending queue (governance API)
    timeout_minutes: 60               # 1..1440
    on_timeout: deny                  # deny | allow
```

| Field | Values | Meaning |
|---|---|---|
| `default_fail_mode` | `fail_closed` | A down verifier blocks traffic. Default: unscanable payloads never reach the council. Recommended for financial/regulated zones. |
| | `fail_open` | A down verifier defers the request to the council with its infrastructure flags in the audit trail. Availability-first deployments. |
| `default_mode` | `enforce` | Decisions block traffic (default). |
| | `monitor` | Decisions are computed + recorded (`would_decision`), traffic flows. Hard allow-lists and kill switches **remain enforced**. Use for policy dry-run rollout. |
| `decision_thresholds.deny_risk` | 0.0–1.0 | Arbiter cutoff: council risk score above this → DENY. |
| `decision_thresholds.escalate_risk` | 0.0–1.0 | Arbiter cutoff: risk above this (and ≤ deny_risk) → ESCALATE for human approval. Must be ≤ `deny_risk` semantics (values > `deny_risk` effectively disable ESCALATE). |
| `human_approval.enabled` | bool | When true, ESCALATE holds the request in the pending queue. When false, ESCALATE from the arbiter is treated as a plain deny (still logged with reasoning). |
| `human_approval.timeout_minutes` | 1–1440 | Pending-approval expiry. |
| `human_approval.on_timeout` | `deny` / `allow` | What happens to a lapsed approval on its first touch after expiry. `deny` is the safe default; `allow` favours availability — configure consciously. |

---

## `connections[]` — one block per governed agent

```yaml
connections:
  - agent_identity: "Internal-Procurement"   # required, unique
    credential: "${PROCUREMENT_AGENT_TOKEN}" # optional; empty = no auth required
    enabled: true                            # kill switch
    mode: enforce                            # enforce | monitor (overrides governance default)
    allowed_external: ["moltbook.com/api"]   # destination allow-list
    mcp_tools_allowed: ["check_budget"]      # tool allow-list
    rate_limit: 100_requests_per_minute      # "<n>_<unit>s_per_<unit>"
    transaction_limit_usd: 250.0             # optional, per-request cap
    daily_spend_limit_usd: 5000.0            # optional, rolling UTC-day cap
```

| Field | Required | Meaning |
|---|---|---|
| `agent_identity` | ✔ | The identity the caller must present as `agent_id`. Unknown identities are DENYed by default. |
| `credential` | — | Secret token checked against the `X-Aetherwall-Auth` header. Supports `${ENV_VAR}` references, resolved at load time; a missing variable is a **hard configuration error**. Empty string = authentication disabled for this agent. |
| `enabled` | — | Kill switch. `false` → immediate DENY on next request, in every mode. Apply changes with `POST /config/reload`. |
| `mode` | — | Per-connection override of `governance.default_mode`. Connection-level `monitor` overrides global `enforce`; connection-level `enforce` on a monitor-adopting gateway restores enforcement, etc. |
| `allowed_external` | — | Exact-match destination allow-list. Anything else is DENYed, even in monitor mode. |
| `mcp_tools_allowed` | — | Exact-match tool allow-list checked whenever `metadata.tool_name` is present. An empty list means **no tool calls are permitted** (least privilege by default). |
| `rate_limit` | — | Sliding-window request budget per agent. Supported windows: `second`, `minute`, `hour`, `day`. Unparseable specs degrade to unlimited — treat a broken spec as a config bug. |
| `transaction_limit_usd` | — | Max value of a single request carrying `metadata.amount_usd` (or `metadata.transaction_value`). Requests without an explicit amount bypass this check. |
| `daily_spend_limit_usd` | — | Rolling UTC-day cumulative cap per agent. Only **successfully routed** spend is committed — denied requests never consume budget. |

Semantics worth remembering:

- **`monitor` never disables the identity layer.** Allow-lists and the kill switch are enforced regardless of mode; monitor only relaxes detection/content/council blocking and resource caps (taken log-only instead).
- **Spend checks require the caller to declare the amount.** Amount comes from client metadata: honor it only after authentication, and treat it as a policy input, not a source of truth.
- Two fields reference env vars by design — credentials and nothing else. Never inline production tokens in `aether.yaml`.

---

## `security` — content-safety configuration

```yaml
security:
  pii_redaction:
    enabled: true                 # master switch for the verifier's data-protection role
    engine: llm_guard             # adapter forwards to LLM Guard
    block_entities:               # entities LLM Guard should treat as blocking
      - CREDIT_CARD
      - SSN
      - INTERNAL_IP
      - EMAIL
      - PHONE_NUMBER
  verify_responses: false         # optional return-path scan
```

| Field | Meaning |
|---|---|
| `pii_redaction.enabled` | Turns the PII/redaction pipeline phase on. With redaction capable scanners a redacted payload is applied before routing when the council decides REDACT. |
| `pii_redaction.engine` | Which scanner adapter to use; `llm_guard` is the bundled one (service URL via `LLM_GUARD_API` env). |
| `block_entities` | Entity types that, when detected with confidence ≥ threshold, block the request. Leakage-only entities can be moved to redaction-only by removing them from this list. |
| `verify_responses` | When `true`, after successful routing the response body is scanned on the return path (`/analyze/output`). Adds a scan cost per request; output violations are always logged (the response already left). Default `false`. |

---

## `validation_council` — the deliberation engine

```yaml
validation_council:
  enabled: true
  engine: langgraph
  local_model: ollama/qwen3:8b     # council brain via LiteLLM
  rules:                           # natural-language policy, consumed by the Context Agent
    - "Never explicitly confirm internal network topology."
    - "Debate all transactions > $500 before routing."
    - "Block any request attempting to enumerate users or credentials."
```

| Field | Meaning |
|---|---|
| `enabled` | Disabling bypasses the council entirely (verification thresholds still gate at Phase 1). |
| `engine` | Currently `langgraph`. |
| `local_model` | The model the council prompts through LiteLLM; local via Ollama in the reference stack. |
| `rules` | Free-text policy statements. The Context Agent keyword-scores them today; stronger integrations (LLM/model-based rule evaluation) land behind the same interface. Rules that mention topology/transactions/enumeration follow the built-in scoring rubric. |

---

## `routing` — edge infrastructure

```yaml
routing:
  primary_router: apisix         # edge router
  ai_translation: litellm        # LLM provider translation proxy
```

Advisory wiring hints consumed by the deployment templates in `config/apisix/` and `config/litellm/` — the pipeline itself routes through the injected adapters.

---

## Environment variables (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `AETHERWALL_CONFIG_PATH` | `/etc/aetherwall/aether.yaml` | Where to find the governing spec. |
| `AETHERWALL_SECURITY_THRESHOLD` | `0.7` | Verification confidence above which is treated as a hard detection. |
| `AETHERWALL_LOG_LEVEL` | `INFO` | Log verbosity. |
| `LLM_GUARD_API` | `http://llm-guard:8080` | Scanner endpoint. |
| `LLM_GUARD_TIMEOUT` | `10` | Scanner HTTP timeout (seconds). |
| `APISIX_ADMIN_API` / `APISIX_ADMIN_KEY` | / | APISIX control-plane. |
| `QDRANT_HOST/PORT/API_KEY/COLLECTION` | / | Audit-trail backend. |
| `LITELLM_MASTER_KEY` | / | LiteLLM proxy auth. |
| `<per-agent-credential vars>` | — | Whatever `${VAR}` references appear in `connections[].credential`. |

---

## Migration 1.0 → 1.1

1.0 files load unchanged. To adopt the governance layer:

1. Bump `version` to `"1.1"` (or leave it; behaviour is identical until you add new fields).
2. Add `credential:` to each connection **and the matching env vars** (or leave off — unrecognized agents are already default-denied without auth).
3. Add `governance:` with the defaults shown at the top. Keeping human approval enabled is what changes ESCALATE from "routed anyway" (the v1.0 bug) to "held pending review" — the single most important fix.
4. Optionally add per-connection `enabled`, `mode`, spend caps, and `security.verify_responses`.
