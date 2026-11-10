# HTTP API Reference

The gateway exposes a small, governance-focused surface. Everything funnels through `/gateway/process`; the rest is administration of decisions and approvals.

## `POST /gateway/process`

Run one agent request through the governed pipeline.

**Auth header (optional):** `X-Aetherwall-Auth: <token>` — required whenever the connection in `aether.yaml` declares a `credential`; a missing or mismatched header yields decision `deny` (*Authentication failed*) rather than an error leak.

```jsonc
// Request body
{
  "agent_id": "Internal-Procurement",
  "destination": "moltbook.com/api",
  "payload": "Check budget for PO-2024-001",
  "metadata": {
    "tool_name": "check_budget",     // triggers the MCP tool allow-list check
    "amount_usd": 42.5               // triggers transaction / daily-spend caps
  },
  "context": { "tenant": "acme" }    // arbitrary; passed to the council
}
```

**Responses:**

| Status | Meaning |
|---|---|
| `200` | A decision was settled: `allow` (routed), `deny` (policy/limit), `escalate` (held for human approval) |
| `403` | **security_violation** — payload tripped verification above `security_threshold` |
| `422` | **validation_rejected** — the council denied, or escalated while HITL is disabled |
| `502` | **routing_error** — upstream unreachable/failed |
| `503` | Pipeline not initialized (readiness race) |

```jsonc
// 200 response
{
  "request_id": "2a4c...",
  "decision": "allow",              // allow | deny | escalate | redact — monitor mode always reports allow
  "reasoning": "...",               // council/policy rationale
  "route_result": { ... },          // adapter output (null for denied/held)
  "security_flags": [],             // flags from request verification
  "confidence_score": 0.0,
  "output_flags": [],               // flags from response verification (if enabled)
  "approval_id": null,              // set when decision == "escalate"
  "monitor_mode": false,            // true when monitor mode allowed flagged traffic
  "would_decision": null            // what monitor mode *would* have decided
}
```

**Client guidance for agents:** treat `escalate` as an asynchronous pending state — keep or re-fetch the record and poll `GET /governance/approvals` or resubmit after the reviewer's decision. Treat `monitor_mode: true` as "this call is being observed, not yet governed".

---

## `GET /governance/approvals`

List requests held for human review, oldest first:

```jsonc
{
  "count": 1,
  "approvals": [
    {
      "approval_id": "b1f8...",
      "agent_id": "Internal-Procurement",
      "destination": "moltbook.com/api",
      "payload": "DELETE FROM orders WHERE status='pending'; ...",
      "reasoning": "Risk assessment: ... (score=0.45) | Context assessment: ... ",
      "created_at": "2026-11-10T09:00:12.101+00:00",
      "expires_at": "2026-11-10T10:00:12.101+00:00"
    }
  ]
}
```

Wire this into a reviewer's channel (Slack bot, ops dashboard) — the queue is in-memory on this node, so integrate against a long-lived instance.

---

## `POST /governance/approvals/{approval_id}/decision`

Settle a pending approval.

```jsonc
// body
{
  "action": "approve",        // approve | reject
  "reviewer": "jane@security",
  "comment": "Verified against PO ledger"   // optional
}
```

**Responses**

| Status | Meaning |
|---|---|
| `200` | Settled — decision `allow` (approved) or `deny` (rejected) with reasoning. Approving resumes routing of the held request; `route_result` is populated. |
| `404` | Unknown approval id. |
| `409` | Already resolved (approved/rejected before). |
| `500` | Internal failure while resuming routing. |

Approving an expired approval settles it per the `on_timeout` policy instead — `deny` (default) or `allow`.

---

## `POST /config/reload`

Hot-reload `aether.yaml` without restarting:

```jsonc
{ "status": "reloaded", "config_version": "1.1" }
```

Use it for the kill-switch and policy-change flows: edit `aether.yaml`, flip `enabled: false` for a burned agent, reload. Failed reloads return `500` and keep the previous config.

---

## `GET /audit/search?q=...`

Semantic search over every recorded decision (allowed, denied, escalated, reviewer actions, monitor verdicts):

```
GET /audit/search?q=topology probe attempts&limit=20
```

Returns the most similar audit points: `id`, `score`, and the payload (request/decision/flags/timestamp). This is the forensic and compliance-relevant window into the gateway's history.

---

## `GET /healthz`, `GET /readyz`

Liveness (always OK when the process runs) and readiness (pipeline assembled, config parsed with its version). `readyz` fails with `503` + a check breakdown if the pipeline isn't wired.

---

## Status code summary

| Code | Trigger | Client action |
|---|---|---|
| 200 | Decision settled | Honor `decision` field |
| 403 | Security violation | Drop; inspect `security_flags` |
| 409 | Approval double-resolve | Stop polling; treat as settled |
| 422 | Council rejection | Drop; read `reasoning` |
| 500 | Gateway error | Retry with backoff |
| 502 | Routing failure | Retry later; upstream may be down |
| 503 | Not initialized / not ready | Wait and retry |
