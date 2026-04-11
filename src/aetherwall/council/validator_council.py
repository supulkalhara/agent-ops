"""
LangGraph Validator Council — implements CoreGatewayValidatorInterface.

Architecture
------------
Two specialised internal agents deliberate on every request:

  • **Risk Agent**    — assesses financial and security risk
  • **Context Agent** — checks contextual coherence and intent alignment

Their assessments flow through a LangGraph StateGraph:

    ┌───────────┐     ┌───────────────┐     ┌────────────────┐     ┌──────────┐
    │  START    │────▶│  Risk Agent   │────▶│ Context Agent  │────▶│ Arbiter  │
    └───────────┘     └───────────────┘     └────────────────┘     └──────────┘

The **Arbiter** node makes the final decision based on both assessments
and the configured policy rules from ``aether.yaml``.

All LLM calls go through LiteLLM, keeping the council decoupled from
any specific provider.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from aetherwall.domain.config import GatewayConfig
from aetherwall.domain.models import (
    ActionDecision,
    AgentRequest,
    SecurityAnalysis,
    ValidationResult,
)
from aetherwall.interfaces.validator import CoreGatewayValidatorInterface

logger = logging.getLogger(__name__)


# ── State Schema ──────────────────────────────────────────────────────


class CouncilState(TypedDict):
    """Shared state flowing through the council graph."""

    # Input
    agent_id: str
    destination: str
    payload: str
    security_flags: list[str]
    confidence_score: float
    is_safe: bool
    context: dict[str, Any]
    rules: list[str]

    # Agent assessments
    risk_assessment: str
    risk_score: float
    context_assessment: str
    context_aligned: bool

    # Final decision
    decision: str
    reasoning: str


# ── Agent Nodes ───────────────────────────────────────────────────────


async def _risk_agent_node(state: CouncilState) -> dict[str, Any]:
    """
    Risk Agent — evaluates financial and security risk.

    Uses heuristics + security analysis flags to produce a risk score.
    In production, this would call an LLM via LiteLLM for reasoning.
    """
    risk_score = 0.0
    assessments: list[str] = []

    # Factor 1: Security flags from verifier
    if state["security_flags"]:
        risk_score += 0.3 * len(state["security_flags"])
        assessments.append(
            f"Security flags detected: {', '.join(state['security_flags'])}"
        )

    # Factor 2: Confidence from verifier (higher = more dangerous)
    if not state["is_safe"]:
        risk_score += state["confidence_score"] * 0.4
        assessments.append(
            f"Verifier confidence of threat: {state['confidence_score']:.2f}"
        )

    # Factor 3: Check for high-value transaction patterns
    payload_lower = state["payload"].lower()
    high_risk_patterns = [
        "delete", "drop", "truncate", "transfer", "wire",
        "credential", "password", "secret", "admin",
    ]
    triggered = [p for p in high_risk_patterns if p in payload_lower]
    if triggered:
        risk_score += 0.2 * len(triggered)
        assessments.append(
            f"High-risk keywords detected: {', '.join(triggered)}"
        )

    # Normalize to [0, 1]
    risk_score = min(risk_score, 1.0)

    assessment_text = "; ".join(assessments) if assessments else "No risk factors identified"

    return {
        "risk_assessment": assessment_text,
        "risk_score": round(risk_score, 4),
    }


async def _context_agent_node(state: CouncilState) -> dict[str, Any]:
    """
    Context Agent — validates contextual coherence and intent.

    Checks if the request aligns with the agent's permissions and
    doesn't violate any configured policy rules.
    """
    violations: list[str] = []
    payload_lower = state["payload"].lower()

    # Check against configured rules
    for rule in state["rules"]:
        rule_lower = rule.lower()

        # Rule: topology disclosure
        if "topology" in rule_lower:
            topology_keywords = [
                "network", "subnet", "ip address", "internal",
                "topology", "architecture", "infrastructure",
            ]
            if any(kw in payload_lower for kw in topology_keywords):
                violations.append(
                    f"Potential rule violation: '{rule}'"
                )

        # Rule: high-value transactions
        if "transaction" in rule_lower and "$" in rule_lower:
            money_keywords = [
                "purchase", "buy", "transaction", "payment",
                "invoice", "transfer", "wire",
            ]
            if any(kw in payload_lower for kw in money_keywords):
                violations.append(
                    f"Potential rule violation: '{rule}'"
                )

        # Rule: user enumeration
        if "enumerate" in rule_lower or "credentials" in rule_lower:
            enum_keywords = [
                "list users", "all users", "credentials",
                "passwords", "enumerate", "dump",
            ]
            if any(kw in payload_lower for kw in enum_keywords):
                violations.append(
                    f"Potential rule violation: '{rule}'"
                )

    is_aligned = len(violations) == 0
    assessment = (
        "Request is contextually aligned with policy."
        if is_aligned
        else f"Context violations found: {'; '.join(violations)}"
    )

    return {
        "context_assessment": assessment,
        "context_aligned": is_aligned,
    }


async def _arbiter_node(state: CouncilState) -> dict[str, Any]:
    """
    Arbiter — makes the final decision based on both agents' assessments.

    Decision matrix:
    - High risk (>0.7) OR context violations → DENY
    - Medium risk (0.3-0.7) AND context aligned → ESCALATE
    - Low risk (<0.3) AND context aligned → ALLOW
    """
    risk_score = state["risk_score"]
    context_aligned = state["context_aligned"]

    parts: list[str] = [
        f"Risk assessment: {state['risk_assessment']} (score={risk_score:.2f})",
        f"Context assessment: {state['context_assessment']}",
    ]

    if risk_score > 0.7 or not context_aligned:
        decision = ActionDecision.DENY.value
        parts.append("DECISION: DENY — risk too high or context misaligned")
    elif risk_score > 0.3:
        decision = ActionDecision.ESCALATE.value
        parts.append("DECISION: ESCALATE — moderate risk, needs human review")
    else:
        decision = ActionDecision.ALLOW.value
        parts.append("DECISION: ALLOW — low risk and context aligned")

    return {
        "decision": decision,
        "reasoning": " | ".join(parts),
    }


# ── Council Graph Builder ─────────────────────────────────────────────


def build_council_graph() -> StateGraph:  # type: ignore[type-arg]
    """
    Build the LangGraph state graph for the Validator Council.

    Flow: risk_agent → context_agent → arbiter → END
    """
    graph = StateGraph(CouncilState)

    graph.add_node("risk_agent", _risk_agent_node)
    graph.add_node("context_agent", _context_agent_node)
    graph.add_node("arbiter", _arbiter_node)

    graph.set_entry_point("risk_agent")
    graph.add_edge("risk_agent", "context_agent")
    graph.add_edge("context_agent", "arbiter")
    graph.add_edge("arbiter", END)

    return graph


# ── Interface Implementation ──────────────────────────────────────────


@dataclass
class ValidatorCouncil(CoreGatewayValidatorInterface):
    """
    LangGraph-based validator council implementing the
    CoreGatewayValidatorInterface.

    Spins up the Risk and Context agents, runs them through
    the LangGraph pipeline, and returns the council's decision.
    """

    config: GatewayConfig = field(default_factory=GatewayConfig)
    _compiled_graph: Any = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        graph = build_council_graph()
        self._compiled_graph = graph.compile()

    async def evaluate_request(
        self,
        request: AgentRequest,
        security_analysis: SecurityAnalysis,
        context: dict[str, Any],
    ) -> ValidationResult:
        """
        Run the full council deliberation on a request.
        """
        # Build the initial state from the request + analysis
        initial_state: CouncilState = {
            "agent_id": request.agent_id,
            "destination": request.destination,
            "payload": request.payload,
            "security_flags": security_analysis.flags,
            "confidence_score": security_analysis.confidence_score,
            "is_safe": security_analysis.is_safe,
            "context": context,
            "rules": self.config.validation_council.rules,
            # Placeholders — filled by agents
            "risk_assessment": "",
            "risk_score": 0.0,
            "context_assessment": "",
            "context_aligned": True,
            "decision": "",
            "reasoning": "",
        }

        logger.info(
            "Council deliberating on request %s from agent %s",
            request.request_id,
            request.agent_id,
        )

        # Run the graph
        final_state = await self._compiled_graph.ainvoke(initial_state)

        # Map the string decision back to our enum
        decision_str = final_state["decision"]
        try:
            decision = ActionDecision(decision_str)
        except ValueError:
            logger.warning(
                "Unknown decision '%s', defaulting to DENY",
                decision_str,
            )
            decision = ActionDecision.DENY

        return ValidationResult(
            decision=decision,
            reasoning=final_state["reasoning"],
        )
