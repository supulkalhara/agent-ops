from abc import ABC, abstractmethod

from aetherwall.domain.models import AgentRequest, SecurityAnalysis

# Infrastructure-unavailability flags emitted by verifier adapters.
INFRASTRUCTURE_FLAGS = frozenset({"llm_guard_error", "llm_guard_unreachable"})


class SecurityVerifierInterface(ABC):
    """
    Stateless inspection interface (e.g. LLM Guard adapter).

    Covers both directions of agent traffic:
      • ``verify_payload`` — inbound requests (prompt side)
      • ``verify_output``  — outbound responses (return path), used when
        ``security.verify_responses`` is enabled in `aether.yaml`.
    """

    @abstractmethod
    async def verify_payload(self, request: AgentRequest) -> SecurityAnalysis:
        """
        Analyzes the payload for toxicity, PII, and jailbreaks.
        """
        pass

    @abstractmethod
    async def verify_output(
        self, request: AgentRequest, response_text: str
    ) -> SecurityAnalysis:
        """
        Analyzes a response body being routed back to the calling agent.

        Guards the return path: exfiltrated data, malicious content, or
        injected instructions travelling to the agent.
        """
        pass
