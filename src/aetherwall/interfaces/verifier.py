from abc import ABC, abstractmethod

from aetherwall.domain.models import AgentRequest, SecurityAnalysis


class SecurityVerifierInterface(ABC):
    """
    Stateless inspection interface (e.g. LLM Guard adapter).
    """

    @abstractmethod
    async def verify_payload(self, request: AgentRequest) -> SecurityAnalysis:
        """
        Analyzes the payload for toxicity, PII, and jailbreaks.
        """
        pass
