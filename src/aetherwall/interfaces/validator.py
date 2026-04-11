from abc import ABC, abstractmethod
from typing import Any, Dict

from aetherwall.domain.models import AgentRequest, SecurityAnalysis, ValidationResult


class CoreGatewayValidatorInterface(ABC):
    """
    Council validation interface (e.g. LangGraph adapter).
    """

    @abstractmethod
    async def evaluate_request(
        self,
        request: AgentRequest,
        security_analysis: SecurityAnalysis,
        context: Dict[str, Any]
    ) -> ValidationResult:
        """
        Takes the request and the security analysis, invokes internal agents
        (Risk & Context), and debates if the request should proceed.
        """
        pass
