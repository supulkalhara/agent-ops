from abc import ABC, abstractmethod
from typing import Any

from aetherwall.domain.models import AgentRequest, ValidationResult


class APIRouterInterface(ABC):
    """
    Decoupled interface for the Routing Engine (e.g. APISIX adapter).
    """

    @abstractmethod
    async def route_request(self, request: AgentRequest, validation: ValidationResult) -> Any:
        """
        Routes the validated request to its destination.
        """
        pass

    @abstractmethod
    async def block_request(self, request: AgentRequest, reason: str) -> None:
        """
        Blocks the request at the edge.
        """
        pass
