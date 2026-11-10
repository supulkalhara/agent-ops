"""
APISIX adapter — implements APIRouterInterface.

Routes validated requests through Apache APISIX and logs blocked
requests via the admin API. In production, APISIX handles the actual
upstream proxying; this adapter manages the control plane.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from agent_ops.domain.models import AgentRequest, ValidationResult
from agent_ops.interfaces.router import APIRouterInterface

logger = logging.getLogger(__name__)


@dataclass
class APISIXRouter(APIRouterInterface):
    """
    Concrete router using the APISIX Admin API.

    Parameters
    ----------
    admin_url : str
        Base URL of the APISIX Admin API.
    admin_key : str
        APISIX admin API key for authentication.
    proxy_url : str
        Base URL of the APISIX proxy for forwarding requests.
    timeout : float
        HTTP request timeout in seconds.
    """

    admin_url: str = "http://apisix:9180"
    admin_key: str = ""
    proxy_url: str = "http://apisix:9080"
    timeout: float = 10.0
    _client: httpx.AsyncClient = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def route_request(
        self, request: AgentRequest, validation: ValidationResult
    ) -> Any:
        """
        Forward the validated request through APISIX proxy.

        The request is sent as a POST to the proxy URL with the agent's
        destination as the path. APISIX handles upstream resolution,
        load balancing, and mTLS.
        """
        target_url = f"{self.proxy_url}/{request.destination}"

        headers = {
            "X-AgentOps-Request-ID": request.request_id,
            "X-AgentOps-Agent-ID": request.agent_id,
            "X-AgentOps-Decision": validation.decision.value,
            "Content-Type": "application/json",
        }

        logger.info(
            "Routing request %s to %s (decision=%s)",
            request.request_id,
            target_url,
            validation.decision.value,
        )

        response = await self._client.post(
            target_url,
            json={
                "payload": request.payload,
                "metadata": request.metadata,
            },
            headers=headers,
        )
        response.raise_for_status()

        return {
            "status": "routed",
            "destination": request.destination,
            "status_code": response.status_code,
            "request_id": request.request_id,
        }

    async def block_request(
        self, request: AgentRequest, reason: str
    ) -> None:
        """
        Log the blocked request. In production, this could also update
        APISIX's blocklist via the Admin API to ban repeat offenders.
        """
        logger.warning(
            "BLOCKED request_id=%s agent=%s destination=%s reason=%s",
            request.request_id,
            request.agent_id,
            request.destination,
            reason,
        )

    async def close(self) -> None:
        """Close the HTTP client gracefully."""
        await self._client.aclose()
