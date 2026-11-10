"""
Qdrant audit logger — stores every gateway decision as a vector point.

Each processed request produces an audit record stored in Qdrant,
enabling semantic search over past decisions (e.g. "show me all
blocked prompt injection attempts this week").

The logger is intentionally decoupled from the gateway pipeline —
it's called after pipeline completion, not during, to avoid latency.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)

from agent_ops.domain.models import GatewayResponse

logger = logging.getLogger(__name__)

# Simple payload hashing for deterministic vector generation
# In production, you'd use a proper embedding model via LiteLLM
_VECTOR_DIM = 48


def _payload_to_vector(text: str) -> list[float]:
    """
    Generate a deterministic pseudo-vector from text via hashing.

    This is a placeholder for development and testing. In production,
    replace with an embedding model call via LiteLLM.
    """
    h = hashlib.sha384(text.encode()).digest()
    return [float(b) / 255.0 for b in h]


@dataclass
class QdrantAuditLogger:
    """
    Stores gateway audit records in Qdrant for semantic search.

    Parameters
    ----------
    host : str
        Qdrant server hostname.
    port : int
        Qdrant REST API port.
    api_key : str
        Qdrant API key (if auth is enabled).
    collection_name : str
        Name of the Qdrant collection for audit logs.
    """

    host: str = "qdrant"
    port: int = 6333
    api_key: str = ""
    collection_name: str = "agent_ops_audit"
    _client: AsyncQdrantClient | None = None

    async def _ensure_client(self) -> AsyncQdrantClient:
        """Lazily initialise the Qdrant async client."""
        if self._client is None:
            self._client = AsyncQdrantClient(
                host=self.host,
                port=self.port,
                api_key=self.api_key or None,
            )
        return self._client

    async def ensure_collection(self) -> None:
        """Create the audit collection if it doesn't exist."""
        client = await self._ensure_client()
        collections = await client.get_collections()
        existing = {c.name for c in collections.collections}

        if self.collection_name not in existing:
            await client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=_VECTOR_DIM,
                    distance=Distance.COSINE,
                ),
            )
            logger.info("Created Qdrant collection: %s", self.collection_name)

    async def log_decision(
        self,
        request_id: str,
        agent_id: str,
        destination: str,
        payload: str,
        response: GatewayResponse,
    ) -> str:
        """
        Store a gateway decision as a vector point in Qdrant.

        Returns the point ID for reference.
        """
        client = await self._ensure_client()
        point_id = str(uuid.uuid4())

        # Build the audit payload
        audit_payload: dict[str, Any] = {
            "request_id": request_id,
            "agent_id": agent_id,
            "destination": destination,
            "decision": response.decision.value,
            "reasoning": response.reasoning,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if response.security_analysis:
            audit_payload["security_flags"] = response.security_analysis.flags
            audit_payload["confidence_score"] = (
                response.security_analysis.confidence_score
            )

        # Generate vector from the payload text
        vector = _payload_to_vector(payload)

        await client.upsert(
            collection_name=self.collection_name,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=audit_payload,
                )
            ],
        )

        logger.info(
            "Logged audit point %s for request %s",
            point_id,
            request_id,
        )
        return point_id

    async def search_similar(
        self, query_text: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        """
        Semantic search over audit logs.

        Returns the top-k most similar audit records to the query text.
        """
        client = await self._ensure_client()
        vector = _payload_to_vector(query_text)

        results = await client.query_points(
            collection_name=self.collection_name,
            query=vector,
            limit=limit,
        )

        return [
            {
                "id": str(point.id),
                "score": point.score,
                "payload": point.payload,
            }
            for point in results.points
        ]

    async def close(self) -> None:
        """Close the Qdrant client."""
        if self._client:
            await self._client.close()
            self._client = None
