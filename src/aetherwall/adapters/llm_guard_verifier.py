"""
LLM Guard adapter — implements SecurityVerifierInterface.

Wraps the LLM Guard REST API for stateless payload inspection:
  • Prompt injection detection
  • PII detection and redaction
  • Toxicity classification
  • Jailbreak attempt identification

The adapter is fully stateless — each call is an independent HTTP request,
keeping the verification layer horizontally scalable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from aetherwall.domain.models import AgentRequest, SecurityAnalysis
from aetherwall.interfaces.verifier import SecurityVerifierInterface

logger = logging.getLogger(__name__)

# Scanners that map to specific threat categories
_THREAT_SCANNER_MAP: dict[str, str] = {
    "PromptInjection": "prompt_injection",
    "BanTopics": "banned_topic",
    "Toxicity": "toxicity",
    "Regex": "regex_match",
    "Secrets": "secret_detected",
    "Sentiment": "negative_sentiment",
    "TokenLimit": "token_limit_exceeded",
    "InvisibleText": "invisible_text",
    "Gibberish": "gibberish",
    "LanguageSame": "language_mismatch",
    "Code": "code_detected",
}


@dataclass
class LLMGuardVerifier(SecurityVerifierInterface):
    """
    Concrete verifier using the LLM Guard REST API.

    Parameters
    ----------
    api_url : str
        Base URL of the LLM Guard API (e.g. ``http://llm-guard:8080``).
    timeout : float
        HTTP request timeout in seconds.
    """

    api_url: str = "http://llm-guard:8080"
    timeout: float = 10.0
    _client: httpx.AsyncClient = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.api_url,
            timeout=self.timeout,
        )

    async def verify_payload(self, request: AgentRequest) -> SecurityAnalysis:
        """
        Send the payload to LLM Guard for scanning.

        Returns a SecurityAnalysis with detected flags and an optional
        redacted (sanitized) version of the payload.
        """
        try:
            response = await self._client.post(
                "/analyze/prompt",
                json={"prompt": request.payload},
            )
            response.raise_for_status()
            data = response.json()

            return self._parse_response(data, request.payload)

        except httpx.HTTPStatusError as exc:
            logger.error(
                "LLM Guard returned HTTP %d: %s",
                exc.response.status_code,
                exc.response.text,
            )
            # Fail-closed: treat errors as unsafe
            return SecurityAnalysis(
                is_safe=False,
                confidence_score=1.0,
                flags=["llm_guard_error"],
            )
        except httpx.RequestError as exc:
            logger.error("LLM Guard unreachable: %s", exc)
            return SecurityAnalysis(
                is_safe=False,
                confidence_score=1.0,
                flags=["llm_guard_unreachable"],
            )

    def _parse_response(
        self, data: dict[str, Any], original_payload: str
    ) -> SecurityAnalysis:
        """Parse the LLM Guard response into our domain model."""
        is_valid: bool = bool(data.get("is_valid", True))
        sanitized: str | None = data.get("sanitized_prompt", None)
        scanners: list[dict[str, Any]] = data.get("results", [])

        flags: list[str] = []
        max_risk: float = 0.0

        for scanner in scanners:
            scanner_name: str = scanner.get("scanner_name", "")
            risk_score: float = float(scanner.get("risk_score", 0.0))
            is_triggered: bool = bool(scanner.get("is_detected", False))

            if is_triggered:
                threat_type = _THREAT_SCANNER_MAP.get(
                    scanner_name, scanner_name.lower()
                )
                flags.append(threat_type)
                max_risk = max(max_risk, risk_score)

        # Determine redacted payload
        redacted: str | None = None
        if sanitized and sanitized != original_payload:
            redacted = sanitized

        return SecurityAnalysis(
            is_safe=is_valid and len(flags) == 0,
            confidence_score=round(max_risk, 4) if flags else 0.0,
            flags=flags,
            redacted_payload=redacted,
        )

    async def close(self) -> None:
        """Close the HTTP client gracefully."""
        await self._client.aclose()
