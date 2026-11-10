"""
Custom domain exceptions for AgentOps.

All gateway-specific errors inherit from AgentOpsError to allow
consumers to catch them at the top-level in a single except clause.
"""


class AgentOpsError(Exception):
    """Base exception for all AgentOps domain errors."""


class SecurityViolationError(AgentOpsError):
    """Raised when the verifier detects a critical security threat."""

    def __init__(self, flags: list[str], confidence: float) -> None:
        self.flags = flags
        self.confidence = confidence
        super().__init__(
            f"Security violation detected (confidence={confidence:.2f}): {', '.join(flags)}"
        )


class ValidationRejectedError(AgentOpsError):
    """Raised when the validation council rejects a request."""

    def __init__(self, reasoning: str) -> None:
        self.reasoning = reasoning
        super().__init__(f"Validation council rejected request: {reasoning}")


class RoutingError(AgentOpsError):
    """Raised when routing fails due to an unreachable or disallowed destination."""

    def __init__(self, destination: str, reason: str) -> None:
        self.destination = destination
        self.reason = reason
        super().__init__(f"Routing to '{destination}' failed: {reason}")


class ConfigurationError(AgentOpsError):
    """Raised when the gateway configuration (agentops.yaml) is invalid."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Configuration error: {detail}")
