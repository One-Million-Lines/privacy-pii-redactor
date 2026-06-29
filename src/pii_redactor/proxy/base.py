"""
Abstract base class and data models for LLM providers.

All concrete LLM provider implementations must subclass :class:`LLMProvider`
and implement the :meth:`complete` coroutine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LLMRequest:
    """
    Normalised LLM chat completion request.

    Attributes:
        model: Model identifier string (e.g. ``"gpt-4o-mini"``).
        messages: List of message dicts with ``"role"`` and ``"content"`` keys.
        extra: Additional provider-specific parameters forwarded as-is.
    """

    model: str
    messages: list[dict[str, Any]]
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """
    Normalised LLM chat completion response.

    Attributes:
        content: The assistant's reply text.
        model: Model identifier echoed from the provider response.
        raw: Complete raw response dict from the provider (pass-through).
        usage: Optional token usage information.
    """

    content: str
    model: str
    raw: dict[str, Any]
    usage: Optional[dict[str, int]] = None


class LLMProvider(ABC):
    """
    Abstract interface for upstream LLM providers.

    Concrete implementations wrap a specific LLM API (OpenAI, Anthropic,
    Gemini, etc.) and normalise their responses into :class:`LLMResponse`.

    Example implementation::

        class MyProvider(LLMProvider):
            async def complete(self, request: LLMRequest) -> LLMResponse:
                # call API, parse response
                ...
    """

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """
        Send a chat completion request to the upstream LLM provider.

        Args:
            request: Normalised chat completion request.

        Returns:
            Normalised :class:`LLMResponse` containing the assistant's reply.

        Raises:
            httpx.HTTPError: On HTTP-level failures.
            httpx.TimeoutException: When the request exceeds the configured timeout.
        """

    async def close(self) -> None:
        """
        Release any held resources (e.g., HTTP connection pool).

        Override in subclasses that hold persistent connections.
        Default implementation is a no-op.
        """
