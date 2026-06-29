"""
OpenAI-compatible LLM provider.

Implements :class:`LLMProvider` for any API that follows the OpenAI chat
completions format.  This includes OpenAI itself, Azure OpenAI, Anthropic's
OpenAI-compatible endpoint, local models (Ollama, LM Studio, vLLM), and many
others.

The provider uses ``httpx.AsyncClient`` with a configurable timeout and
propagates the ``Authorization: Bearer <api_key>`` header.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from pii_redactor.proxy.base import LLMProvider, LLMRequest, LLMResponse

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(LLMProvider):
    """
    Async LLM provider for any OpenAI-compatible chat completions API.

    Uses ``httpx.AsyncClient`` to send requests to ``{base_url}/chat/completions``
    and returns a normalised :class:`LLMResponse`.

    Args:
        base_url: Base URL of the upstream LLM API
            (e.g. ``"https://api.openai.com/v1"``). Trailing slashes are stripped.
        api_key: API key forwarded in the ``Authorization: Bearer`` header.
        timeout: Request timeout in seconds (default: 60).

    Example::

        provider = OpenAICompatibleProvider(
            base_url="https://api.openai.com/v1",
            api_key="sk-...",
        )
        response = await provider.complete(
            LLMRequest(model="gpt-4o-mini", messages=[{"role": "user", "content": "Hello"}])
        )
        print(response.content)
    """

    _COMPLETIONS_PATH = "/chat/completions"

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 60,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ── HTTP client lifecycle ─────────────────────────────────────────────────

    def _get_client(self) -> httpx.AsyncClient:
        """
        Return (creating if necessary) the shared ``AsyncClient``.

        The client is created lazily and reused across requests for connection
        pooling efficiency.

        Returns:
            Configured ``httpx.AsyncClient`` instance.
        """
        if self._client is None or self._client.is_closed:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._client

    async def close(self) -> None:
        """
        Close the underlying HTTP client and release connection pool resources.

        Should be called when the provider is no longer needed (e.g., during
        application shutdown).
        """
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.debug("OpenAICompatibleProvider HTTP client closed")

    # ── LLMProvider implementation ────────────────────────────────────────────

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """
        Send a chat completion request to the upstream API.

        Constructs an OpenAI-format ``/chat/completions`` request body from
        *request*, posts it to the configured base URL, and parses the response
        into a normalised :class:`LLMResponse`.

        Args:
            request: Normalised chat completion request.

        Returns:
            Normalised :class:`LLMResponse` with the assistant's content.

        Raises:
            httpx.HTTPStatusError: If the upstream API returns a 4xx/5xx status.
            httpx.TimeoutException: If the request exceeds the configured timeout.
        """
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": request.messages,
            **request.extra,
        }

        client = self._get_client()
        logger.debug(
            "Sending chat completion request to %s (model=%s, messages=%d)",
            self._base_url + self._COMPLETIONS_PATH,
            request.model,
            len(request.messages),
        )

        response = await client.post(self._COMPLETIONS_PATH, json=payload)
        response.raise_for_status()

        raw: dict[str, Any] = response.json()

        # Extract content from the first choice
        content = ""
        try:
            content = raw["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("Could not extract content from LLM response: %s", exc)

        model = raw.get("model", request.model)
        usage = raw.get("usage")

        return LLMResponse(
            content=content,
            model=model,
            raw=raw,
            usage=usage,
        )
