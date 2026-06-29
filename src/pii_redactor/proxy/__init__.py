"""
Proxy sub-package.

Provides the LLM provider abstraction layer used by the ``/v1/chat/completions``
proxy endpoint.
"""

from pii_redactor.proxy.base import LLMProvider, LLMRequest, LLMResponse
from pii_redactor.proxy.openai_compatible import OpenAICompatibleProvider

__all__ = ["LLMProvider", "LLMRequest", "LLMResponse", "OpenAICompatibleProvider"]
