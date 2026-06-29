"""
LLM proxy example: send a chat request through the PII redactor proxy.

This example shows how to use the PrivacyRedactor as a middleware layer
before calling an OpenAI-compatible LLM endpoint.

Requires:
    - LLM_PROVIDER_URL set to an OpenAI-compatible base URL
    - LLM_PROVIDER_API_KEY set to your API key

Run:
    LLM_PROVIDER_URL=https://api.openai.com/v1 \\
    LLM_PROVIDER_API_KEY=sk-... \\
    python examples/llm_proxy.py
"""

from __future__ import annotations

import asyncio
import os

from pii_redactor import PrivacyRedactor
from pii_redactor.config import Settings
from pii_redactor.proxy.base import LLMRequest
from pii_redactor.proxy.openai_compatible import OpenAICompatibleProvider

LLM_PROVIDER_URL = os.environ.get("LLM_PROVIDER_URL", "")
LLM_PROVIDER_API_KEY = os.environ.get("LLM_PROVIDER_API_KEY", "")


async def main() -> None:
    if not LLM_PROVIDER_URL:
        print("LLM_PROVIDER_URL is not set. Set it to run this example.")
        print("Example: LLM_PROVIDER_URL=https://api.openai.com/v1 python examples/llm_proxy.py")
        return

    # ── 1. Redact the user prompt ──────────────────────────────────────────────
    settings = Settings(enable_presidio=False, enable_spacy=False)
    redactor = PrivacyRedactor(config=settings)

    user_message = (
        "Please summarize the account of John Smith, email john@example.com, "
        "who has credit card 4111 1111 1111 1111 on file."
    )

    result = redactor.redact(user_message, store_mapping=True)
    print("Original prompt :", user_message)
    print("Redacted prompt :", result.redacted_text)
    print("Mapping ID      :", result.mapping_id)
    print()

    # ── 2. Forward redacted prompt to LLM ────────────────────────────────────
    provider = OpenAICompatibleProvider(
        base_url=LLM_PROVIDER_URL,
        api_key=LLM_PROVIDER_API_KEY,
    )

    llm_request = LLMRequest(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": result.redacted_text}],
    )

    try:
        llm_response = await provider.complete(llm_request)
        print("LLM response (redacted) :", llm_response.content)

        # ── 3. Restore original values in the LLM response ────────────────────
        if result.mapping_id:
            restored = redactor.restore_by_id(
                llm_response.content,
                result.mapping_id,
                delete_after=True,
            )
            if restored:
                print("Restored response      :", restored.restored_text)
    finally:
        await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
