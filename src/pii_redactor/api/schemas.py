"""
Pydantic v2 request and response schemas for the PII Redactor API.

All request/response bodies are defined here. Pydantic v2's model validation
provides automatic type coercion, clear error messages, and OpenAPI schema
generation.

Security note:
    No schema should echo raw PII values back in error responses.
    Error messages use codes and generic descriptions only.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Shared entity info schemas
# ─────────────────────────────────────────────────────────────────────────────


class EntityInfo(BaseModel):
    """Describes a single detected PII entity in a detection response."""

    type: str = Field(description="Normalized entity type, e.g. 'EMAIL', 'PERSON'")
    start: int = Field(ge=0, description="Start character offset (inclusive)")
    end: int = Field(ge=0, description="End character offset (exclusive)")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")
    source: str = Field(
        description="Which detector produced this entity: 'regex', 'presidio', 'spacy', or 'custom'"
    )


class RedactedEntityInfo(BaseModel):
    """Describes a redacted entity in a redaction response."""

    type: str = Field(description="Normalized entity type")
    placeholder: str = Field(description="Placeholder token that replaced the original value")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────


class DetectRequest(BaseModel):
    """Request body for ``POST /v1/detect``."""

    text: str = Field(description="Text to scan for PII entities")
    language: str = Field(default="en", description="ISO 639-1 language code")


class DetectResponse(BaseModel):
    """Response body for ``POST /v1/detect``."""

    entities: list[EntityInfo] = Field(description="List of detected PII entities")
    total: int = Field(description="Total number of detected entities")


# ─────────────────────────────────────────────────────────────────────────────
# Redaction
# ─────────────────────────────────────────────────────────────────────────────


class RedactRequest(BaseModel):
    """Request body for ``POST /v1/redact``."""

    text: str = Field(description="Text to redact PII from")
    language: str = Field(default="en", description="ISO 639-1 language code")
    store_mapping: bool = Field(
        default=True,
        description=(
            "Whether to persist the placeholder→value mapping for later restoration. "
            "Set to False if you do not need to restore the original values."
        ),
    )


class RedactResponse(BaseModel):
    """Response body for ``POST /v1/redact``."""

    redacted_text: str = Field(description="Text with PII replaced by placeholders")
    entities: list[RedactedEntityInfo] = Field(
        description="List of redacted entities with their placeholder assignments"
    )
    mapping_id: str | None = Field(
        default=None,
        description="Opaque ID for retrieving the mapping during restoration. Null if store_mapping=false.",
    )
    expires_in: int | None = Field(
        default=None,
        description="Seconds until the mapping expires. Null if store_mapping=false.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Restoration
# ─────────────────────────────────────────────────────────────────────────────


class RestoreRequest(BaseModel):
    """Request body for ``POST /v1/restore``."""

    text: str = Field(description="Redacted text containing placeholder tokens to restore")
    mapping_id: str = Field(description="Mapping ID returned by a previous /v1/redact call")
    delete_after_restore: bool = Field(
        default=True,
        description="Delete the mapping after successful restoration (recommended for security)",
    )


class RestoreResponse(BaseModel):
    """Response body for ``POST /v1/restore``."""

    restored_text: str = Field(description="Text with placeholders replaced by original values")
    placeholders_replaced: int = Field(
        description="Number of placeholder tokens successfully replaced"
    )


# ─────────────────────────────────────────────────────────────────────────────
# LLM Proxy
# ─────────────────────────────────────────────────────────────────────────────


class ChatMessage(BaseModel):
    """A single message in a chat completion request."""

    role: str = Field(description="Message role: 'system', 'user', or 'assistant'")
    content: str = Field(description="Message content text")


class ChatCompletionRequest(BaseModel):
    """Request body for ``POST /v1/chat/completions`` (proxy endpoint)."""

    model: str = Field(description="Model identifier to pass to the upstream LLM provider")
    messages: list[ChatMessage] = Field(description="Conversation history")
    restore_response: bool = Field(
        default=True,
        description="Restore placeholder values in the LLM response if a mapping exists",
    )
    # Forward any extra OpenAI-compatible parameters (temperature, max_tokens, etc.)
    model_config = {"extra": "allow"}


class ChatCompletionResponse(BaseModel):
    """Response body for the proxy endpoint — passes through the LLM response."""

    model_config = {"extra": "allow"}

    # Pass-through fields from the upstream LLM provider
    id: str | None = None
    object: str | None = None
    created: int | None = None
    model: str | None = None
    choices: list[dict[str, Any]] | None = None
    usage: dict[str, int] | None = None
    # Metadata added by the proxy
    _pii_metadata: dict[str, Any] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Common
# ─────────────────────────────────────────────────────────────────────────────


class ErrorDetail(BaseModel):
    """Error detail object nested inside :class:`ErrorResponse`."""

    code: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable error description (no PII)")


class ErrorResponse(BaseModel):
    """Standard error response body."""

    error: ErrorDetail


class HealthResponse(BaseModel):
    """Response body for ``GET /health``."""

    status: str = Field(default="ok", description="Service status string")
