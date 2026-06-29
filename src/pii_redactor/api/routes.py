"""
API route handlers.

Defines all HTTP endpoints for the PII Redactor service:

    GET  /health                   — liveness probe
    POST /v1/detect                — detect PII entities (no redaction)
    POST /v1/redact                — redact PII and optionally store mapping
    POST /v1/restore               — restore original values from mapping
    POST /v1/chat/completions      — LLM proxy with transparent PII redaction

Security:
    - API key is compared with ``hmac.compare_digest`` to prevent timing attacks.
    - Error responses never include raw PII values from the request.
    - Request body is never logged at INFO level.
"""

from __future__ import annotations

import hmac
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from pii_redactor.api.dependencies import get_detector, get_redactor, get_restorer, get_settings, get_store
from pii_redactor.api.schemas import (
    ChatCompletionRequest,
    DetectRequest,
    DetectResponse,
    EntityInfo,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    RedactRequest,
    RedactResponse,
    RedactedEntityInfo,
    RestoreRequest,
    RestoreResponse,
)
from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.models import DetectedEntity
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer
from pii_redactor.storage.base import MappingStore

logger = logging.getLogger(__name__)

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Auth helper
# ─────────────────────────────────────────────────────────────────────────────


def _verify_api_key(request: Request, settings: Settings) -> None:
    """
    Verify the ``Authorization: Bearer <key>`` header using constant-time compare.

    No-op when ``settings.api_key`` is empty / None (auth disabled).

    Args:
        request: Current HTTP request.
        settings: Application settings (contains expected key).

    Raises:
        HTTPException(401): If the key is missing or incorrect.
    """
    if not settings.api_key:
        return  # Auth not configured

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "UNAUTHORIZED", "message": "Missing or invalid Authorization header"}},
        )

    provided_key = auth_header[len("Bearer "):]
    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(provided_key.encode(), settings.api_key.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "UNAUTHORIZED", "message": "Invalid API key"}},
        )


def _entity_to_info(entity: DetectedEntity) -> EntityInfo:
    """Convert a :class:`DetectedEntity` to an :class:`EntityInfo` schema."""
    return EntityInfo(
        type=entity.entity_type,
        start=entity.start,
        end=entity.end,
        confidence=entity.confidence,
        source=entity.source,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns 200 OK when the service is running.",
    tags=["Utility"],
)
async def health_check() -> HealthResponse:
    """Liveness probe endpoint."""
    return HealthResponse(status="ok")


@router.post(
    "/v1/detect",
    response_model=DetectResponse,
    summary="Detect PII entities",
    description="Analyse text and return detected PII entities without modifying the text.",
    tags=["Detection"],
)
async def detect(
    body: DetectRequest,
    detector: Annotated[PIIDetector, Depends(get_detector)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DetectResponse:
    """
    Detect PII entities in the provided text.

    Returns a list of entity spans with type, position, confidence, and source.
    The original text is never echoed back in the response.
    """
    entities = detector.detect(body.text, language=body.language)
    return DetectResponse(
        entities=[_entity_to_info(e) for e in entities],
        total=len(entities),
    )


@router.post(
    "/v1/redact",
    response_model=RedactResponse,
    summary="Redact PII from text",
    description=(
        "Replace detected PII entities with placeholders and optionally persist "
        "the mapping for later restoration."
    ),
    tags=["Redaction"],
)
async def redact(
    body: RedactRequest,
    detector: Annotated[PIIDetector, Depends(get_detector)],
    redactor: Annotated[PIIRedactor, Depends(get_redactor)],
    store: Annotated[MappingStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RedactResponse:
    """
    Detect and redact PII from text.

    If ``store_mapping=true`` (default), the placeholder→value mapping is
    persisted and a ``mapping_id`` is returned for use with ``/v1/restore``.
    """
    entities = detector.detect(body.text, language=body.language)
    result = redactor.redact(text=body.text, entities=entities)

    mapping_id = None
    expires_in = None

    if body.store_mapping and result.mapping:
        try:
            mapping_id = store.save(result.mapping, ttl=settings.mapping_ttl_seconds)
            expires_in = settings.mapping_ttl_seconds
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist mapping: %s", exc)

    # Build redacted entity list with placeholder assignments
    redacted_entities: list[RedactedEntityInfo] = []
    for entity in result.entities:
        original_value = body.text[entity.start:entity.end]
        # Find the placeholder assigned to this value
        placeholder = next(
            (ph for ph, val in result.mapping.items() if val == original_value),
            f"<{entity.entity_type}_?>",
        )
        redacted_entities.append(
            RedactedEntityInfo(
                type=entity.entity_type,
                placeholder=placeholder,
                confidence=entity.confidence,
            )
        )

    logger.info(
        "Redacted %d entity/entities from text of length %d (mapping_id=%s)",
        len(result.entities),
        len(body.text),
        mapping_id or "none",
    )

    return RedactResponse(
        redacted_text=result.redacted_text,
        entities=redacted_entities,
        mapping_id=mapping_id,
        expires_in=expires_in,
    )


@router.post(
    "/v1/restore",
    response_model=RestoreResponse,
    summary="Restore original PII values",
    description="Replace placeholder tokens in text with their original PII values.",
    tags=["Restoration"],
)
async def restore(
    body: RestoreRequest,
    request: Request,
    restorer: Annotated[PIIRestorer, Depends(get_restorer)],
    store: Annotated[MappingStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RestoreResponse:
    """
    Restore original PII values in redacted text using a stored mapping.

    Requires authentication when ``API_KEY`` is configured.
    After successful restoration, the mapping is deleted if
    ``delete_after_restore=true`` (default).
    """
    _verify_api_key(request, settings)

    mapping = store.get(body.mapping_id)
    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "MAPPING_NOT_FOUND", "message": "Mapping ID not found or expired"}},
        )

    result = restorer.restore(text=body.text, mapping=mapping)

    if body.delete_after_restore:
        try:
            store.delete(body.mapping_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to delete mapping %s: %s", body.mapping_id, exc)

    logger.info(
        "Restored %d placeholder(s) (mapping_id=%s, deleted=%s)",
        result.placeholders_replaced,
        body.mapping_id,
        body.delete_after_restore,
    )

    return RestoreResponse(
        restored_text=result.restored_text,
        placeholders_replaced=result.placeholders_replaced,
    )


@router.post(
    "/v1/chat/completions",
    summary="LLM proxy with PII redaction",
    description=(
        "Transparent proxy to an upstream LLM provider. PII is redacted from "
        "user messages before forwarding, and optionally restored in the response."
    ),
    tags=["Proxy"],
)
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    detector: Annotated[PIIDetector, Depends(get_detector)],
    redactor: Annotated[PIIRedactor, Depends(get_redactor)],
    restorer: Annotated[PIIRestorer, Depends(get_restorer)],
    store: Annotated[MappingStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    """
    PII-redacting proxy to an upstream LLM.

    Flow:
        1. Redact PII from all ``user`` message contents.
        2. Forward the modified request to the upstream LLM provider.
        3. If ``restore_response=true``, restore placeholders in the LLM reply.
        4. Return the (optionally restored) LLM response.
    """
    if not settings.llm_provider_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": {
                    "code": "LLM_PROVIDER_NOT_CONFIGURED",
                    "message": "LLM_PROVIDER_URL is not configured",
                }
            },
        )

    from pii_redactor.proxy.openai_compatible import OpenAICompatibleProvider  # noqa: PLC0415
    from pii_redactor.proxy.base import LLMRequest  # noqa: PLC0415

    provider = OpenAICompatibleProvider(
        base_url=settings.llm_provider_url,
        api_key=settings.llm_provider_api_key,
        timeout=settings.llm_timeout_seconds,
    )

    # Redact PII from user messages
    combined_mapping: dict[str, str] = {}
    redacted_messages: list[dict[str, Any]] = []

    for msg in body.messages:
        if msg.role == "user":
            entities = detector.detect(msg.content)
            red_result = redactor.redact(msg.content, entities)
            combined_mapping.update(red_result.mapping)
            redacted_messages.append({"role": msg.role, "content": red_result.redacted_text})
        else:
            redacted_messages.append({"role": msg.role, "content": msg.content})

    # Build extra params from the request (exclude known fields)
    extra = {
        k: v for k, v in body.model_dump(exclude={"model", "messages", "restore_response"}).items()
        if v is not None
    }

    llm_request = LLMRequest(
        model=body.model,
        messages=redacted_messages,
        extra=extra,
    )

    try:
        llm_response = await provider.complete(llm_request)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM provider request failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": {"code": "LLM_PROVIDER_ERROR", "message": "Upstream LLM request failed"}},
        ) from exc
    finally:
        await provider.close()

    # Optionally restore placeholders in the LLM response
    response_content = llm_response.content
    if body.restore_response and combined_mapping:
        restore_result = restorer.restore(response_content, combined_mapping)
        response_content = restore_result.restored_text

    # Build pass-through response, injecting restored content
    raw_response = dict(llm_response.raw)
    try:
        if raw_response.get("choices"):
            raw_response["choices"][0]["message"]["content"] = response_content
    except (KeyError, IndexError, TypeError):
        pass

    return JSONResponse(content=raw_response)
