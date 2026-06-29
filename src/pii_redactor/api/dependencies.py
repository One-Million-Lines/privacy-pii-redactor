"""
FastAPI dependency injection providers.

All shared objects (detector, redactor, restorer, store, etc.) are created
here as FastAPI dependency functions. This centralises construction logic and
makes them easy to override in tests.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from fastapi import Request

from pii_redactor.config import Settings, load_yaml_config
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer
from pii_redactor.storage.base import MappingStore
from pii_redactor.storage.memory import InMemoryStore

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the application settings singleton.

    Cached after the first call so environment variables are only read once.
    Override in tests by calling ``app.dependency_overrides[get_settings]``.

    Returns:
        Loaded :class:`~pii_redactor.config.Settings` instance.
    """
    return Settings()


# ─────────────────────────────────────────────────────────────────────────────
# PIIDetector
# ─────────────────────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def _build_detector(config_file: str | None) -> PIIDetector:
    """
    Internal factory: build (and cache) the PIIDetector.

    Loads custom patterns from the YAML config file if configured.

    Args:
        config_file: Path to optional YAML config file.

    Returns:
        Configured :class:`~pii_redactor.detection.detector.PIIDetector`.
    """
    settings = get_settings()
    custom_patterns: list[dict] = []

    if config_file:
        try:
            yaml_cfg = load_yaml_config(config_file)
            custom_patterns = yaml_cfg.get("custom_recognizers", [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load YAML config from %s: %s", config_file, exc)

    return PIIDetector(config=settings, custom_patterns=custom_patterns)


def get_detector() -> PIIDetector:
    """
    FastAPI dependency: return the cached PIIDetector instance.

    Returns:
        Shared :class:`~pii_redactor.detection.detector.PIIDetector`.
    """
    settings = get_settings()
    return _build_detector(settings.config_file)


# ─────────────────────────────────────────────────────────────────────────────
# PIIRedactor / PIIRestorer (stateless — no cache needed)
# ─────────────────────────────────────────────────────────────────────────────


def get_redactor() -> PIIRedactor:
    """
    FastAPI dependency: return a :class:`~pii_redactor.redaction.redactor.PIIRedactor`.

    PIIRedactor is stateless, so a shared singleton is fine.

    Returns:
        :class:`~pii_redactor.redaction.redactor.PIIRedactor` instance.
    """
    return _REDACTOR_SINGLETON


def get_restorer() -> PIIRestorer:
    """
    FastAPI dependency: return a :class:`~pii_redactor.redaction.restorer.PIIRestorer`.

    Returns:
        :class:`~pii_redactor.redaction.restorer.PIIRestorer` instance.
    """
    return _RESTORER_SINGLETON


# Module-level singletons for the stateless services
_REDACTOR_SINGLETON = PIIRedactor()
_RESTORER_SINGLETON = PIIRestorer()


# ─────────────────────────────────────────────────────────────────────────────
# MappingStore
# ─────────────────────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def _build_store() -> MappingStore:
    """
    Internal factory: build and cache the MappingStore.

    Attempts to create a RedisStore if redis_url is set.  Falls back to
    InMemoryStore if Redis is unavailable.

    Returns:
        Active :class:`~pii_redactor.storage.base.MappingStore` implementation.
    """
    settings = get_settings()

    # Try Redis first
    try:
        from pii_redactor.storage.redis import RedisStore  # noqa: PLC0415

        store = RedisStore(redis_url=settings.redis_url)
        logger.info("Using RedisStore for PII mappings (url=%s)", settings.redis_url)
        return store
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Redis unavailable (%s). Falling back to InMemoryStore.", exc
        )

    store = InMemoryStore()
    logger.info("Using InMemoryStore for PII mappings")
    return store


def get_store() -> MappingStore:
    """
    FastAPI dependency: return the active MappingStore.

    Returns:
        Active :class:`~pii_redactor.storage.base.MappingStore`.
    """
    return _build_store()


# ─────────────────────────────────────────────────────────────────────────────
# Request helpers
# ─────────────────────────────────────────────────────────────────────────────


async def get_request_body(request: Request) -> bytes:
    """
    Read and cache the raw request body bytes.

    FastAPI normally streams the body once; this helper reads it and caches
    it on the request state so it can be accessed multiple times.

    Args:
        request: The current HTTP request.

    Returns:
        Raw request body as bytes.
    """
    if not hasattr(request.state, "_body"):
        request.state._body = await request.body()
    return request.state._body
