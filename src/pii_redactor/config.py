"""
Application configuration for privacy-pii-redactor.

Configuration is loaded from environment variables using pydantic-settings.
An optional YAML config file can extend the base settings with entity-level
overrides and custom recognizer definitions.

Priority order (highest to lowest):
    1. Environment variables
    2. YAML config file (if CONFIG_FILE is set)
    3. Default values declared in Settings
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All fields map to uppercase environment variable names by default
    (pydantic-settings convention). E.g., ``port`` ↔ ``PORT``.

    Example usage::

        from pii_redactor.config import Settings
        settings = Settings()  # loads from environment
        settings = Settings(port=9000)  # override specific fields
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_env: str = Field(default="development", description="Runtime environment name")
    host: str = Field(default="0.0.0.0", description="Bind host for the HTTP server")
    port: int = Field(default=8000, description="Bind port for the HTTP server")

    # ── Storage ───────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL used by RedisStore",
    )
    mapping_ttl_seconds: int = Field(
        default=900,
        description="How long (seconds) a PII mapping persists before expiry",
    )

    # ── Detection ─────────────────────────────────────────────────────────────
    default_language: str = Field(
        default="en",
        description="Default ISO 639-1 language code for NLP detectors",
    )
    min_confidence_score: float = Field(
        default=0.65,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold; detections below this are discarded",
    )
    enable_spacy: bool = Field(default=True, description="Enable spaCy NER detector")
    enable_presidio: bool = Field(
        default=True, description="Enable Microsoft Presidio analyzer"
    )
    enable_regex: bool = Field(
        default=True, description="Enable built-in regex detector"
    )

    # ── Security / Auth ───────────────────────────────────────────────────────
    api_key: str | None = Field(
        default=None,
        description=(
            "Bearer token required for sensitive endpoints. "
            "Leave empty / None to disable authentication."
        ),
    )

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", description="Python logging level name")

    # ── LLM proxy ─────────────────────────────────────────────────────────────
    llm_provider_url: str | None = Field(
        default=None,
        description="Base URL of the upstream LLM provider (e.g. https://api.openai.com)",
    )
    llm_provider_api_key: str | None = Field(
        default=None,
        description="API key forwarded to the upstream LLM provider",
    )
    llm_timeout_seconds: int = Field(
        default=60, description="HTTP timeout for upstream LLM requests (seconds)"
    )

    # ── Request limits ────────────────────────────────────────────────────────
    max_request_size_bytes: int = Field(
        default=102_400,  # 100 KB
        description="Maximum allowed request body size in bytes",
    )

    # ── API / Docs ────────────────────────────────────────────────────────────
    docs_enabled: bool = Field(
        default=True, description="Expose /docs and /redoc Swagger UI endpoints"
    )

    # ── YAML config ───────────────────────────────────────────────────────────
    config_file: str | None = Field(
        default=None,
        description="Path to an optional YAML config file with entity overrides and custom recognizers",
    )


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """
    Load and parse a YAML configuration file.

    The YAML file may contain two top-level keys:

    * ``entity_overrides`` — dict mapping entity type names to per-type settings
      (e.g., ``min_confidence``).
    * ``custom_recognizers`` — list of dicts, each defining a custom regex
      recognizer with at minimum ``name`` and ``pattern`` fields.

    Args:
        path: Filesystem path to the YAML file.

    Returns:
        Dict with keys ``"entity_overrides"`` (dict, possibly empty) and
        ``"custom_recognizers"`` (list, possibly empty).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML cannot be parsed.

    Example YAML structure::

        entity_overrides:
          PERSON:
            min_confidence: 0.80
        custom_recognizers:
          - name: CUSTOMER_ID
            pattern: "CUS-[0-9]{6}"
            confidence: 0.95
    """
    import yaml  # local import — PyYAML is an optional dep in tests

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML config at {path}: {exc}") from exc

    result: dict[str, Any] = {
        "entity_overrides": raw.get("entity_overrides") or {},
        "custom_recognizers": raw.get("custom_recognizers") or [],
    }
    logger.debug(
        "Loaded YAML config from %s: %d entity overrides, %d custom recognizers",
        path,
        len(result["entity_overrides"]),
        len(result["custom_recognizers"]),
    )
    return result


def configure_logging(settings: Settings) -> None:
    """
    Apply the log level from *settings* to the root logger.

    Called once at application startup. Subsequent calls are idempotent.

    Args:
        settings: Loaded application settings.
    """
    numeric_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("pii_redactor").setLevel(numeric_level)
