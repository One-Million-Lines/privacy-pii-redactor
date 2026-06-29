"""
Presidio-based PII detector.

Wraps Microsoft Presidio's ``AnalyzerEngine`` to provide ML-backed PII
detection. Presidio is an optional dependency — if not installed this module
logs a single warning and the detector returns an empty list for every call,
allowing the rest of the pipeline to operate with regex-only detection.

Entity type mapping from Presidio's native labels to our normalized labels
is defined in ``_PRESIDIO_TO_NORMALIZED``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pii_redactor.models import DetectedEntity

if TYPE_CHECKING:
    pass  # avoid importing presidio at module level

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Presidio → normalized entity type mapping
# ──────────────────────────────────────────────────────────────────────────────

_PRESIDIO_TO_NORMALIZED: dict[str, str] = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "CREDIT_CARD": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP_ADDRESS",
    "URL": "URL",
    "US_SSN": "SSN",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "US_BANK_NUMBER": "BANK_ACCOUNT",
    "DATE_TIME": "DATE_OF_BIRTH",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "ORGANIZATION",
    "NRP": "NRP",  # Nationality, religion, political group
    "MEDICAL_LICENSE": "MEDICAL_LICENSE",
    "CRYPTO": "CRYPTO_ADDRESS",
}


class PresidioDetector:
    """
    PII detector backed by Microsoft Presidio's ``AnalyzerEngine``.

    Presidio provides high-quality NLP-based entity recognition by combining
    regex recognizers, rule-based recognizers, and an NLP model (spaCy).
    Results are mapped from Presidio's entity labels to our normalized schema.

    This detector is an *optional* enrichment layer. When ``presidio-analyzer``
    is not installed, all calls to :meth:`detect` return ``[]`` without raising
    exceptions — the pipeline continues with other active detectors.

    Args:
        language: Default ISO 639-1 language code (default ``"en"``).
        score_threshold: Minimum Presidio confidence score to retain a result.

    Example::

        detector = PresidioDetector()
        entities = detector.detect("Call John at john@example.com")
    """

    def __init__(
        self,
        language: str = "en",
        score_threshold: float = 0.5,
    ) -> None:
        self._language = language
        self._score_threshold = score_threshold
        self._engine = self._init_engine()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _init_engine(self):
        """
        Attempt to instantiate the Presidio ``AnalyzerEngine``.

        Returns:
            A configured ``AnalyzerEngine`` instance, or ``None`` if Presidio
            is not installed (dependency not available).
        """
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore[import]

            engine = AnalyzerEngine()
            logger.debug("Presidio AnalyzerEngine initialised successfully")
            return engine
        except ImportError:
            logger.warning(
                "presidio-analyzer is not installed. "
                "Presidio-based detection is disabled. "
                "Install it with: pip install presidio-analyzer"
            )
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to initialise Presidio AnalyzerEngine: %s", exc)
            return None

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """True if the Presidio engine was loaded successfully."""
        return self._engine is not None

    def detect(self, text: str, language: str | None = None) -> list[DetectedEntity]:
        """
        Analyse *text* with Presidio and return normalised detected entities.

        If Presidio is unavailable, returns an empty list immediately.

        Args:
            text: Input text to analyse.
            language: ISO 639-1 language override. Falls back to the instance
                default if not provided.

        Returns:
            List of :class:`~pii_redactor.models.DetectedEntity` with
            ``source="presidio"``.
        """
        if self._engine is None or not text or not text.strip():
            return []

        lang = language or self._language
        try:
            results = self._engine.analyze(
                text=text,
                language=lang,
                score_threshold=self._score_threshold,
                return_decision_process=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Presidio analysis failed: %s", exc)
            return []

        entities: list[DetectedEntity] = []
        for result in results:
            normalized_type = _PRESIDIO_TO_NORMALIZED.get(result.entity_type, result.entity_type)
            entities.append(
                DetectedEntity(
                    entity_type=normalized_type,
                    start=result.start,
                    end=result.end,
                    confidence=float(result.score),
                    source="presidio",
                )
            )

        return entities
