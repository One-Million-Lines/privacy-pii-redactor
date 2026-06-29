"""
PIIDetector orchestrator.

Coordinates all active sub-detectors (Presidio, spaCy, regex), merges their
outputs, resolves overlapping detections using
:class:`~pii_redactor.detection.conflict_resolver.ConflictResolver`, and
filters results by the configured minimum confidence threshold.

The detector is the single entry point for all PII detection within the
library and proxy server.
"""

from __future__ import annotations

import logging
from typing import Any

from pii_redactor.config import Settings
from pii_redactor.detection.conflict_resolver import ConflictResolver
from pii_redactor.detection.presidio_detector import PresidioDetector
from pii_redactor.detection.regex_detector import RegexDetector
from pii_redactor.detection.spacy_detector import SpacyDetector
from pii_redactor.models import DetectedEntity

logger = logging.getLogger(__name__)


class PIIDetector:
    """
    Orchestrates all active PII detectors into a single detection pipeline.

    Runs enabled sub-detectors in sequence, merges results, resolves
    conflicts, and applies the global confidence threshold filter.

    Detectors are enabled or disabled via the :class:`~pii_redactor.config.Settings`
    flags ``enable_regex``, ``enable_presidio``, and ``enable_spacy``.

    Args:
        config: Application settings controlling which detectors are active and
            what confidence threshold to enforce.
        custom_patterns: Optional list of custom pattern dicts forwarded to
            :class:`~pii_redactor.detection.regex_detector.RegexDetector`.
            Each dict must contain at least ``"name"`` and ``"pattern"`` keys.

    Example::

        config = Settings(enable_presidio=False, enable_spacy=False)
        detector = PIIDetector(config=config)
        entities = detector.detect("Contact me at user@example.com")
    """

    def __init__(
        self,
        config: Settings | None = None,
        custom_patterns: list[dict[str, Any]] | None = None,
    ) -> None:
        self._config = config or Settings()
        self._resolver = ConflictResolver()
        self._detectors: list[Any] = []

        # Initialise sub-detectors respecting config flags
        if self._config.enable_regex:
            self._detectors.append(
                RegexDetector(custom_patterns=custom_patterns or [])
            )
            logger.debug("RegexDetector enabled")
        else:
            logger.debug("RegexDetector disabled by config")

        if self._config.enable_presidio:
            self._detectors.append(
                PresidioDetector(
                    language=self._config.default_language,
                    score_threshold=max(0.0, self._config.min_confidence_score - 0.1),
                )
            )
            logger.debug("PresidioDetector enabled")
        else:
            logger.debug("PresidioDetector disabled by config")

        if self._config.enable_spacy:
            self._detectors.append(
                SpacyDetector(language=self._config.default_language)
            )
            logger.debug("SpacyDetector enabled")
        else:
            logger.debug("SpacyDetector disabled by config")

        active_count = len(self._detectors)
        logger.info(
            "PIIDetector initialised with %d active detector(s)", active_count
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self, text: str, language: str | None = None) -> list[DetectedEntity]:
        """
        Detect PII entities in *text* using all active sub-detectors.

        The pipeline is:
            1. Run each active sub-detector on *text*.
            2. Merge all results into a single candidate list.
            3. Resolve conflicts (select the best non-overlapping set).
            4. Filter by ``min_confidence_score``.
            5. Sort by start position.

        Args:
            text: Input text to scan for PII.
            language: ISO 639-1 language code. Overrides the default language
                from config for this call only.

        Returns:
            Sorted list of non-overlapping :class:`~pii_redactor.models.DetectedEntity`
            objects whose confidence meets the configured threshold.
        """
        if not text or not text.strip():
            return []

        lang = language or self._config.default_language
        all_candidates: list[DetectedEntity] = []

        # Collect from all active sub-detectors
        for detector in self._detectors:
            try:
                results = detector.detect(text, language=lang)
                all_candidates.extend(results)
                logger.debug(
                    "%s found %d candidate(s)",
                    type(detector).__name__,
                    len(results),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s raised an unexpected error: %s — skipping",
                    type(detector).__name__,
                    exc,
                )

        # Resolve conflicts → non-overlapping set
        resolved = self._resolver.resolve(all_candidates)

        # Apply confidence threshold
        threshold = self._config.min_confidence_score
        filtered = [e for e in resolved if e.confidence >= threshold]

        if len(filtered) < len(resolved):
            logger.debug(
                "Dropped %d entity/entities below confidence threshold %.2f",
                len(resolved) - len(filtered),
                threshold,
            )

        logger.debug(
            "Detection complete: %d entity/entities in final result",
            len(filtered),
        )
        return filtered

    # ── Convenience helpers ───────────────────────────────────────────────────

    @property
    def active_detector_names(self) -> list[str]:
        """Names of currently active sub-detectors (for diagnostics)."""
        return [type(d).__name__ for d in self._detectors]
