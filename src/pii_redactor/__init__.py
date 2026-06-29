"""
Privacy-First PII Redactor
==========================

A self-hosted Python library and proxy that detects and removes sensitive
data before prompts reach external AI providers.

Quick start::

    from pii_redactor import PrivacyRedactor

    redactor = PrivacyRedactor()
    result = redactor.redact("Contact John at john@example.com")
    print(result.redacted_text)
    # → "Contact <PERSON_1> at <EMAIL_1>"

    restored = redactor.restore(result.redacted_text, result.mapping)
    print(restored.restored_text)
    # → "Contact John at john@example.com"
"""

from __future__ import annotations

from typing import Optional

from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.models import DetectedEntity, RedactionResult, RestorationResult
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer
from pii_redactor.storage.base import MappingStore
from pii_redactor.storage.memory import InMemoryStore

__version__ = "0.1.0"
__author__ = "Privacy PII Redactor Contributors"
__license__ = "MIT"


class PrivacyRedactor:
    """
    High-level convenience wrapper for PII detection, redaction, and restoration.

    This class bundles the detector, redactor, restorer, and an in-memory
    mapping store behind a simple three-method API. For advanced usage
    (custom detectors, Redis store, async proxy) use the individual components
    directly.

    Args:
        config: Optional ``Settings`` instance. If not provided, settings are
            loaded from environment variables.
        store: Optional ``MappingStore`` implementation. Defaults to
            :class:`~pii_redactor.storage.memory.InMemoryStore`.
        custom_patterns: Optional list of custom recognizer dicts to pass to
            the regex detector.

    Example::

        from pii_redactor import PrivacyRedactor
        from pii_redactor.config import Settings

        # Regex-only (fast, no ML dependencies required)
        redactor = PrivacyRedactor(
            config=Settings(enable_presidio=False, enable_spacy=False)
        )
        result = redactor.redact("My card is 4111 1111 1111 1111")
        print(result.redacted_text)   # "My card is <CREDIT_CARD_1>"
    """

    def __init__(
        self,
        config: Optional[Settings] = None,
        store: Optional[MappingStore] = None,
        custom_patterns: Optional[list[dict]] = None,
    ) -> None:
        self._config = config or Settings()
        self._detector = PIIDetector(config=self._config, custom_patterns=custom_patterns)
        self._redactor = PIIRedactor()
        self._restorer = PIIRestorer()
        self._store: MappingStore = store or InMemoryStore()

    # ── Core API ──────────────────────────────────────────────────────────────

    def detect(self, text: str, language: str = "en") -> list[DetectedEntity]:
        """
        Detect PII entities in *text* without modifying it.

        Args:
            text: Input text to scan.
            language: ISO 639-1 language code (default: ``"en"``).

        Returns:
            Sorted list of non-overlapping :class:`DetectedEntity` objects.
        """
        return self._detector.detect(text, language=language)

    def redact(
        self,
        text: str,
        language: str = "en",
        store_mapping: bool = False,
    ) -> RedactionResult:
        """
        Detect and redact PII from *text*.

        Replaces each detected entity with a placeholder such as
        ``<EMAIL_1>``, ``<PERSON_2>``, etc.  The same original value always
        receives the same placeholder within a single call.

        Args:
            text: Input text that may contain PII.
            language: ISO 639-1 language code (default: ``"en"``).
            store_mapping: If ``True``, persist the mapping in the configured
                store and populate ``result.mapping_id``.

        Returns:
            :class:`RedactionResult` with ``redacted_text``, ``entities``,
            ``mapping``, and optionally ``mapping_id``.
        """
        entities = self._detector.detect(text, language=language)
        result = self._redactor.redact(text, entities)

        if store_mapping and result.mapping:
            mapping_id = self._store.save(
                result.mapping,
                ttl=self._config.mapping_ttl_seconds,
            )
            result.mapping_id = mapping_id

        return result

    def restore(
        self,
        text: str,
        mapping: dict[str, str],
    ) -> RestorationResult:
        """
        Replace placeholders in *text* with their original values.

        Args:
            text: Redacted text containing placeholder tokens.
            mapping: Dict mapping placeholder strings to original PII values.
                Typically ``result.mapping`` from a prior :meth:`redact` call.

        Returns:
            :class:`RestorationResult` with ``restored_text`` and
            ``placeholders_replaced``.
        """
        return self._restorer.restore(text, mapping)

    def restore_by_id(
        self,
        text: str,
        mapping_id: str,
        delete_after: bool = True,
    ) -> Optional[RestorationResult]:
        """
        Restore *text* using a mapping previously stored via :meth:`redact`.

        Args:
            text: Redacted text to restore.
            mapping_id: ID returned from a prior :meth:`redact` call with
                ``store_mapping=True``.
            delete_after: If ``True``, delete the mapping from the store after
                successful restoration (default: ``True`` for privacy).

        Returns:
            :class:`RestorationResult`, or ``None`` if the mapping has expired
            or was not found.
        """
        mapping = self._store.get(mapping_id)
        if mapping is None:
            return None

        result = self._restorer.restore(text, mapping)

        if delete_after:
            self._store.delete(mapping_id)

        return result


__all__ = [
    # High-level API
    "PrivacyRedactor",
    # Core components
    "PIIDetector",
    "PIIRedactor",
    "PIIRestorer",
    # Models
    "DetectedEntity",
    "RedactionResult",
    "RestorationResult",
    # Config
    "Settings",
    # Storage
    "MappingStore",
    "InMemoryStore",
    # Metadata
    "__version__",
    "__author__",
    "__license__",
]
