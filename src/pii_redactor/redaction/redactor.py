"""
PIIRedactor: replace detected entities with placeholders.

Implements right-to-left replacement to preserve character indices across
multiple replacements, and uses :class:`PlaceholderManager` to ensure
consistent placeholder assignment within a single redaction call.
"""

from __future__ import annotations

import logging

from pii_redactor.models import DetectedEntity, RedactionResult
from pii_redactor.redaction.placeholders import PlaceholderManager

logger = logging.getLogger(__name__)


class PIIRedactor:
    """
    Replaces detected PII entities in text with format-stable placeholders.

    The redactor is *stateless* — it creates a fresh
    :class:`~pii_redactor.redaction.placeholders.PlaceholderManager` for each
    :meth:`redact` call. This means placeholder counters reset between calls;
    cross-request consistency must be handled at the storage layer.

    Replacement strategy:
        * Entities are processed from *right to left* (highest ``start`` index
          first) so that replacing an earlier entity never shifts the indices
          of later ones.
        * The same original value always gets the same placeholder within a
          single call (handled by :class:`PlaceholderManager`).

    Example::

        redactor = PIIRedactor()
        result = redactor.redact(
            text="Contact john@example.com",
            entities=[DetectedEntity("EMAIL", 8, 24, 0.95, "regex")],
        )
        # result.redacted_text == "Contact <EMAIL_1>"
        # result.mapping == {"<EMAIL_1>": "john@example.com"}
    """

    def redact(
        self,
        text: str,
        entities: list[DetectedEntity],
    ) -> RedactionResult:
        """
        Replace all detected entity spans in *text* with placeholders.

        Args:
            text: Original text that may contain PII.
            entities: Non-overlapping list of detected entities (typically the
                output of :meth:`PIIDetector.detect` after conflict resolution).
                The list does not need to be sorted — it is sorted internally.

        Returns:
            :class:`~pii_redactor.models.RedactionResult` containing:
            - ``redacted_text``: Text with PII replaced by placeholders.
            - ``entities``: The input entities sorted by start position.
            - ``mapping``: Dict mapping each placeholder to its original value.
            - ``mapping_id``: ``None`` — callers should persist the mapping
              separately if required.

        Raises:
            ValueError: If any entity references a span outside *text*.
        """
        if not text:
            return RedactionResult(
                redacted_text=text,
                entities=[],
                mapping={},
            )

        if not entities:
            return RedactionResult(
                redacted_text=text,
                entities=[],
                mapping={},
            )

        manager = PlaceholderManager()

        # Sort descending by start position for right-to-left replacement
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        result_text = text
        for entity in sorted_entities:
            if entity.start > len(result_text) or entity.end > len(result_text):
                logger.warning(
                    "Entity %s [%d:%d] is out of bounds for text of length %d — skipping",
                    entity.entity_type,
                    entity.start,
                    entity.end,
                    len(result_text),
                )
                continue

            original_value = result_text[entity.start:entity.end]
            placeholder = manager.get_placeholder(entity.entity_type, original_value)

            # Replace the span with the placeholder (right-to-left, so indices remain valid)
            result_text = result_text[:entity.start] + placeholder + result_text[entity.end:]

            logger.debug(
                "Replaced %s at [%d:%d] with placeholder %s",
                entity.entity_type,
                entity.start,
                entity.end,
                placeholder,
            )

        # Return entities in document order (ascending start)
        sorted_asc = sorted(entities, key=lambda e: e.start)

        return RedactionResult(
            redacted_text=result_text,
            entities=sorted_asc,
            mapping=manager.mapping,
            mapping_id=None,
        )
