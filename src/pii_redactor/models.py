"""
Core data models for privacy-pii-redactor.

This module defines the primary dataclasses used throughout the library
for representing detected PII entities, redaction results, and restoration
results. These models are intentionally lightweight — using dataclasses
rather than Pydantic — so the core detection/redaction logic remains
dependency-free.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectedEntity:
    """
    Represents a single detected PII entity within a text.

    Attributes:
        entity_type: Normalized entity type label (e.g., "EMAIL", "PERSON",
            "CREDIT_CARD"). Always upper-case.
        start: Start character offset (inclusive) within the source text.
        end: End character offset (exclusive) within the source text, matching
            Python slice semantics: ``text[start:end]`` gives the raw value.
        confidence: Detection confidence score in range [0.0, 1.0].
            1.0 = fully deterministic (e.g., Luhn-validated credit card).
            Values closer to 0.0 indicate heuristic / low-confidence detections.
        source: Which detector produced this entity.
            One of ``"presidio"``, ``"spacy"``, ``"regex"``, ``"custom"``.
    """

    entity_type: str
    start: int
    end: int
    confidence: float
    source: str  # "presidio" | "spacy" | "regex" | "custom"

    def __post_init__(self) -> None:
        """Validate field values after construction."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0.0, 1.0], got {self.confidence}"
            )
        if self.start < 0:
            raise ValueError(f"start must be >= 0, got {self.start}")
        if self.end < self.start:
            raise ValueError(
                f"end must be >= start, got end={self.end}, start={self.start}"
            )
        if self.source not in {"presidio", "spacy", "regex", "custom"}:
            raise ValueError(
                f"source must be one of presidio/spacy/regex/custom, got '{self.source}'"
            )

    @property
    def span_length(self) -> int:
        """Number of characters covered by this entity."""
        return self.end - self.start

    def overlaps(self, other: "DetectedEntity") -> bool:
        """
        Return True if this entity overlaps with *other* in character space.

        Two entities overlap when at least one character belongs to both.
        Adjacent entities (where one ends exactly where the other starts)
        are **not** considered overlapping.

        Args:
            other: Another detected entity to compare against.

        Returns:
            True if the character ranges intersect, False otherwise.
        """
        return self.start < other.end and other.start < self.end


@dataclass
class RedactionResult:
    """
    Result of a single redaction operation.

    Contains the redacted text, all detected entities, and the placeholder
    mapping that can be used to restore the original values.

    Attributes:
        redacted_text: The text with PII replaced by placeholders such as
            ``<EMAIL_1>``, ``<PERSON_1>``, etc.
        entities: List of all detected entities, sorted by start position.
        mapping: Dict mapping each placeholder back to its original value,
            e.g. ``{"<EMAIL_1>": "john@example.com"}``.
        mapping_id: Optional ID under which the mapping was persisted in a
            ``MappingStore``. ``None`` when the caller did not request storage.
    """

    redacted_text: str
    entities: list[DetectedEntity]
    mapping: dict[str, str]
    mapping_id: Optional[str] = None


@dataclass
class RestorationResult:
    """
    Result of a single restoration operation.

    Attributes:
        restored_text: Text with placeholders replaced by their original values.
        placeholders_replaced: Number of distinct placeholder tokens that were
            successfully replaced. Placeholders not found in the mapping are
            left untouched and not counted here.
    """

    restored_text: str
    placeholders_replaced: int
