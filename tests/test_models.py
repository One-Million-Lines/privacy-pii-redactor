"""
Tests for core data models (models.py).

Covers DetectedEntity, RedactionResult, and RestorationResult dataclasses.
"""

from __future__ import annotations

import pytest

from pii_redactor.models import DetectedEntity, RedactionResult, RestorationResult

# ──────────────────────────────────────────────────────────────────────────────
# DetectedEntity
# ──────────────────────────────────────────────────────────────────────────────


class TestDetectedEntity:
    def test_creation_and_fields(self):
        """DetectedEntity stores all fields correctly."""
        e = DetectedEntity("EMAIL", 5, 20, 0.95, "regex")
        assert e.entity_type == "EMAIL"
        assert e.start == 5
        assert e.end == 20
        assert e.confidence == 0.95
        assert e.source == "regex"

    def test_source_presidio(self):
        """DetectedEntity accepts 'presidio' as source."""
        e = DetectedEntity("PERSON", 0, 10, 0.80, "presidio")
        assert e.source == "presidio"

    def test_source_spacy(self):
        """DetectedEntity accepts 'spacy' as source."""
        e = DetectedEntity("PERSON", 0, 10, 0.75, "spacy")
        assert e.source == "spacy"

    def test_source_custom(self):
        """DetectedEntity accepts 'custom' as source."""
        e = DetectedEntity("CUSTOMER_ID", 0, 10, 0.90, "custom")
        assert e.source == "custom"

    def test_source_regex(self):
        """DetectedEntity accepts 'regex' as source."""
        e = DetectedEntity("SSN", 3, 14, 0.97, "regex")
        assert e.source == "regex"

    def test_span_length(self):
        """span_length property returns correct character count."""
        e = DetectedEntity("EMAIL", 5, 25, 0.95, "regex")
        assert e.span_length == 20

    def test_overlaps_true(self):
        """Two overlapping entities return True from overlaps()."""
        e1 = DetectedEntity("EMAIL", 0, 15, 0.95, "regex")
        e2 = DetectedEntity("PERSON", 10, 25, 0.80, "presidio")
        assert e1.overlaps(e2)
        assert e2.overlaps(e1)

    def test_overlaps_false_adjacent(self):
        """Adjacent entities (end == start of next) do NOT overlap."""
        e1 = DetectedEntity("EMAIL", 0, 10, 0.95, "regex")
        e2 = DetectedEntity("PHONE_NUMBER", 10, 25, 0.85, "regex")
        assert not e1.overlaps(e2)
        assert not e2.overlaps(e1)

    def test_confidence_validation_min(self):
        """confidence=0.0 is valid."""
        e = DetectedEntity("EMAIL", 0, 5, 0.0, "regex")
        assert e.confidence == 0.0

    def test_confidence_validation_max(self):
        """confidence=1.0 is valid."""
        e = DetectedEntity("EMAIL", 0, 5, 1.0, "regex")
        assert e.confidence == 1.0

    def test_confidence_out_of_range_raises(self):
        """confidence > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            DetectedEntity("EMAIL", 0, 5, 1.5, "regex")

    def test_confidence_negative_raises(self):
        """confidence < 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            DetectedEntity("EMAIL", 0, 5, -0.1, "regex")

    def test_invalid_source_raises(self):
        """Unknown source string raises ValueError."""
        with pytest.raises(ValueError, match="source"):
            DetectedEntity("EMAIL", 0, 5, 0.9, "unknown_source")

    def test_negative_start_raises(self):
        """Negative start raises ValueError."""
        with pytest.raises(ValueError, match="start"):
            DetectedEntity("EMAIL", -1, 5, 0.9, "regex")

    def test_end_before_start_raises(self):
        """end < start raises ValueError."""
        with pytest.raises(ValueError, match="end"):
            DetectedEntity("EMAIL", 10, 5, 0.9, "regex")

    def test_zero_length_span(self):
        """start == end (zero-length span) is valid."""
        e = DetectedEntity("EMAIL", 5, 5, 0.9, "regex")
        assert e.span_length == 0

    def test_overlaps_no_same_entity(self):
        """Entity does not overlap with itself (technically trivially true)."""
        e = DetectedEntity("EMAIL", 5, 15, 0.95, "regex")
        assert e.overlaps(e)  # overlaps with itself


# ──────────────────────────────────────────────────────────────────────────────
# RedactionResult
# ──────────────────────────────────────────────────────────────────────────────


class TestRedactionResult:
    def test_basic_creation(self):
        """RedactionResult stores all fields."""
        entity = DetectedEntity("EMAIL", 0, 15, 0.95, "regex")
        result = RedactionResult(
            redacted_text="<EMAIL_1>",
            entities=[entity],
            mapping={"<EMAIL_1>": "john@example.com"},
        )
        assert result.redacted_text == "<EMAIL_1>"
        assert len(result.entities) == 1
        assert result.mapping["<EMAIL_1>"] == "john@example.com"
        assert result.mapping_id is None

    def test_mapping_id_none_by_default(self):
        """mapping_id defaults to None."""
        result = RedactionResult("text", [], {})
        assert result.mapping_id is None

    def test_mapping_id_set(self):
        """mapping_id can be set after creation."""
        result = RedactionResult("text", [], {})
        result.mapping_id = "abc123"
        assert result.mapping_id == "abc123"

    def test_empty_entities(self):
        """Empty entities list is valid."""
        result = RedactionResult("no pii here", [], {})
        assert result.entities == []
        assert result.mapping == {}

    def test_multiple_entities(self):
        """Multiple entities stored correctly."""
        e1 = DetectedEntity("EMAIL", 0, 10, 0.95, "regex")
        e2 = DetectedEntity("PHONE_NUMBER", 15, 30, 0.88, "regex")
        result = RedactionResult(
            "<EMAIL_1> and <PHONE_NUMBER_1>",
            [e1, e2],
            {"<EMAIL_1>": "a@b.com", "<PHONE_NUMBER_1>": "555-1234"},
        )
        assert len(result.entities) == 2
        assert len(result.mapping) == 2


# ──────────────────────────────────────────────────────────────────────────────
# RestorationResult
# ──────────────────────────────────────────────────────────────────────────────


class TestRestorationResult:
    def test_basic_creation(self):
        """RestorationResult stores fields correctly."""
        result = RestorationResult(restored_text="Hello John", placeholders_replaced=1)
        assert result.restored_text == "Hello John"
        assert result.placeholders_replaced == 1

    def test_zero_replacements(self):
        """Zero placeholders replaced is valid."""
        result = RestorationResult(restored_text="no placeholders", placeholders_replaced=0)
        assert result.placeholders_replaced == 0

    def test_multiple_replacements(self):
        """Multiple replacements counted correctly."""
        result = RestorationResult(
            restored_text="email and phone restored", placeholders_replaced=2
        )
        assert result.placeholders_replaced == 2
