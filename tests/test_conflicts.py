"""
Tests for ConflictResolver — removing overlapping entity detections.
"""

from __future__ import annotations

import pytest

from pii_redactor.detection.conflict_resolver import ConflictResolver
from pii_redactor.models import DetectedEntity


def make(entity_type, start, end, confidence=0.80, source="regex"):
    """Helper to create DetectedEntity instances."""
    return DetectedEntity(entity_type, start, end, confidence, source)


@pytest.fixture
def resolver():
    return ConflictResolver()


class TestConflictResolver:
    def test_non_overlapping_both_kept(self, resolver):
        """Two non-overlapping entities are both kept."""
        e1 = make("EMAIL", 0, 20)
        e2 = make("PHONE_NUMBER", 25, 40)
        result = resolver.resolve([e1, e2])
        assert len(result) == 2

    def test_exactly_overlapping_highest_confidence_wins(self, resolver):
        """Two entities at same span: highest confidence is selected."""
        e_high = make("EMAIL", 5, 25, confidence=0.95, source="presidio")
        e_low = make("EMAIL", 5, 25, confidence=0.60, source="spacy")
        result = resolver.resolve([e_high, e_low])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_partial_overlap_larger_span_wins(self, resolver):
        """Partial overlap: larger span takes priority (same source/confidence)."""
        e_large = make("EMAIL", 0, 30, confidence=0.80, source="presidio")
        e_small = make("PERSON", 15, 25, confidence=0.80, source="presidio")
        result = resolver.resolve([e_large, e_small])
        assert len(result) == 1
        assert result[0].span_length == 30

    def test_regex_preferred_over_spacy_same_span(self, resolver):
        """Regex source beats spacy for the same character span."""
        e_regex = make("EMAIL", 5, 25, confidence=0.80, source="regex")
        e_spacy = make("PERSON", 5, 25, confidence=0.90, source="spacy")
        result = resolver.resolve([e_regex, e_spacy])
        assert len(result) == 1
        assert result[0].source == "regex"

    def test_presidio_preferred_over_spacy_same_span(self, resolver):
        """Presidio source beats spacy for the same character span."""
        e_presidio = make("EMAIL", 5, 25, confidence=0.80, source="presidio")
        e_spacy = make("EMAIL", 5, 25, confidence=0.90, source="spacy")
        result = resolver.resolve([e_presidio, e_spacy])
        assert len(result) == 1
        assert result[0].source == "presidio"

    def test_custom_same_priority_as_regex(self, resolver):
        """Custom source has same priority as regex."""
        e_custom = make("CUSTOMER_ID", 5, 15, confidence=0.90, source="custom")
        e_spacy = make("PERSON", 5, 15, confidence=0.95, source="spacy")
        result = resolver.resolve([e_custom, e_spacy])
        assert len(result) == 1
        assert result[0].source == "custom"

    def test_multiple_overlapping_same_source(self, resolver):
        """Multiple overlapping from same source: highest confidence wins."""
        e_low = make("EMAIL", 0, 20, confidence=0.70, source="presidio")
        e_high = make("EMAIL", 0, 20, confidence=0.90, source="presidio")
        result = resolver.resolve([e_low, e_high])
        assert len(result) == 1
        assert result[0].confidence == 0.90

    def test_email_vs_person_same_span_regex_wins(self, resolver):
        """EMAIL (regex) wins over PERSON (spacy) for same span."""
        e_email = make("EMAIL", 10, 30, confidence=0.95, source="regex")
        e_person = make("PERSON", 10, 30, confidence=0.80, source="spacy")
        result = resolver.resolve([e_email, e_person])
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"

    def test_adjacent_entities_both_kept(self, resolver):
        """Adjacent entities (e1.end == e2.start) are both kept."""
        e1 = make("EMAIL", 0, 16)   # ends at 16
        e2 = make("PHONE_NUMBER", 16, 30)  # starts at 16
        result = resolver.resolve([e1, e2])
        assert len(result) == 2

    def test_three_way_overlap_one_winner(self, resolver):
        """Three overlapping entities resolve to exactly one winner."""
        e1 = make("EMAIL", 5, 25, confidence=0.95, source="regex")
        e2 = make("PERSON", 8, 20, confidence=0.80, source="presidio")
        e3 = make("LOCATION", 5, 25, confidence=0.70, source="spacy")
        result = resolver.resolve([e1, e2, e3])
        assert len(result) == 1
        assert result[0].source == "regex"

    def test_large_span_vs_small_same_confidence(self, resolver):
        """Larger span wins over smaller when confidence is equal."""
        e_large = make("EMAIL", 0, 30, confidence=0.80, source="presidio")
        e_small = make("EMAIL", 5, 15, confidence=0.80, source="presidio")
        result = resolver.resolve([e_large, e_small])
        assert len(result) == 1
        assert result[0].span_length == 30

    def test_empty_input_returns_empty(self, resolver):
        """Empty input returns empty list."""
        assert resolver.resolve([]) == []

    def test_single_entity_returned_unchanged(self, resolver):
        """Single entity is returned as-is."""
        e = make("EMAIL", 5, 20)
        result = resolver.resolve([e])
        assert len(result) == 1
        assert result[0] == e

    def test_stable_output_same_input_same_output(self, resolver):
        """Same input always produces same output (deterministic)."""
        entities = [
            make("EMAIL", 0, 15, confidence=0.90, source="regex"),
            make("PERSON", 5, 20, confidence=0.85, source="spacy"),
            make("PHONE_NUMBER", 25, 40, confidence=0.88, source="regex"),
        ]
        result1 = resolver.resolve(entities[:])
        result2 = resolver.resolve(entities[:])
        assert [e.entity_type for e in result1] == [e.entity_type for e in result2]

    def test_output_sorted_by_start_position(self, resolver):
        """Output is sorted by start position (document order)."""
        e1 = make("PHONE_NUMBER", 30, 45)
        e2 = make("EMAIL", 5, 20)
        e3 = make("CREDIT_CARD", 50, 70)
        result = resolver.resolve([e1, e2, e3])
        starts = [e.start for e in result]
        assert starts == sorted(starts)

    def test_no_overlaps_in_output(self, resolver):
        """No two entities in the output share any character position."""
        entities = [
            make("EMAIL", 0, 20),
            make("PERSON", 10, 30),
            make("PHONE_NUMBER", 25, 45),
            make("CREDIT_CARD", 40, 60),
        ]
        result = resolver.resolve(entities)
        # Check no overlaps in result
        for i, e1 in enumerate(result):
            for e2 in result[i + 1:]:
                assert not e1.overlaps(e2), f"{e1} overlaps {e2}"
