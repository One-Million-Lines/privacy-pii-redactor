"""
Tests for PIIRestorer — replacing placeholders with original PII values.
"""

from __future__ import annotations

import pytest

from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer


@pytest.fixture
def restorer():
    return PIIRestorer()


@pytest.fixture
def detector():
    settings = Settings(enable_presidio=False, enable_spacy=False, min_confidence_score=0.5)
    return PIIDetector(config=settings)


@pytest.fixture
def redactor():
    return PIIRedactor()


class TestBasicRestoration:
    def test_restore_single_placeholder(self, restorer):
        """Single placeholder is replaced with its original value."""
        mapping = {"<EMAIL_1>": "john@example.com"}
        result = restorer.restore("Contact <EMAIL_1> please", mapping)
        assert result.restored_text == "Contact john@example.com please"
        assert result.placeholders_replaced == 1

    def test_restore_multiple_placeholders(self, restorer):
        """Multiple different placeholders are all replaced."""
        mapping = {
            "<EMAIL_1>": "john@example.com",
            "<PHONE_NUMBER_1>": "555-123-4567",
        }
        result = restorer.restore("Email <EMAIL_1> or call <PHONE_NUMBER_1>", mapping)
        assert "john@example.com" in result.restored_text
        assert "555-123-4567" in result.restored_text
        assert result.placeholders_replaced == 2

    def test_restore_preserves_surrounding_text(self, restorer):
        """Text around placeholders is preserved exactly."""
        mapping = {"<EMAIL_1>": "user@example.com"}
        result = restorer.restore("PREFIX <EMAIL_1> SUFFIX", mapping)
        assert result.restored_text == "PREFIX user@example.com SUFFIX"

    def test_unknown_placeholder_left_unchanged(self, restorer):
        """Unknown placeholder not in mapping is left as-is."""
        mapping = {"<EMAIL_1>": "a@b.com"}
        result = restorer.restore("Known <EMAIL_1> and unknown <PERSON_1>", mapping)
        assert "a@b.com" in result.restored_text
        assert "<PERSON_1>" in result.restored_text  # unchanged

    def test_restore_empty_text(self, restorer):
        """Empty text returns empty result with 0 replacements."""
        result = restorer.restore("", {"<EMAIL_1>": "a@b.com"})
        assert result.restored_text == ""
        assert result.placeholders_replaced == 0

    def test_restore_text_no_placeholders(self, restorer):
        """Text with no placeholder tokens returns 0 replacements."""
        result = restorer.restore("Hello world", {"<EMAIL_1>": "a@b.com"})
        assert result.restored_text == "Hello world"
        assert result.placeholders_replaced == 0

    def test_restoration_count_correct(self, restorer):
        """placeholders_replaced is accurate."""
        mapping = {
            "<EMAIL_1>": "a@b.com",
            "<PHONE_NUMBER_1>": "555-0000",
            "<CREDIT_CARD_1>": "4111111111111111",
        }
        text = "<EMAIL_1> <PHONE_NUMBER_1> <CREDIT_CARD_1>"
        result = restorer.restore(text, mapping)
        assert result.placeholders_replaced == 3

    def test_partial_restore_known_and_unknown(self, restorer):
        """Only known placeholders are replaced; unknown ones stay."""
        mapping = {"<EMAIL_1>": "a@b.com"}
        text = "<EMAIL_1> and <UNKNOWN_1>"
        result = restorer.restore(text, mapping)
        assert "a@b.com" in result.restored_text
        assert "<UNKNOWN_1>" in result.restored_text
        assert result.placeholders_replaced == 1

    def test_same_placeholder_multiple_times(self, restorer):
        """Same placeholder appearing multiple times is replaced each time."""
        mapping = {"<EMAIL_1>": "john@example.com"}
        text = "Send to <EMAIL_1> and cc <EMAIL_1>"
        result = restorer.restore(text, mapping)
        assert result.restored_text == "Send to john@example.com and cc john@example.com"
        assert result.placeholders_replaced == 2

    def test_empty_mapping(self, restorer):
        """Empty mapping → no replacements, text unchanged."""
        text = "<EMAIL_1> stays"
        result = restorer.restore(text, {})
        assert result.restored_text == "<EMAIL_1> stays"
        assert result.placeholders_replaced == 0

    def test_restoration_count_with_mapping_10_entities(self, restorer):
        """Restoration with 10 different entity placeholders."""
        mapping = {f"<EMAIL_{i}>": f"user{i}@example.com" for i in range(1, 11)}
        text = " ".join(f"<EMAIL_{i}>" for i in range(1, 11))
        result = restorer.restore(text, mapping)
        assert result.placeholders_replaced == 10
        for i in range(1, 11):
            assert f"user{i}@example.com" in result.restored_text


class TestRoundTrip:
    def test_redact_then_restore_gives_original(self, detector, redactor, restorer):
        """Full round-trip: redact → restore == original text."""
        original = "Contact john@example.com or call +1-555-123-4567"
        entities = detector.detect(original)
        red_result = redactor.redact(original, entities)
        rest_result = restorer.restore(red_result.redacted_text, red_result.mapping)
        assert rest_result.restored_text == original

    def test_round_trip_email_only(self, detector, redactor, restorer):
        """Round-trip with single email."""
        original = "Email alice@domain.org today"
        entities = detector.detect(original)
        red = redactor.redact(original, entities)
        restored = restorer.restore(red.redacted_text, red.mapping)
        assert restored.restored_text == original

    def test_round_trip_credit_card(self, detector, redactor, restorer):
        """Round-trip with credit card."""
        original = "Card number 4111 1111 1111 1111 must be protected"
        entities = detector.detect(original)
        red = redactor.redact(original, entities)
        restored = restorer.restore(red.redacted_text, red.mapping)
        assert restored.restored_text == original

    def test_restore_from_store(self, redactor, restorer):
        """Restore using a mapping retrieved from a store."""
        from pii_redactor.models import DetectedEntity
        from pii_redactor.storage.memory import InMemoryStore

        store = InMemoryStore()
        entity = DetectedEntity("EMAIL", 8, 24, 0.95, "regex")
        text = "Contact john@example.com for info"
        red_result = redactor.redact(text, [entity])
        mapping_id = store.save(red_result.mapping, ttl=60)

        mapping = store.get(mapping_id)
        assert mapping is not None
        rest_result = restorer.restore(red_result.redacted_text, mapping)
        assert rest_result.restored_text == text


class TestRestorationEdgeCases:
    def test_modified_placeholder_left_unchanged(self, restorer):
        """Placeholder with wrong format (e.g., LLM modified it) is left unchanged."""
        mapping = {"<EMAIL_1>": "john@example.com"}
        # LLM changed the format
        text = "Contact [EMAIL_1] for info"
        result = restorer.restore(text, mapping)
        assert "[EMAIL_1]" in result.restored_text
        assert result.placeholders_replaced == 0

    def test_restore_german_with_umlauts(self, restorer):
        """German text with umlauts restored correctly."""
        mapping = {"<EMAIL_1>": "hans@müller.de"}
        result = restorer.restore("Schreiben Sie <EMAIL_1>", mapping)
        assert "hans@müller.de" in result.restored_text

    def test_restore_french_accents(self, restorer):
        """French text with accents restored correctly."""
        mapping = {"<EMAIL_1>": "marie.dupont@example.fr"}
        result = restorer.restore("Contactez <EMAIL_1> s'il vous plaît", mapping)
        assert "marie.dupont@example.fr" in result.restored_text

    def test_restore_email_different_position(self, restorer):
        """Placeholder at different positions in the sentence."""
        mapping = {"<EMAIL_1>": "a@b.com"}
        # Placeholder at end
        result = restorer.restore("The email is <EMAIL_1>", mapping)
        assert result.restored_text.endswith("a@b.com")
        # Placeholder at start
        result2 = restorer.restore("<EMAIL_1> is the contact", mapping)
        assert result2.restored_text.startswith("a@b.com")
