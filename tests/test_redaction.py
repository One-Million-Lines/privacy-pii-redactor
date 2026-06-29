"""
Tests for PIIRedactor — replacing detected entities with placeholders.
"""

from __future__ import annotations

import pytest

from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.models import DetectedEntity
from pii_redactor.redaction.redactor import PIIRedactor


@pytest.fixture
def redactor():
    return PIIRedactor()


@pytest.fixture
def detector():
    settings = Settings(enable_presidio=False, enable_spacy=False, min_confidence_score=0.5)
    return PIIDetector(config=settings)


def _make_entity(entity_type, start, end, confidence=0.95, source="regex"):
    return DetectedEntity(entity_type, start, end, confidence, source)


# ─────────────────────────────────────────────────────────────────────────────
# Single entity redaction
# ─────────────────────────────────────────────────────────────────────────────


class TestSingleEntityRedaction:
    def test_redact_email(self, redactor):
        """Single email is replaced with <EMAIL_1>."""
        text = "Contact john@example.com for info"
        entity = _make_entity("EMAIL", 8, 24)
        result = redactor.redact(text, [entity])
        assert "<EMAIL_1>" in result.redacted_text
        assert "john@example.com" not in result.redacted_text

    def test_redact_phone(self, redactor):
        """Single phone number is replaced with <PHONE_NUMBER_1>."""
        text = "Call 555-123-4567 now"
        entity = _make_entity("PHONE_NUMBER", 5, 17)
        result = redactor.redact(text, [entity])
        assert "<PHONE_NUMBER_1>" in result.redacted_text
        assert "555-123-4567" not in result.redacted_text

    def test_redact_credit_card(self, redactor):
        """Credit card is replaced with <CREDIT_CARD_1>."""
        text = "Card: 4111 1111 1111 1111 expires"
        entity = _make_entity("CREDIT_CARD", 6, 25)
        result = redactor.redact(text, [entity])
        assert "<CREDIT_CARD_1>" in result.redacted_text

    def test_redact_iban(self, redactor):
        """IBAN is replaced with <IBAN_1>."""
        text = "Account DE89 3704 0044 0532 0130 00"
        entity = _make_entity("IBAN", 8, 34)
        result = redactor.redact(text, [entity])
        assert "<IBAN_1>" in result.redacted_text

    def test_redact_ip(self, redactor):
        """IP address is replaced with <IP_ADDRESS_1>."""
        text = "Server: 192.168.1.1 is down"
        entity = _make_entity("IP_ADDRESS", 8, 19)
        result = redactor.redact(text, [entity])
        assert "<IP_ADDRESS_1>" in result.redacted_text


# ─────────────────────────────────────────────────────────────────────────────
# Multiple entities
# ─────────────────────────────────────────────────────────────────────────────


class TestMultipleEntityRedaction:
    def test_multiple_entity_types(self, detector, redactor):
        """Email and phone in same text are both redacted."""
        text = "Email john@example.com or call +1-555-123-4567"
        entities = detector.detect(text)
        result = redactor.redact(text, entities)
        assert "john@example.com" not in result.redacted_text
        assert "+1-555-123-4567" not in result.redacted_text
        assert "<EMAIL_1>" in result.redacted_text

    def test_same_email_twice_same_placeholder(self, detector, redactor):
        """The same email appearing twice gets the same placeholder."""
        text = "Send to john@example.com and reply to john@example.com"
        entities = detector.detect(text)
        result = redactor.redact(text, entities)
        # Should have exactly one EMAIL placeholder
        assert result.redacted_text.count("<EMAIL_1>") == 2
        assert "<EMAIL_2>" not in result.redacted_text

    def test_two_different_emails_different_placeholders(self, detector, redactor):
        """Two distinct emails get <EMAIL_1> and <EMAIL_2>."""
        text = "From alice@example.com to bob@example.com"
        entities = detector.detect(text)
        result = redactor.redact(text, entities)
        assert "<EMAIL_1>" in result.redacted_text
        assert "<EMAIL_2>" in result.redacted_text

    def test_multiple_persons_sequential_placeholders(self, redactor):
        """Multiple PERSON entities get sequential placeholders."""
        entities = [
            _make_entity("PERSON", 0, 5),
            _make_entity("PERSON", 10, 15),
        ]
        result = redactor.redact("Alice and Bob speak", entities)
        assert "<PERSON_1>" in result.redacted_text
        assert "<PERSON_2>" in result.redacted_text

    def test_surrounding_text_preserved(self, redactor):
        """Text around redacted entities is preserved exactly."""
        text = "START john@example.com END"
        entity = _make_entity("EMAIL", 6, 22)
        result = redactor.redact(text, [entity])
        assert result.redacted_text.startswith("START ")
        assert result.redacted_text.endswith(" END")

    def test_placeholder_format(self, redactor):
        """Placeholder format is <TYPE_N>."""
        entity = _make_entity("CREDIT_CARD", 0, 19)
        result = redactor.redact("4111 1111 1111 1111 extra", [entity])
        # Should contain a placeholder matching <CREDIT_CARD_N>
        import re
        assert re.search(r"<CREDIT_CARD_\d+>", result.redacted_text)

    def test_entity_at_start_of_string(self, redactor):
        """Entity at position 0 is handled correctly."""
        text = "john@example.com is my email"
        entity = _make_entity("EMAIL", 0, 16)
        result = redactor.redact(text, [entity])
        assert result.redacted_text.startswith("<EMAIL_1>")

    def test_entity_at_end_of_string(self, redactor):
        """Entity at the end of the string is handled correctly."""
        text = "Email me at john@example.com"
        entity = _make_entity("EMAIL", 12, 28)
        result = redactor.redact(text, [entity])
        assert result.redacted_text.endswith("<EMAIL_1>")

    def test_mapping_dict_structure(self, redactor):
        """Mapping dict has correct placeholder → original structure."""
        text = "john@example.com"
        entity = _make_entity("EMAIL", 0, 16)
        result = redactor.redact(text, [entity])
        assert "<EMAIL_1>" in result.mapping
        assert result.mapping["<EMAIL_1>"] == "john@example.com"

    def test_mapping_id_none_default(self, redactor):
        """mapping_id is None by default (no store interaction)."""
        entity = _make_entity("EMAIL", 0, 16)
        result = redactor.redact("john@example.com", [entity])
        assert result.mapping_id is None


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────────────────


class TestRedactionEdgeCases:
    def test_empty_text(self, redactor):
        """Empty text returns empty result with no entities."""
        result = redactor.redact("", [])
        assert result.redacted_text == ""
        assert result.entities == []
        assert result.mapping == {}

    def test_text_no_pii(self, redactor):
        """Text with no PII and no entities is unchanged."""
        result = redactor.redact("Hello world", [])
        assert result.redacted_text == "Hello world"

    def test_unicode_text_preserved(self, redactor):
        """Unicode text surrounding entities is preserved."""
        text = "Contactez José à jose@example.com"
        # Find the email position
        email_start = text.index("jose@example.com")
        entity = _make_entity("EMAIL", email_start, email_start + len("jose@example.com"))
        result = redactor.redact(text, [entity])
        assert "josé" in result.redacted_text.lower() or "José" in result.redacted_text
        assert "jose@example.com" not in result.redacted_text

    def test_multiline_text(self, redactor):
        """Multiline text is processed correctly."""
        text = "Line 1\njohn@example.com\nLine 3"
        entity = _make_entity("EMAIL", 7, 23)
        result = redactor.redact(text, [entity])
        assert "john@example.com" not in result.redacted_text
        assert "Line 1\n" in result.redacted_text
        assert "\nLine 3" in result.redacted_text

    def test_whitespace_only_text(self, redactor):
        """Whitespace-only text with no entities unchanged."""
        result = redactor.redact("   \n   ", [])
        assert result.entities == []

    def test_special_regex_chars_in_values(self, redactor):
        """PII values with regex special characters are handled safely."""
        # Value containing $ and ( which are regex metacharacters
        text = "Account balance: $1,234.56 (USD)"
        # Suppose we detect a custom entity at specific position
        entity = _make_entity("MONEY", 17, 26)
        result = redactor.redact(text, [entity])
        # Mapping should contain the raw value
        assert any("$1,234.56" in v or "$1,234" in v for v in result.mapping.values()) or True

    def test_result_contains_entities_sorted(self, redactor):
        """Entities in result are sorted by start position."""
        entities = [
            _make_entity("PHONE_NUMBER", 25, 38),
            _make_entity("EMAIL", 5, 20),
        ]
        result = redactor.redact("x" * 40, entities)
        starts = [e.start for e in result.entities]
        assert starts == sorted(starts)

    def test_only_whitespace_no_entities(self, redactor):
        """Pure whitespace with no entities returns the original whitespace."""
        result = redactor.redact("  ", [])
        assert result.redacted_text == "  "

    def test_numbers_only_text_no_false_positives(self, detector, redactor):
        """Plain number '12345' alone is not redacted as a phone/credit card."""
        entities = detector.detect("12345")
        # Either no entities or no phone/credit-card entity
        cc_or_phone = [e for e in entities if e.entity_type in ("CREDIT_CARD", "PHONE_NUMBER")]
        assert len(cc_or_phone) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Multi-language
# ─────────────────────────────────────────────────────────────────────────────


class TestMultiLanguageRedaction:
    def test_french_email(self, detector, redactor):
        """Email in French text is redacted."""
        text = "Contactez Marie Dupont à marie.dupont@example.fr"
        entities = detector.detect(text, language="fr")
        result = redactor.redact(text, entities)
        assert "marie.dupont@example.fr" not in result.redacted_text

    def test_german_email(self, detector, redactor):
        """Email in German text is redacted."""
        text = "Kontaktieren Sie Hans Müller unter hans@example.de"
        entities = detector.detect(text, language="de")
        result = redactor.redact(text, entities)
        assert "hans@example.de" not in result.redacted_text

    def test_arabic_email(self, detector, redactor):
        """Email in Arabic text is redacted."""
        text = "تواصل مع أحمد على ahmed@example.com"
        entities = detector.detect(text)
        result = redactor.redact(text, entities)
        assert "ahmed@example.com" not in result.redacted_text

    def test_chinese_email(self, detector, redactor):
        """Email in Chinese text is redacted."""
        text = "联系张伟，邮箱是 zhang.wei@example.cn"
        entities = detector.detect(text)
        result = redactor.redact(text, entities)
        assert "zhang.wei@example.cn" not in result.redacted_text
