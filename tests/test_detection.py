"""
Tests for PII detection (regex-based, covering all entity types).

These tests run against the regex detector only and do NOT require
presidio-analyzer or spaCy to be installed.
"""

from __future__ import annotations

import pytest

from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.detection.regex_detector import RegexDetector

# ── Fixture shortcuts ─────────────────────────────────────────────────────────


@pytest.fixture
def regex_detector():
    """Regex-only detector, low threshold."""
    return RegexDetector()


@pytest.fixture
def detector():
    """PIIDetector with regex only and low threshold."""
    settings = Settings(enable_presidio=False, enable_spacy=False, min_confidence_score=0.5)
    return PIIDetector(config=settings)


def _has_entity(entities, entity_type):
    """Return True if any entity of *entity_type* is in *entities*."""
    return any(e.entity_type == entity_type for e in entities)


def _entity_count(entities, entity_type):
    return sum(1 for e in entities if e.entity_type == entity_type)


# ─────────────────────────────────────────────────────────────────────────────
# Email detection
# ─────────────────────────────────────────────────────────────────────────────


class TestEmailDetection:
    def test_simple_email(self, regex_detector):
        """Standard email address is detected."""
        entities = regex_detector.detect("Contact john@example.com please")
        assert _has_entity(entities, "EMAIL")

    def test_email_with_subdomain(self, regex_detector):
        """Email with subdomain is detected."""
        entities = regex_detector.detect("Write to user@mail.example.org")
        assert _has_entity(entities, "EMAIL")

    def test_email_with_plus_sign(self, regex_detector):
        """Email with + addressing is detected."""
        entities = regex_detector.detect("Send to john+tag@example.com")
        assert _has_entity(entities, "EMAIL")

    def test_email_with_numbers(self, regex_detector):
        """Email with numbers in local and domain parts is detected."""
        entities = regex_detector.detect("Try user123@example456.com")
        assert _has_entity(entities, "EMAIL")

    def test_email_in_sentence(self, regex_detector):
        """Email within a longer sentence is extracted at correct position."""
        text = "Please send the report to alice.smith@company.co.uk by Friday."
        entities = regex_detector.detect(text)
        assert _has_entity(entities, "EMAIL")
        email_entity = next(e for e in entities if e.entity_type == "EMAIL")
        extracted = text[email_entity.start:email_entity.end]
        assert "@" in extracted


# ─────────────────────────────────────────────────────────────────────────────
# Phone number detection
# ─────────────────────────────────────────────────────────────────────────────


class TestPhoneDetection:
    def test_us_format_parentheses(self, regex_detector):
        """US phone in (NXX) NXX-XXXX format."""
        entities = regex_detector.detect("Call (555) 123-4567 now")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_us_with_country_code(self, regex_detector):
        """US phone with +1 country code."""
        entities = regex_detector.detect("+1-555-123-4567")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_international_format(self, regex_detector):
        """UK international phone number detected."""
        entities = regex_detector.detect("Dial +44 20 7946 0958")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_dashes_format(self, regex_detector):
        """US phone with dashes only."""
        entities = regex_detector.detect("555-123-4567")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_dots_format(self, regex_detector):
        """US phone with dots as separators."""
        entities = regex_detector.detect("555.123.4567")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_romanian_format(self, regex_detector):
        """Romanian mobile number with +40 country code."""
        entities = regex_detector.detect("+40 721 123 456")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_german_format(self, regex_detector):
        """German phone number with +49 country code."""
        entities = regex_detector.detect("+49 30 12345678")
        assert _has_entity(entities, "PHONE_NUMBER")

    def test_in_sentence(self, regex_detector):
        """Phone number embedded in a sentence is extracted."""
        text = "Our support line is +1 800 555 0199 available 24/7."
        entities = regex_detector.detect(text)
        assert _has_entity(entities, "PHONE_NUMBER")


# ─────────────────────────────────────────────────────────────────────────────
# Credit card detection
# ─────────────────────────────────────────────────────────────────────────────


class TestCreditCardDetection:
    def test_visa_with_spaces(self, regex_detector):
        """Visa test number with spaces passes Luhn check."""
        entities = regex_detector.detect("Card: 4111 1111 1111 1111")
        assert _has_entity(entities, "CREDIT_CARD")

    def test_mastercard(self, regex_detector):
        """Mastercard test number is detected."""
        entities = regex_detector.detect("Pay with 5500 0000 0000 0004")
        assert _has_entity(entities, "CREDIT_CARD")

    def test_amex(self, regex_detector):
        """American Express test number is detected."""
        entities = regex_detector.detect("Amex: 3714 496353 98431")
        assert _has_entity(entities, "CREDIT_CARD")

    def test_with_dashes(self, regex_detector):
        """Card number with dashes is detected."""
        entities = regex_detector.detect("4111-1111-1111-1111")
        assert _has_entity(entities, "CREDIT_CARD")

    def test_no_separators(self, regex_detector):
        """16-digit card number without separators."""
        entities = regex_detector.detect("4111111111111111")
        assert _has_entity(entities, "CREDIT_CARD")

    def test_invalid_luhn_not_detected(self, regex_detector):
        """Number that fails Luhn check is NOT detected as credit card."""
        # 4111111111111112 — last digit changed to fail Luhn
        entities = regex_detector.detect("4111111111111112")
        assert not _has_entity(entities, "CREDIT_CARD")


# ─────────────────────────────────────────────────────────────────────────────
# IP address detection
# ─────────────────────────────────────────────────────────────────────────────


class TestIPAddressDetection:
    def test_ipv4_basic(self, regex_detector):
        """Basic IPv4 address is detected."""
        entities = regex_detector.detect("Server IP: 192.168.1.1")
        assert _has_entity(entities, "IP_ADDRESS")

    def test_ipv4_in_sentence(self, regex_detector):
        """IPv4 embedded in sentence."""
        entities = regex_detector.detect("The service is running at 10.0.0.1 on port 8080")
        assert _has_entity(entities, "IP_ADDRESS")

    def test_ipv6_full(self, regex_detector):
        """Full IPv6 address is detected."""
        entities = regex_detector.detect("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert _has_entity(entities, "IP_ADDRESS")

    def test_loopback(self, regex_detector):
        """Loopback address 127.0.0.1 is detected."""
        entities = regex_detector.detect("Connect to 127.0.0.1")
        assert _has_entity(entities, "IP_ADDRESS")


# ─────────────────────────────────────────────────────────────────────────────
# IBAN detection
# ─────────────────────────────────────────────────────────────────────────────


class TestIBANDetection:
    def test_german_iban(self, regex_detector):
        """German IBAN is detected."""
        entities = regex_detector.detect("IBAN: DE89 3704 0044 0532 0130 00")
        assert _has_entity(entities, "IBAN")

    def test_uk_iban(self, regex_detector):
        """UK IBAN is detected."""
        entities = regex_detector.detect("Account: GB29 NWBK 6016 1331 9268 19")
        assert _has_entity(entities, "IBAN")

    def test_romanian_iban(self, regex_detector):
        """Romanian IBAN is detected."""
        entities = regex_detector.detect("RO49 AAAA 1B31 0075 9384 0000")
        assert _has_entity(entities, "IBAN")

    def test_iban_in_sentence(self, regex_detector):
        """IBAN embedded in a sentence."""
        text = "Please transfer to DE89370400440532013000 by end of month."
        entities = regex_detector.detect(text)
        assert _has_entity(entities, "IBAN")


# ─────────────────────────────────────────────────────────────────────────────
# URL detection
# ─────────────────────────────────────────────────────────────────────────────


class TestURLDetection:
    def test_https_url(self, regex_detector):
        """HTTPS URL is detected."""
        entities = regex_detector.detect("Visit https://example.com for details")
        assert _has_entity(entities, "URL")

    def test_url_with_path_and_query(self, regex_detector):
        """URL with path and query string is detected."""
        entities = regex_detector.detect("See https://example.com/path?q=1#anchor")
        assert _has_entity(entities, "URL")

    def test_http_url(self, regex_detector):
        """HTTP URL is detected."""
        entities = regex_detector.detect("http://internal.service/api/v1")
        assert _has_entity(entities, "URL")

    def test_ftp_url(self, regex_detector):
        """FTP URL is detected."""
        entities = regex_detector.detect("Download from ftp://files.example.com/data.zip")
        assert _has_entity(entities, "URL")


# ─────────────────────────────────────────────────────────────────────────────
# SSN detection
# ─────────────────────────────────────────────────────────────────────────────


class TestSSNDetection:
    def test_us_ssn(self, regex_detector):
        """Standard US SSN is detected."""
        entities = regex_detector.detect("SSN: 123-45-6789")
        assert _has_entity(entities, "SSN")

    def test_ssn_in_text(self, regex_detector):
        """SSN embedded in text is detected."""
        entities = regex_detector.detect("Social security number is 234-56-7890 on file")
        assert _has_entity(entities, "SSN")

    def test_invalid_ssn_starting_000_not_detected(self, regex_detector):
        """SSN starting with 000 is rejected by pattern."""
        entities = regex_detector.detect("000-12-3456")
        # Should not detect as SSN (pattern excludes 000-xxx-xxxx)
        ssn_entities = [e for e in entities if e.entity_type == "SSN"]
        assert len(ssn_entities) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Physical address detection
# ─────────────────────────────────────────────────────────────────────────────


class TestAddressDetection:
    def test_street_address(self, regex_detector):
        """Simple street address is detected."""
        entities = regex_detector.detect("She lives at 123 Main Street")
        assert _has_entity(entities, "ADDRESS")

    def test_avenue_address(self, regex_detector):
        """Address with Ave suffix."""
        entities = regex_detector.detect("Office at 456 Oak Ave")
        assert _has_entity(entities, "ADDRESS")

    def test_address_in_sentence(self, regex_detector):
        """Street address embedded in a longer sentence."""
        text = "Send the package to 789 Elm Drive by Thursday."
        entities = regex_detector.detect(text)
        assert _has_entity(entities, "ADDRESS")


# ─────────────────────────────────────────────────────────────────────────────
# Date of birth detection
# ─────────────────────────────────────────────────────────────────────────────


class TestDateDetection:
    def test_iso_format(self, regex_detector):
        """ISO 8601 date is detected."""
        entities = regex_detector.detect("Born on 1990-01-15")
        assert _has_entity(entities, "DATE_OF_BIRTH")

    def test_us_slash_format(self, regex_detector):
        """MM/DD/YYYY date is detected."""
        entities = regex_detector.detect("DOB: 01/15/1990")
        assert _has_entity(entities, "DATE_OF_BIRTH")

    def test_spelled_out_month(self, regex_detector):
        """Spelled-out month date is detected."""
        entities = regex_detector.detect("January 15, 1990")
        assert _has_entity(entities, "DATE_OF_BIRTH")


# ─────────────────────────────────────────────────────────────────────────────
# Empty / edge cases
# ─────────────────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_string(self, regex_detector):
        """Empty string returns no entities."""
        assert regex_detector.detect("") == []

    def test_whitespace_only(self, regex_detector):
        """Whitespace-only string returns no entities."""
        assert regex_detector.detect("   \n\t  ") == []

    def test_no_pii(self, regex_detector):
        """Text without PII returns empty list."""
        entities = regex_detector.detect("The weather is nice today.")
        # No deterministic PII patterns should match
        assert len(entities) == 0 or all(
            e.entity_type not in {"EMAIL", "PHONE_NUMBER", "CREDIT_CARD", "SSN"}
            for e in entities
        )

    def test_multiple_entity_types(self, detector):
        """Multiple entity types in one text are all detected."""
        text = "Email john@example.com or call +1-555-123-4567"
        entities = detector.detect(text)
        types = {e.entity_type for e in entities}
        assert "EMAIL" in types
        assert "PHONE_NUMBER" in types

    def test_entity_source_is_regex(self, regex_detector):
        """All entities from regex detector have source='regex'."""
        entities = regex_detector.detect("john@example.com")
        assert all(e.source in ("regex", "custom") for e in entities)
