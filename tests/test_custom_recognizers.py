"""
Tests for custom recognizers loaded via Python dict or YAML config.
"""

from __future__ import annotations

import pytest

from pii_redactor.config import Settings, load_yaml_config
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.detection.regex_detector import RegexDetector
from pii_redactor.redaction.redactor import PIIRedactor

CUSTOMER_ID_PATTERN = {"name": "CUSTOMER_ID", "pattern": r"CUS-[0-9]{6}", "confidence": 0.95}
PROJECT_CODE_PATTERN = {"name": "PROJECT_CODE", "pattern": r"PRJ-[A-Z]{3}-[0-9]{4}", "confidence": 0.90}

YAML_CONFIG_CONTENT = """
custom_recognizers:
  - name: CUSTOMER_ID
    pattern: "CUS-[0-9]{6}"
    confidence: 0.95
    context_words: ["customer", "client"]

  - name: PROJECT_CODE
    pattern: "PRJ-[A-Z]{3}-[0-9]{4}"
    confidence: 0.90
"""


@pytest.fixture
def custom_detector():
    settings = Settings(enable_presidio=False, enable_spacy=False, min_confidence_score=0.5)
    return PIIDetector(config=settings, custom_patterns=[CUSTOMER_ID_PATTERN, PROJECT_CODE_PATTERN])


@pytest.fixture
def yaml_config_file(tmp_path):
    """Write YAML config to a temp file and return its path."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(YAML_CONFIG_CONTENT, encoding="utf-8")
    return config_path


class TestCustomRecognizers:
    def test_yaml_loaded_correctly(self, yaml_config_file):
        """YAML config file is parsed correctly into custom_recognizers list."""
        cfg = load_yaml_config(yaml_config_file)
        assert "custom_recognizers" in cfg
        names = [r["name"] for r in cfg["custom_recognizers"]]
        assert "CUSTOMER_ID" in names
        assert "PROJECT_CODE" in names

    def test_customer_id_detected(self, custom_detector):
        """CUSTOMER_ID pattern CUS-123456 is detected."""
        entities = custom_detector.detect("Account CUS-123456 is active")
        types = {e.entity_type for e in entities}
        assert "CUSTOMER_ID" in types

    def test_project_code_detected(self, custom_detector):
        """PROJECT_CODE pattern PRJ-ABC-1234 is detected."""
        entities = custom_detector.detect("Project PRJ-ABC-1234 is on track")
        types = {e.entity_type for e in entities}
        assert "PROJECT_CODE" in types

    def test_custom_placeholder_format(self, custom_detector):
        """Custom recognizer placeholder format is <CUSTOMER_ID_1>."""
        redactor = PIIRedactor()
        text = "Customer CUS-999888 is new"
        entities = custom_detector.detect(text)
        result = redactor.redact(text, entities)
        import re
        assert re.search(r"<CUSTOMER_ID_\d+>", result.redacted_text)

    def test_multiple_custom_patterns_same_text(self, custom_detector):
        """Multiple custom patterns detected in the same text."""
        text = "Client CUS-111222 worked on PRJ-XYZ-5678"
        entities = custom_detector.detect(text)
        types = {e.entity_type for e in entities}
        assert "CUSTOMER_ID" in types
        assert "PROJECT_CODE" in types

    def test_custom_recognizer_via_dict(self):
        """Custom recognizer works when supplied directly as a Python dict."""
        patterns = [{"name": "TICKET_ID", "pattern": r"TKT-\d{5}", "confidence": 0.92}]
        detector = RegexDetector(custom_patterns=patterns)
        entities = detector.detect("Ticket TKT-12345 is open")
        types = {e.entity_type for e in entities}
        assert "TICKET_ID" in types

    def test_custom_recognizer_below_threshold_not_returned(self):
        """Custom recognizer with low confidence is filtered by threshold."""
        patterns = [{"name": "LOW_CONF", "pattern": r"LOW-\d{4}", "confidence": 0.20}]
        settings = Settings(
            enable_presidio=False,
            enable_spacy=False,
            min_confidence_score=0.65,
        )
        detector = PIIDetector(config=settings, custom_patterns=patterns)
        entities = detector.detect("Match LOW-1234 here")
        # Should be filtered out since 0.20 < 0.65
        types = {e.entity_type for e in entities}
        assert "LOW_CONF" not in types

    def test_invalid_regex_pattern_skipped(self):
        """Custom recognizer with invalid regex is skipped without crashing."""
        bad_patterns = [
            {"name": "BAD_PATTERN", "pattern": r"[invalid(regex", "confidence": 0.90},
            {"name": "GOOD_PATTERN", "pattern": r"GOOD-\d{4}", "confidence": 0.90},
        ]
        detector = RegexDetector(custom_patterns=bad_patterns)
        # Should not raise; GOOD_PATTERN should still work
        entities = detector.detect("Ref GOOD-1234 here")
        types = {e.entity_type for e in entities}
        assert "GOOD_PATTERN" in types
        assert "BAD_PATTERN" not in types

    def test_custom_recognizer_source_is_custom(self):
        """Custom recognizer entities have source='custom'."""
        patterns = [{"name": "MY_ID", "pattern": r"MY-\d{6}", "confidence": 0.88}]
        detector = RegexDetector(custom_patterns=patterns)
        entities = detector.detect("ID is MY-123456")
        my_id_entities = [e for e in entities if e.entity_type == "MY_ID"]
        assert len(my_id_entities) > 0
        assert all(e.source == "custom" for e in my_id_entities)

    def test_custom_in_conflict_with_builtin(self):
        """Custom pattern at same position as built-in: custom wins (same priority as regex)."""
        from pii_redactor.detection.conflict_resolver import ConflictResolver
        from pii_redactor.models import DetectedEntity

        resolver = ConflictResolver()
        # Custom entity and presidio entity at same span
        custom_e = DetectedEntity("CUSTOMER_ID", 5, 15, 0.90, "custom")
        presidio_e = DetectedEntity("PERSON", 5, 15, 0.95, "presidio")
        result = resolver.resolve([custom_e, presidio_e])
        assert len(result) == 1
        assert result[0].source == "custom"
