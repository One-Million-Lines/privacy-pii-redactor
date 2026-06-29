"""
Regex-based PII detector.

This is the *primary* and most important detector in the pipeline. It is
entirely dependency-free (standard library only) and covers a broad set of
deterministic PII patterns.

Pattern coverage:
    - Email addresses
    - Phone numbers (US, international, various formats)
    - Credit cards (Visa, Mastercard, Amex, 16-digit) with Luhn validation
    - IBAN (ISO 13616)
    - IP addresses (IPv4, IPv6)
    - URLs (HTTP, HTTPS, FTP)
    - Dates of birth (multiple formats)
    - US Social Security Numbers
    - Passport numbers
    - Driver's license numbers
    - ZIP / postal codes (US, UK, CA, DE, FR, IT)
    - Physical addresses (street patterns)
    - Custom patterns loaded from config
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Iterator

from pii_redactor.models import DetectedEntity

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Luhn algorithm
# ──────────────────────────────────────────────────────────────────────────────


def _luhn_valid(number: str) -> bool:
    """
    Validate a numeric string using the Luhn algorithm.

    The Luhn algorithm is the standard check-digit algorithm used by credit
    card numbers, IMEI numbers, etc.

    Args:
        number: String of digits only (spaces/dashes must be stripped beforehand).

    Returns:
        True if the number passes the Luhn check, False otherwise.

    Example::

        >>> _luhn_valid("4111111111111111")   # Visa test number
        True
        >>> _luhn_valid("4111111111111112")
        False
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


# ──────────────────────────────────────────────────────────────────────────────
# Pattern definitions
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class _Pattern:
    """
    Internal representation of a single detection pattern.

    Attributes:
        entity_type: Normalized entity type label (upper-case).
        pattern: Compiled regular expression.
        confidence: Confidence score assigned to matches (0.0–1.0).
        source: Entity source label ("regex" for built-in, "custom" for user patterns).
        validator: Optional callable that performs additional validation
            on the matched string. If it returns False the match is rejected.
    """

    entity_type: str
    pattern: re.Pattern[str]
    confidence: float
    source: str = "regex"
    validator: None | (
        type[None]
    ) = None  # Callable[[str], bool] | None – avoid typing imports at runtime


# fmt: off
_RAW_PATTERNS: list[tuple[str, str, float]] = [
    # ── Email ────────────────────────────────────────────────────────────────
    (
        "EMAIL",
        r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b",
        0.95,
    ),

    # ── US Social Security Number ────────────────────────────────────────────
    # Must NOT start with 000, 666, or 9xx
    (
        "SSN",
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        0.97,
    ),

    # ── Credit cards ─────────────────────────────────────────────────────────
    # Visa: 4xxx, 13 or 16 digits
    (
        "CREDIT_CARD",
        r"\b4[0-9]{3}(?:[ \-]?[0-9]{4}){3}\b",
        0.90,
    ),
    # Mastercard: 51-55 or 2221-2720
    (
        "CREDIT_CARD",
        r"\b(?:5[1-5][0-9]{2}|2(?:2[2-9][1-9]|[3-6][0-9]{2}|7[01][0-9]|720))(?:[ \-]?[0-9]{4}){3}\b",
        0.90,
    ),
    # Amex: 34xx or 37xx, 15 digits
    (
        "CREDIT_CARD",
        r"\b3[47][0-9]{2}(?:[ \-]?[0-9]{6}[ \-]?[0-9]{5})\b",
        0.90,
    ),
    # Generic 16-digit card (fallback, lower confidence)
    (
        "CREDIT_CARD",
        r"\b[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b",
        0.80,
    ),

    # ── IBAN (ISO 13616) ──────────────────────────────────────────────────────
    # Format: 2 country letters + 2 check digits + up to 30 alphanumeric BBAN chars
    # Supports both compact (no spaces) and space-grouped (groups of 4) formats
    (
        "IBAN",
        r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){12,30}\b",
        0.92,
    ),

    # ── IPv4 ─────────────────────────────────────────────────────────────────
    (
        "IP_ADDRESS",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        0.95,
    ),

    # ── IPv6 (full and compressed) ────────────────────────────────────────────
    (
        "IP_ADDRESS",
        r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b"
        r"|\b:(?::[0-9A-Fa-f]{1,4}){1,7}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}\b"
        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}\b"
        r"|\b[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}\b"
        r"|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b"
        r"|\b[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4}\b",
        0.92,
    ),

    # ── URLs ─────────────────────────────────────────────────────────────────
    (
        "URL",
        r"(?i)\b(?:https?|ftp)://(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:/[^\s]*)?",
        0.92,
    ),

    # ── Phone numbers ────────────────────────────────────────────────────────
    # International format: +CC followed by digits, spaces, dashes, dots
    (
        "PHONE_NUMBER",
        r"\+\d{1,3}[ \-\.]?\(?\d{1,4}\)?(?:[ \-\.]\d{1,4}){1,5}",
        0.88,
    ),
    # US: (NXX) NXX-XXXX with optional country code (+1 or 1)
    # Exchange code relaxed to \d{3} to cover common test numbers like 555-123-4567
    (
        "PHONE_NUMBER",
        r"\b(?:1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        0.85,
    ),
    # Bare 10-digit (no separators): 5551234567
    (
        "PHONE_NUMBER",
        r"\b[2-9]\d{9}\b",
        0.70,
    ),

    # ── Dates (date of birth / general dates) ────────────────────────────────
    # ISO 8601: YYYY-MM-DD
    (
        "DATE_OF_BIRTH",
        r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",
        0.90,
    ),
    # DD/MM/YYYY
    (
        "DATE_OF_BIRTH",
        r"\b(?:0[1-9]|[12]\d|3[01])/(?:0[1-9]|1[0-2])/(?:19|20)\d{2}\b",
        0.85,
    ),
    # MM/DD/YYYY
    (
        "DATE_OF_BIRTH",
        r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b",
        0.85,
    ),
    # Month DD, YYYY (spelled out month)
    (
        "DATE_OF_BIRTH",
        r"\b(?:January|February|March|April|May|June|July|August|September|"
        r"October|November|December)\s+\d{1,2},?\s+(?:19|20)\d{2}\b",
        0.88,
    ),

    # ── Passport ─────────────────────────────────────────────────────────────
    (
        "PASSPORT",
        r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        0.70,
    ),

    # ── Driver's license (US patterns) ───────────────────────────────────────
    # Generic alphanumeric 6-9 chars after common prefixes
    (
        "DRIVER_LICENSE",
        r"\b(?:[A-Z]{1,2}[\-]?[0-9]{4,8}|[0-9]{7,8}[A-Z]?)\b",
        0.65,
    ),

    # ── ZIP / Postal codes ────────────────────────────────────────────────────
    # US ZIP (12345 or 12345-6789)
    (
        "ZIP_CODE",
        r"\b\d{5}(?:-\d{4})?\b",
        0.70,
    ),
    # UK postcode (e.g. SW1A 2AA)
    (
        "ZIP_CODE",
        r"\b[A-Z]{1,2}[0-9][0-9A-Z]?\s?[0-9][A-Z]{2}\b",
        0.82,
    ),
    # Canadian: A1A 1A1
    (
        "ZIP_CODE",
        r"\b[A-Z][0-9][A-Z]\s?[0-9][A-Z][0-9]\b",
        0.82,
    ),
    # German PLZ (5 digits) — handled by the US ZIP pattern above

    # ── Physical addresses ────────────────────────────────────────────────────
    # Matches patterns like "123 Main Street" or "456 Oak Ave, City, ST 12345"
    (
        "ADDRESS",
        r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Court|Ct|"
        r"Lane|Ln|Way|Place|Pl|Terrace|Ter|Circle|Cir)\b",
        0.80,
    ),
]
# fmt: on


class RegexDetector:
    """
    Rule-based PII detector using compiled regular expressions.

    This detector runs entirely in the standard library and requires no
    external ML dependencies. It is the default and most reliable component
    in the detection pipeline.

    Patterns are compiled once on construction. Custom patterns can be
    injected via *custom_patterns* to extend detection without subclassing.

    Args:
        custom_patterns: Optional list of custom pattern dicts.
            Each dict must have ``"name"`` (entity type), ``"pattern"``
            (regex string), and optionally ``"confidence"`` (float, default 0.85).

    Example::

        detector = RegexDetector(
            custom_patterns=[{"name": "EMPLOYEE_ID", "pattern": r"EMP\\d{6}"}]
        )
        entities = detector.detect("Employee EMP123456 joined today.")
    """

    def __init__(
        self,
        custom_patterns: list[dict] | None = None,
    ) -> None:
        self._patterns: list[_Pattern] = []
        self._build_patterns(custom_patterns or [])

    # ── Construction ──────────────────────────────────────────────────────────

    def _build_patterns(self, custom_patterns: list[dict]) -> None:
        """
        Compile all built-in and custom patterns into ``_Pattern`` objects.

        Credit card patterns are paired with the Luhn validator. Invalid
        custom regex patterns are logged as warnings and skipped.

        Args:
            custom_patterns: User-supplied pattern dicts (see ``__init__``).
        """
        for entity_type, raw, confidence in _RAW_PATTERNS:
            try:
                compiled = re.compile(raw)
            except re.error as exc:
                logger.warning("Failed to compile built-in pattern for %s: %s", entity_type, exc)
                continue

            validator = _luhn_valid if entity_type == "CREDIT_CARD" else None
            self._patterns.append(
                _Pattern(entity_type=entity_type, pattern=compiled, confidence=confidence, source="regex", validator=validator)
            )

        for cp in custom_patterns:
            name = cp.get("name")
            raw_pattern = cp.get("pattern")
            if not name or not raw_pattern:
                logger.warning("Skipping custom pattern with missing name or pattern: %s", cp)
                continue
            confidence = float(cp.get("confidence", 0.85))
            try:
                compiled = re.compile(raw_pattern)
            except re.error as exc:
                logger.warning(
                    "Skipping custom pattern '%s': invalid regex — %s", name, exc
                )
                continue
            self._patterns.append(
                _Pattern(
                    entity_type=name.upper(),
                    pattern=compiled,
                    confidence=confidence,
                    source="custom",
                    validator=None,
                )
            )
            logger.debug("Loaded custom pattern '%s'", name)

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self, text: str, language: str = "en") -> list[DetectedEntity]:
        """
        Run all patterns against *text* and return detected entities.

        Each match is converted to a :class:`~pii_redactor.models.DetectedEntity`
        with ``source="regex"`` (or ``"custom"`` for user-supplied patterns).
        Credit card matches are additionally validated with the Luhn algorithm
        and discarded on failure.

        Note: this method returns *all* matches including overlapping ones.
        Callers should pass results through
        :class:`~pii_redactor.detection.conflict_resolver.ConflictResolver`
        to obtain a non-overlapping set.

        Args:
            text: Input text to scan.
            language: ISO 639-1 language code (unused in regex detection but
                provided for API consistency with other detectors).

        Returns:
            List of detected entities, potentially overlapping.
        """
        if not text or not text.strip():
            return []

        entities: list[DetectedEntity] = []
        for p in self._patterns:
            for match in p.pattern.finditer(text):
                raw_value = match.group()
                digits_only = re.sub(r"[\s\-]", "", raw_value)

                # Luhn check for credit cards
                if p.validator is not None and not p.validator(digits_only):
                    continue

                entities.append(
                    DetectedEntity(
                        entity_type=p.entity_type,
                        start=match.start(),
                        end=match.end(),
                        confidence=p.confidence,
                        source=p.source,
                    )
                )

        return entities

    def _iter_matches(self, text: str) -> Iterator[DetectedEntity]:
        """Yield entities from all patterns for *text* (internal helper)."""
        yield from self.detect(text)
