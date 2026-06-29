"""
Detection sub-package.

Exposes the primary public interface: :class:`~pii_redactor.detection.detector.PIIDetector`.
Individual detector classes are available for direct use or extension.
"""

from pii_redactor.detection.conflict_resolver import ConflictResolver
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.detection.presidio_detector import PresidioDetector
from pii_redactor.detection.regex_detector import RegexDetector
from pii_redactor.detection.spacy_detector import SpacyDetector

__all__ = [
    "PIIDetector",
    "RegexDetector",
    "PresidioDetector",
    "SpacyDetector",
    "ConflictResolver",
]
