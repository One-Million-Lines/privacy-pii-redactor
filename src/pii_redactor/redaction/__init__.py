"""
Redaction sub-package.

Exposes the primary public interfaces:
- :class:`~pii_redactor.redaction.redactor.PIIRedactor` — replaces PII with placeholders
- :class:`~pii_redactor.redaction.restorer.PIIRestorer` — restores placeholders to originals
- :class:`~pii_redactor.redaction.placeholders.PlaceholderManager` — manages placeholder naming
"""

from pii_redactor.redaction.placeholders import PlaceholderManager
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer

__all__ = ["PIIRedactor", "PIIRestorer", "PlaceholderManager"]
