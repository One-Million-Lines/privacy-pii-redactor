"""
PIIRestorer: replace placeholders back with original PII values.

Takes a mapping of ``<PLACEHOLDER_N> → original_value`` and substitutes
placeholders found in the text with their original values.

Key properties:
    * Unknown placeholders are left unchanged in the output text.
    * Restoration is case-sensitive (placeholder format is fixed).
    * Counts the number of successful replacements.
"""

from __future__ import annotations

import logging
import re

from pii_redactor.models import RestorationResult

logger = logging.getLogger(__name__)

# Regex that matches any placeholder token of the form <ENTITY_TYPE_N>
# where ENTITY_TYPE is upper-case letters/underscores and N is one or more digits.
_PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z_]*_\d+>")


class PIIRestorer:
    """
    Restores redacted text by replacing placeholders with their original values.

    The restorer is *stateless* — every call to :meth:`restore` is independent.
    Unknown placeholders (those not present in the provided mapping) are
    preserved verbatim in the output.

    Example::

        restorer = PIIRestorer()
        result = restorer.restore(
            text="Contact <EMAIL_1> for details",
            mapping={"<EMAIL_1>": "john@example.com"},
        )
        # result.restored_text == "Contact john@example.com for details"
        # result.placeholders_replaced == 1
    """

    def restore(
        self,
        text: str,
        mapping: dict[str, str],
    ) -> RestorationResult:
        """
        Replace all known placeholders in *text* with their original values.

        Scans *text* for tokens matching ``<TYPE_N>`` and replaces each one
        that exists in *mapping*. Tokens not found in *mapping* are left as-is.

        Args:
            text: Redacted text containing placeholder tokens.
            mapping: Dict mapping placeholder strings to original PII values.
                Typically produced by :class:`~pii_redactor.redaction.redactor.PIIRedactor`.

        Returns:
            :class:`~pii_redactor.models.RestorationResult` containing:
            - ``restored_text``: Text with known placeholders replaced.
            - ``placeholders_replaced``: Count of successful replacements.
        """
        if not text:
            return RestorationResult(restored_text=text, placeholders_replaced=0)

        if not mapping:
            return RestorationResult(restored_text=text, placeholders_replaced=0)

        replaced_count = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal replaced_count
            placeholder = match.group(0)
            if placeholder in mapping:
                replaced_count += 1
                logger.debug("Restoring placeholder %s", placeholder)
                return mapping[placeholder]
            # Unknown placeholder: leave unchanged
            logger.debug("Placeholder %s not found in mapping — leaving unchanged", placeholder)
            return placeholder

        restored = _PLACEHOLDER_RE.sub(_replace, text)

        logger.debug(
            "Restoration complete: %d placeholder(s) replaced out of %d in mapping",
            replaced_count,
            len(mapping),
        )

        return RestorationResult(
            restored_text=restored,
            placeholders_replaced=replaced_count,
        )
