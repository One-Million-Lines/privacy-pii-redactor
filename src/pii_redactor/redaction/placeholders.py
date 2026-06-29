"""
Placeholder manager for PII redaction.

Manages the naming and tracking of replacement placeholders within a single
redaction operation. Ensures:

* Each unique original value maps to exactly one placeholder (deduplication).
* Placeholders are sequentially numbered per entity type: ``<EMAIL_1>``,
  ``<EMAIL_2>``, etc.
* The reverse mapping (placeholder → original value) is maintained so that
  :class:`~pii_redactor.redaction.restorer.PIIRestorer` can reconstruct the
  original text.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Placeholder format used throughout the system: <ENTITY_TYPE_N>
_PLACEHOLDER_TEMPLATE = "<{entity_type}_{n}>"


class PlaceholderManager:
    """
    Per-request placeholder allocation and tracking.

    This class is **not** thread-safe by design — it is meant to be
    instantiated fresh for each redaction operation (which is single-threaded).

    Attributes:
        _counters: Dict mapping entity type to the *next* available counter.
        _value_to_placeholder: Deduplication map (original value → placeholder).
        _placeholder_to_value: Reverse mapping used to produce the final mapping
            dict.

    Example::

        mgr = PlaceholderManager()
        ph1 = mgr.get_placeholder("EMAIL", "a@example.com")   # → "<EMAIL_1>"
        ph2 = mgr.get_placeholder("EMAIL", "b@example.com")   # → "<EMAIL_2>"
        ph3 = mgr.get_placeholder("EMAIL", "a@example.com")   # → "<EMAIL_1>" (dedup)
        mapping = mgr.mapping  # {"<EMAIL_1>": "a@example.com", ...}
    """

    def __init__(self) -> None:
        # Counter per entity type, starting at 1
        self._counters: dict[str, int] = {}
        # original value → assigned placeholder
        self._value_to_placeholder: dict[str, str] = {}
        # placeholder → original value (final output mapping)
        self._placeholder_to_value: dict[str, str] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def get_placeholder(self, entity_type: str, original_value: str) -> str:
        """
        Return the placeholder string for *original_value*.

        If *original_value* has been seen before (for any entity type), the
        same placeholder is returned. Otherwise, a new placeholder is allocated
        using the next available counter for *entity_type*.

        Args:
            entity_type: Normalized entity type label (e.g., ``"EMAIL"``).
                Will be upper-cased.
            original_value: The raw PII value extracted from the text.

        Returns:
            Placeholder string such as ``"<EMAIL_1>"``.
        """
        # Deduplication: same original value always gets same placeholder
        if original_value in self._value_to_placeholder:
            return self._value_to_placeholder[original_value]

        entity_type_upper = entity_type.upper()

        # Allocate next counter for this entity type
        n = self._counters.get(entity_type_upper, 0) + 1
        self._counters[entity_type_upper] = n

        placeholder = _PLACEHOLDER_TEMPLATE.format(entity_type=entity_type_upper, n=n)

        # Store both directions
        self._value_to_placeholder[original_value] = placeholder
        self._placeholder_to_value[placeholder] = original_value

        logger.debug(
            "Assigned placeholder %s (entity_type=%s, value_len=%d)",
            placeholder,
            entity_type_upper,
            len(original_value),
        )
        return placeholder

    @property
    def mapping(self) -> dict[str, str]:
        """
        Return the complete placeholder → original value mapping.

        This is a *copy* of the internal mapping, safe to hand off to callers.

        Returns:
            Dict such as ``{"<EMAIL_1>": "john@example.com", ...}``.
        """
        return dict(self._placeholder_to_value)

    def reset(self) -> None:
        """
        Clear all state, resetting counters and mappings.

        Useful when reusing a :class:`PlaceholderManager` instance across
        multiple redaction operations (not the typical use case).
        """
        self._counters.clear()
        self._value_to_placeholder.clear()
        self._placeholder_to_value.clear()
