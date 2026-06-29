"""
Conflict resolver for overlapping PII detections.

When multiple detectors run on the same text they frequently produce
overlapping (or even identical) entity spans. This module implements a greedy
non-overlapping selection algorithm that produces a clean, non-conflicting
result set.

Priority rules (highest → lowest):
    1. Source type priority: ``regex`` / ``custom`` > ``presidio`` > ``spacy``
    2. Highest confidence score
    3. Largest span (end - start)
    4. Stable / deterministic tie-break (earlier start position)
"""

from __future__ import annotations

import logging
from typing import Final

from pii_redactor.models import DetectedEntity

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Source priority mapping (lower number = higher priority)
# ──────────────────────────────────────────────────────────────────────────────

_SOURCE_PRIORITY: Final[dict[str, int]] = {
    "regex": 0,
    "custom": 0,  # treat custom as equally deterministic as regex
    "presidio": 1,
    "spacy": 2,
}


def _sort_key(entity: DetectedEntity) -> tuple[int, float, int, int]:
    """
    Sort key for candidate entity ordering.

    Entities are ranked by:
        1. Source priority (ascending, so 0 = regex comes first)
        2. Confidence (descending, so negated)
        3. Span length (descending, so negated)
        4. Start position (ascending — stable tie-break)

    Args:
        entity: Entity to compute sort key for.

    Returns:
        Tuple suitable for Python's built-in sort.
    """
    priority = _SOURCE_PRIORITY.get(entity.source, 99)
    return (
        priority,
        -entity.confidence,
        -(entity.end - entity.start),
        entity.start,
    )


class ConflictResolver:
    """
    Resolves overlapping entity detections using a greedy selection algorithm.

    The resolver accepts a list of (potentially overlapping) entities and
    returns a subset where no two entities share any character position.

    Algorithm:
        1. Sort entities by ``_sort_key`` (source priority, then confidence,
           then span length, then start position).
        2. Greedily select each entity if its character range does not overlap
           with any already-selected entity.

    This produces a *stable* output: the same input always produces the same
    output regardless of evaluation order.

    Example::

        resolver = ConflictResolver()
        clean = resolver.resolve(raw_entities)
    """

    def resolve(self, entities: list[DetectedEntity]) -> list[DetectedEntity]:
        """
        Return a non-overlapping subset of *entities*.

        Entities with higher priority (regex > presidio > spacy), higher
        confidence, and larger spans are preferred when resolving conflicts.

        Args:
            entities: Possibly overlapping list of detected entities.

        Returns:
            Sorted, non-overlapping list of selected entities (sorted by
            ``start`` position for downstream consumers).
        """
        if not entities:
            return []

        # Sort candidates so the best entities come first
        candidates = sorted(entities, key=_sort_key)

        selected: list[DetectedEntity] = []
        occupied_ranges: list[tuple[int, int]] = []  # list of (start, end) for selected

        for candidate in candidates:
            if self._overlaps_any(candidate, occupied_ranges):
                logger.debug(
                    "Dropping %s [%d:%d] (conflicts with already-selected entity)",
                    candidate.entity_type,
                    candidate.start,
                    candidate.end,
                )
                continue
            selected.append(candidate)
            occupied_ranges.append((candidate.start, candidate.end))

        # Return in document order (sorted by start position)
        selected.sort(key=lambda e: e.start)
        return selected

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _overlaps_any(
        candidate: DetectedEntity,
        occupied: list[tuple[int, int]],
    ) -> bool:
        """
        Check whether *candidate* overlaps with any range in *occupied*.

        Two ranges overlap when they share at least one character position.
        Adjacent ranges (where end == start) do *not* overlap.

        Args:
            candidate: Entity to check.
            occupied: List of ``(start, end)`` tuples for already-selected entities.

        Returns:
            True if the candidate overlaps with any occupied range.
        """
        cs, ce = candidate.start, candidate.end
        return any(cs < end and start < ce for start, end in occupied)
