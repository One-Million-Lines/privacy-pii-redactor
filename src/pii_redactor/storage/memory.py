"""
In-memory mapping store.

Thread-safe in-process implementation of :class:`MappingStore` using a
Python dict with expiry timestamps.  Suitable for:
    - Single-process deployments
    - Testing and development
    - Environments where Redis is not available

**Security note**: mappings are stored in process memory. They are not
persistent across process restarts and are not visible to other processes.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

from pii_redactor.storage.base import MappingStore

logger = logging.getLogger(__name__)

# Internal storage entry: (mapping_dict, expiry_unix_timestamp)
_Entry = tuple[dict[str, str], float]


class InMemoryStore(MappingStore):
    """
    Thread-safe, in-process PII mapping store.

    Mappings are stored in a plain dict with per-entry expiry timestamps.
    Expired entries are checked lazily on :meth:`get` (no background GC thread).

    Thread safety is provided by a :class:`threading.Lock` that guards all
    mutations. Read-path (``get``) also holds the lock to ensure a consistent
    view of the expiry timestamp.

    Args:
        (none — the store initialises itself)

    Example::

        store = InMemoryStore()
        mapping_id = store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        mapping = store.get(mapping_id)   # {"<EMAIL_1>": "a@b.com"}
        store.delete(mapping_id)
        store.get(mapping_id)             # None
    """

    def __init__(self) -> None:
        self._store: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # ── MappingStore implementation ───────────────────────────────────────────

    def save(self, mapping: dict[str, str], ttl: int) -> str:
        """
        Save *mapping* and return a UUID-based identifier.

        Args:
            mapping: Placeholder-to-original-value dict to persist.
            ttl: Time-to-live in seconds (0 = immediately expired).

        Returns:
            UUID hex string (32 hex chars, no dashes) identifying the stored
            mapping.
        """
        mapping_id = uuid.uuid4().hex
        expires_at = time.monotonic() + ttl  # monotonic clock avoids DST/NTP jumps

        with self._lock:
            self._store[mapping_id] = (dict(mapping), expires_at)

        logger.debug("Saved mapping %s (ttl=%ds, entries=%d)", mapping_id, ttl, len(mapping))
        return mapping_id

    def get(self, mapping_id: str) -> dict[str, str] | None:
        """
        Retrieve a non-expired mapping by its identifier.

        Args:
            mapping_id: ID returned by a previous :meth:`save` call.

        Returns:
            The stored mapping dict, or ``None`` if not found or expired.
        """
        with self._lock:
            entry = self._store.get(mapping_id)

        if entry is None:
            logger.debug("Mapping %s not found", mapping_id)
            return None

        mapping_dict, expires_at = entry
        if time.monotonic() > expires_at:
            # Lazy eviction: remove expired entry on access
            with self._lock:
                self._store.pop(mapping_id, None)
            logger.debug("Mapping %s has expired", mapping_id)
            return None

        return dict(mapping_dict)  # return a copy to prevent external mutation

    def delete(self, mapping_id: str) -> None:
        """
        Delete the mapping for *mapping_id*. No-op if not present.

        Args:
            mapping_id: ID of the mapping to delete.
        """
        with self._lock:
            removed = self._store.pop(mapping_id, None)

        if removed is not None:
            logger.debug("Deleted mapping %s", mapping_id)
        else:
            logger.debug("Delete requested for non-existent mapping %s (no-op)", mapping_id)

    # ── Diagnostic helpers ────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        """Number of currently stored mappings (including expired ones not yet evicted)."""
        with self._lock:
            return len(self._store)

    def purge_expired(self) -> int:
        """
        Remove all expired entries from the store.

        Returns:
            Number of entries purged.
        """
        now = time.monotonic()
        to_delete: list[str] = []

        with self._lock:
            for mid, (_, expires_at) in self._store.items():
                if now > expires_at:
                    to_delete.append(mid)
            for mid in to_delete:
                del self._store[mid]

        if to_delete:
            logger.debug("Purged %d expired mapping(s)", len(to_delete))
        return len(to_delete)
