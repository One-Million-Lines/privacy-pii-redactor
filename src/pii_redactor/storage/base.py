"""
Abstract base class for PII mapping stores.

All storage backends must implement the :class:`MappingStore` ABC to guarantee
a consistent interface for saving, retrieving, and deleting placeholder
mappings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class StorageError(Exception):
    """
    Raised when a storage backend encounters an unrecoverable error.

    Callers should catch this exception rather than backend-specific errors
    (e.g., ``redis.ConnectionError``) to stay decoupled from the storage
    implementation.
    """


class MappingStore(ABC):
    """
    Abstract interface for PII placeholder mapping persistence.

    A mapping is a ``dict[str, str]`` keyed by placeholder (e.g.
    ``"<EMAIL_1>"``) with original PII values as values.  Each mapping is
    stored under a unique opaque identifier returned by :meth:`save`.

    Implementations must handle TTL-based expiry: a mapping that has passed
    its TTL must not be returned by :meth:`get`.

    Concrete implementations:
        - :class:`~pii_redactor.storage.memory.InMemoryStore`
        - :class:`~pii_redactor.storage.redis.RedisStore`
    """

    @abstractmethod
    def save(self, mapping: dict[str, str], ttl: int) -> str:
        """
        Persist *mapping* and return its unique identifier.

        Args:
            mapping: Dict mapping placeholder strings to original PII values.
            ttl: Time-to-live in seconds. After this duration the mapping
                must be considered expired and :meth:`get` must return ``None``.

        Returns:
            A UUID-like opaque string that can be passed back to :meth:`get`
            or :meth:`delete`.

        Raises:
            StorageError: If the mapping could not be saved.
        """

    @abstractmethod
    def get(self, mapping_id: str) -> dict[str, str] | None:
        """
        Retrieve the mapping associated with *mapping_id*.

        Args:
            mapping_id: Identifier previously returned by :meth:`save`.

        Returns:
            The stored mapping dict, or ``None`` if the ID is unknown or the
            mapping has expired.

        Raises:
            StorageError: If the backend encounters an error during retrieval.
        """

    @abstractmethod
    def delete(self, mapping_id: str) -> None:
        """
        Delete the mapping associated with *mapping_id*.

        A no-op if the mapping does not exist or has already expired.

        Args:
            mapping_id: Identifier previously returned by :meth:`save`.

        Raises:
            StorageError: If the backend encounters an error during deletion.
        """
