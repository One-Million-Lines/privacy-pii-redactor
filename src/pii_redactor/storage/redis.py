"""
Redis-backed mapping store.

Production-grade implementation of :class:`MappingStore` using Redis as the
backing store. Suitable for:
    - Multi-process or multi-instance deployments
    - Horizontal scaling behind a load balancer
    - Environments where mapping persistence across restarts is not desired
      (use Redis without AOF/RDB persistence — see docker-compose.yml)

Mappings are serialised to JSON and stored as Redis strings with a TTL set
via Redis ``EXPIRE``.  Each mapping gets a unique UUID4 hex key.

**Security note**: Redis should not be exposed publicly. Use a private network
or Unix socket, and prefer ``redis://`` with a password or ``rediss://``
(TLS) in production.
"""

from __future__ import annotations

import json
import logging
import uuid

from pii_redactor.storage.base import MappingStore, StorageError

logger = logging.getLogger(__name__)

# Redis key prefix to avoid collisions with other applications on the same instance
_KEY_PREFIX = "pii_mapping:"


def get_redis_client(url: str):
    """
    Create and return a Redis client connected to *url*.

    Args:
        url: Redis connection URL, e.g. ``"redis://localhost:6379/0"`` or
             ``"rediss://user:pass@host:6380/1"`` for TLS.

    Returns:
        A configured ``redis.Redis`` client instance with ``decode_responses=True``.

    Raises:
        ImportError: If ``redis-py`` is not installed.
        StorageError: If the connection could not be established.
    """
    try:
        import redis as redis_lib  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "redis-py is not installed. Install it with: pip install redis"
        ) from exc

    try:
        client = redis_lib.Redis.from_url(url, decode_responses=True)
        # Ping to verify connectivity eagerly
        client.ping()
        logger.debug("Redis client connected to %s", url)
        return client
    except Exception as exc:  # noqa: BLE001
        raise StorageError(f"Failed to connect to Redis at {url}: {exc}") from exc


class RedisStore(MappingStore):
    """
    Redis-backed PII mapping store.

    Each mapping is stored as a JSON string at key ``pii_mapping:<uuid4hex>``.
    The Redis ``EXPIRE`` command enforces the TTL so Redis handles expiry
    natively.

    Args:
        redis_url: Redis connection URL (default: ``"redis://localhost:6379/0"``).
        client: Optional pre-configured Redis client. If provided, *redis_url*
            is ignored. Useful for testing with ``fakeredis``.

    Example::

        store = RedisStore(redis_url="redis://localhost:6379/0")
        mid = store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        store.get(mid)    # {"<EMAIL_1>": "a@b.com"}
        store.delete(mid)
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        client=None,  # type: ignore[type-arg]
    ) -> None:
        self._redis_url = redis_url
        if client is not None:
            self._client = client
        else:
            self._client = self._connect()

    # ── Connection ────────────────────────────────────────────────────────────

    def _connect(self):
        """
        Establish Redis connection.

        Raises:
            StorageError: If the connection fails.
        """
        return get_redis_client(self._redis_url)

    # ── MappingStore implementation ───────────────────────────────────────────

    def save(self, mapping: dict[str, str], ttl: int) -> str:
        """
        Serialise *mapping* to JSON and store it in Redis with a TTL.

        Args:
            mapping: Placeholder-to-original-value dict.
            ttl: Time-to-live in seconds (Redis EXPIRE).

        Returns:
            UUID hex string identifying the stored mapping.

        Raises:
            StorageError: On Redis connection or write failure.
        """
        mapping_id = uuid.uuid4().hex
        key = _KEY_PREFIX + mapping_id

        try:
            serialised = json.dumps(mapping)
            self._client.set(key, serialised, ex=max(ttl, 1))  # ex must be >= 1
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Redis save failed: {exc}") from exc

        logger.debug(
            "Saved mapping %s to Redis (ttl=%ds, entries=%d)",
            mapping_id,
            ttl,
            len(mapping),
        )
        return mapping_id

    def get(self, mapping_id: str) -> dict[str, str] | None:
        """
        Retrieve a mapping from Redis by its identifier.

        Args:
            mapping_id: UUID hex string returned by :meth:`save`.

        Returns:
            Deserialized mapping dict, or ``None`` if the key doesn't exist
            (expired or never stored).

        Raises:
            StorageError: On Redis connection or read failure.
        """
        key = _KEY_PREFIX + mapping_id

        try:
            raw = self._client.get(key)
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Redis get failed: {exc}") from exc

        if raw is None:
            logger.debug("Mapping %s not found in Redis (expired or unknown)", mapping_id)
            return None

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to deserialize mapping %s from Redis: %s", mapping_id, exc)
            return None

    def delete(self, mapping_id: str) -> None:
        """
        Delete a mapping from Redis. No-op if the key does not exist.

        Args:
            mapping_id: UUID hex string returned by :meth:`save`.

        Raises:
            StorageError: On Redis connection or delete failure.
        """
        key = _KEY_PREFIX + mapping_id

        try:
            deleted_count = self._client.delete(key)
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Redis delete failed: {exc}") from exc

        if deleted_count:
            logger.debug("Deleted mapping %s from Redis", mapping_id)
        else:
            logger.debug(
                "Delete requested for non-existent Redis key %s (no-op)", mapping_id
            )
