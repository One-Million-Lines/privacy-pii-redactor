"""
Storage sub-package.

Provides persistence backends for PII placeholder mappings.
Mappings need to survive a redaction → LLM round-trip before being used for
restoration.

Available backends:
    - :class:`~pii_redactor.storage.memory.InMemoryStore` — in-process dict,
      suitable for single-instance deployments and testing.
    - :class:`~pii_redactor.storage.redis.RedisStore` — Redis-backed, suitable
      for multi-process or distributed deployments.
"""

from pii_redactor.storage.base import MappingStore
from pii_redactor.storage.memory import InMemoryStore
from pii_redactor.storage.redis import RedisStore

__all__ = ["MappingStore", "InMemoryStore", "RedisStore"]
