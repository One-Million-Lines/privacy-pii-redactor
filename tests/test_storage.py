"""
Tests for InMemoryStore and RedisStore (fakeredis).

Covers save/get/delete, TTL expiry, UUID ID generation, and error cases.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pii_redactor.storage.base import StorageError

# ── InMemoryStore ─────────────────────────────────────────────────────────────


class TestInMemoryStore:
    def test_save_returns_string_id(self, memory_store):
        mid = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        assert isinstance(mid, str)
        assert len(mid) == 32  # UUID4 hex

    def test_save_returns_unique_ids(self, memory_store):
        id1 = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        id2 = memory_store.save({"<EMAIL_2>": "c@d.com"}, ttl=900)
        assert id1 != id2

    def test_get_returns_correct_mapping(self, memory_store):
        mapping = {"<EMAIL_1>": "alice@example.com", "<PERSON_1>": "Alice"}
        mid = memory_store.save(mapping, ttl=900)
        retrieved = memory_store.get(mid)
        assert retrieved == mapping

    def test_get_unknown_id_returns_none(self, memory_store):
        result = memory_store.get("nonexistent_id_xyz")
        assert result is None

    def test_delete_removes_mapping(self, memory_store):
        mid = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        memory_store.delete(mid)
        assert memory_store.get(mid) is None

    def test_delete_nonexistent_is_noop(self, memory_store):
        """Deleting a non-existent ID should not raise."""
        memory_store.delete("nonexistent_id_xyz")  # No exception

    def test_mapping_expires_after_ttl(self, memory_store):
        """Mapping should expire after TTL elapses."""
        mid = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=1)
        # Manipulate the internal store to simulate expiry
        with memory_store._lock:
            mapping_dict, _ = memory_store._store[mid]
            # Set expires_at to 0 (already expired)
            memory_store._store[mid] = (mapping_dict, 0.0)
        assert memory_store.get(mid) is None

    def test_get_returns_copy_not_reference(self, memory_store):
        """Modifying the returned mapping should not affect the stored one."""
        mid = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        retrieved = memory_store.get(mid)
        retrieved["<TAMPERED>"] = "tampered"
        # Re-retrieve — should not contain the tampered key
        clean = memory_store.get(mid)
        assert "<TAMPERED>" not in clean

    def test_size_tracks_entries(self, memory_store):
        assert memory_store.size == 0
        memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        assert memory_store.size == 1
        memory_store.save({"<EMAIL_2>": "b@c.com"}, ttl=900)
        assert memory_store.size == 2

    def test_purge_expired_removes_old_entries(self, memory_store):
        mid = memory_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        # Force expiry
        with memory_store._lock:
            mapping_dict, _ = memory_store._store[mid]
            memory_store._store[mid] = (mapping_dict, 0.0)
        purged = memory_store.purge_expired()
        assert purged == 1
        assert memory_store.size == 0

    def test_large_mapping_stored_correctly(self, memory_store):
        mapping = {f"<EMAIL_{i}>": f"user{i}@example.com" for i in range(1, 101)}
        mid = memory_store.save(mapping, ttl=900)
        retrieved = memory_store.get(mid)
        assert len(retrieved) == 100

    def test_thread_safety_concurrent_saves(self, memory_store):
        """Multiple threads saving concurrently should not corrupt state."""
        import threading

        ids = []
        lock = threading.Lock()

        def save_mapping(i):
            mid = memory_store.save({f"<EMAIL_{i}>": f"user{i}@example.com"}, ttl=900)
            with lock:
                ids.append(mid)

        threads = [threading.Thread(target=save_mapping, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(ids)) == 20  # All IDs must be unique

    def test_save_with_empty_mapping(self, memory_store):
        mid = memory_store.save({}, ttl=900)
        retrieved = memory_store.get(mid)
        assert retrieved == {}


# ── RedisStore with fakeredis ─────────────────────────────────────────────────


class TestRedisStore:
    def test_save_returns_string_id(self, fake_redis_store):
        mid = fake_redis_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        assert isinstance(mid, str)
        assert len(mid) == 32

    def test_save_returns_unique_ids(self, fake_redis_store):
        id1 = fake_redis_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        id2 = fake_redis_store.save({"<EMAIL_2>": "c@d.com"}, ttl=900)
        assert id1 != id2

    def test_get_returns_correct_mapping(self, fake_redis_store):
        mapping = {"<EMAIL_1>": "alice@example.com", "<PERSON_1>": "Alice"}
        mid = fake_redis_store.save(mapping, ttl=900)
        retrieved = fake_redis_store.get(mid)
        assert retrieved == mapping

    def test_get_unknown_id_returns_none(self, fake_redis_store):
        result = fake_redis_store.get("nonexistent_id_xyz")
        assert result is None

    def test_delete_removes_mapping(self, fake_redis_store):
        mid = fake_redis_store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)
        fake_redis_store.delete(mid)
        assert fake_redis_store.get(mid) is None

    def test_delete_nonexistent_is_noop(self, fake_redis_store):
        fake_redis_store.delete("nonexistent_id_xyz")  # No exception

    def test_large_mapping_stored_correctly(self, fake_redis_store):
        mapping = {f"<EMAIL_{i}>": f"user{i}@example.com" for i in range(1, 51)}
        mid = fake_redis_store.save(mapping, ttl=900)
        retrieved = fake_redis_store.get(mid)
        assert len(retrieved) == 50

    def test_mapping_serialised_and_deserialised(self, fake_redis_store):
        mapping = {
            "<EMAIL_1>": "alice@example.com",
            "<CREDIT_CARD_1>": "4111 1111 1111 1111",
            "<PHONE_NUMBER_1>": "+1-555-123-4567",
        }
        mid = fake_redis_store.save(mapping, ttl=900)
        retrieved = fake_redis_store.get(mid)
        assert retrieved == mapping

    def test_redis_connection_error_raises_storage_error(self):
        """When Redis is not available, StorageError should be raised."""
        from pii_redactor.storage.redis import RedisStore

        bad_client = MagicMock()
        bad_client.set.side_effect = Exception("Redis connection refused")
        store = RedisStore(client=bad_client)
        with pytest.raises(StorageError):
            store.save({"<EMAIL_1>": "a@b.com"}, ttl=900)

    def test_redis_get_error_raises_storage_error(self):
        from pii_redactor.storage.redis import RedisStore

        bad_client = MagicMock()
        bad_client.get.side_effect = Exception("Redis connection refused")
        store = RedisStore(client=bad_client)
        with pytest.raises(StorageError):
            store.get("some_id")

    def test_redis_delete_error_raises_storage_error(self):
        from pii_redactor.storage.redis import RedisStore

        bad_client = MagicMock()
        bad_client.delete.side_effect = Exception("Redis connection refused")
        store = RedisStore(client=bad_client)
        with pytest.raises(StorageError):
            store.delete("some_id")
