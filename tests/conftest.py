"""
Shared pytest fixtures and configuration for the test suite.

All fixtures use regex-only detection by default (enable_presidio=False,
enable_spacy=False) to keep tests fast and free of heavy ML dependencies.

Tests that specifically require Presidio or spaCy should be marked with
``@pytest.mark.presidio`` or ``@pytest.mark.spacy`` respectively and will
be skipped when those dependencies are not installed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pii_redactor import PrivacyRedactor
from pii_redactor.config import Settings
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.redaction.redactor import PIIRedactor
from pii_redactor.redaction.restorer import PIIRestorer
from pii_redactor.storage.memory import InMemoryStore

# ── Pytest markers ────────────────────────────────────────────────────────────


def pytest_configure(config):
    """Register custom markers to avoid warnings."""
    config.addinivalue_line("markers", "presidio: tests that require presidio-analyzer")
    config.addinivalue_line("markers", "spacy: tests that require spacy + en_core_web_sm")
    config.addinivalue_line("markers", "redis: tests that require a running Redis instance")
    config.addinivalue_line("markers", "slow: tests that are slow (ML model loading)")


# ── Settings fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def settings() -> Settings:
    """
    Test settings with ML detectors disabled for speed.

    Uses InMemoryStore, low confidence threshold, and regex-only detection.
    """
    return Settings(
        enable_presidio=False,
        enable_spacy=False,
        enable_regex=True,
        min_confidence_score=0.5,
        mapping_ttl_seconds=60,
        api_key=None,
        docs_enabled=True,
    )


@pytest.fixture
def settings_with_auth() -> Settings:
    """Settings with API key authentication enabled."""
    return Settings(
        enable_presidio=False,
        enable_spacy=False,
        enable_regex=True,
        min_confidence_score=0.5,
        api_key="test-secret-key-12345",
    )


# ── Core component fixtures ───────────────────────────────────────────────────


@pytest.fixture
def detector(settings: Settings) -> PIIDetector:
    """Regex-only PIIDetector for tests."""
    return PIIDetector(config=settings)


@pytest.fixture
def redactor() -> PIIRedactor:
    """Stateless PIIRedactor."""
    return PIIRedactor()


@pytest.fixture
def restorer() -> PIIRestorer:
    """Stateless PIIRestorer."""
    return PIIRestorer()


@pytest.fixture
def privacy_redactor(settings: Settings) -> PrivacyRedactor:
    """High-level PrivacyRedactor with regex-only detection."""
    store = InMemoryStore()
    return PrivacyRedactor(config=settings, store=store)


# ── Storage fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def memory_store() -> InMemoryStore:
    """Fresh InMemoryStore for each test."""
    return InMemoryStore()


@pytest.fixture
def fake_redis_store():
    """
    RedisStore backed by fakeredis (no real Redis required).

    Skips automatically if fakeredis is not installed.
    """
    try:
        import fakeredis  # type: ignore[import]
        from pii_redactor.storage.redis import RedisStore

        server = fakeredis.FakeServer()
        client = fakeredis.FakeRedis(server=server, decode_responses=True)
        return RedisStore(client=client)
    except ImportError:
        pytest.skip("fakeredis not installed")


# ── API test client fixture ───────────────────────────────────────────────────


@pytest.fixture
def test_client(settings: Settings) -> TestClient:
    """
    FastAPI TestClient with dependency overrides for test isolation.

    Overrides:
        - get_settings → test settings (regex-only, no auth)
        - get_store → fresh InMemoryStore
        - get_detector → fresh PIIDetector (regex-only)
    """
    from pii_redactor.api.app import create_app
    from pii_redactor.api.dependencies import (
        get_detector,
        get_redactor,
        get_restorer,
        get_settings,
        get_store,
    )

    app = create_app(config=settings)

    # Use fresh store per test to avoid state leakage
    store = InMemoryStore()
    det = PIIDetector(config=settings)

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_detector] = lambda: det
    app.dependency_overrides[get_redactor] = lambda: PIIRedactor()
    app.dependency_overrides[get_restorer] = lambda: PIIRestorer()

    return TestClient(app)


@pytest.fixture
def test_client_with_auth(settings_with_auth: Settings) -> TestClient:
    """TestClient with API key auth enabled."""
    from pii_redactor.api.app import create_app
    from pii_redactor.api.dependencies import (
        get_detector,
        get_redactor,
        get_restorer,
        get_settings,
        get_store,
    )

    app = create_app(config=settings_with_auth)

    store = InMemoryStore()
    det = PIIDetector(config=settings_with_auth)

    app.dependency_overrides[get_settings] = lambda: settings_with_auth
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_detector] = lambda: det
    app.dependency_overrides[get_redactor] = lambda: PIIRedactor()
    app.dependency_overrides[get_restorer] = lambda: PIIRestorer()

    return TestClient(app)
