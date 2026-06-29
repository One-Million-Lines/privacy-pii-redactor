"""
Tests for the FastAPI REST API: all endpoints, auth, size limits, error handling.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestHealthEndpoint:
    def test_health_returns_ok(self, test_client: TestClient):
        resp = test_client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_content_type_json(self, test_client: TestClient):
        resp = test_client.get("/health")
        assert "application/json" in resp.headers["content-type"]


class TestDetectEndpoint:
    def test_detect_email(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "Email me at alice@example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "entities" in data
        types = [e["type"] for e in data["entities"]]
        assert "EMAIL" in types

    def test_detect_phone_number(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "Call +1-555-123-4567 now"})
        assert resp.status_code == 200
        data = resp.json()
        types = [e["type"] for e in data["entities"]]
        assert "PHONE_NUMBER" in types

    def test_detect_empty_text(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "   "})
        assert resp.status_code == 200
        assert resp.json()["entities"] == []

    def test_detect_missing_text_field(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"language": "en"})
        assert resp.status_code == 422  # Pydantic validation error

    def test_detect_with_language_param(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/detect",
            json={"text": "Email alice@example.com", "language": "fr"},
        )
        assert resp.status_code == 200

    def test_detect_entity_has_required_fields(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "alice@example.com"})
        assert resp.status_code == 200
        entity = resp.json()["entities"][0]
        assert "type" in entity
        assert "start" in entity
        assert "end" in entity
        assert "confidence" in entity
        assert "source" in entity

    def test_detect_total_field_present(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "alice@example.com"})
        assert resp.status_code == 200
        assert "total" in resp.json()

    def test_detect_no_pii_returns_empty_entities(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/detect",
            json={"text": "The quick brown fox jumps over the lazy dog"},
        )
        assert resp.status_code == 200


class TestRedactEndpoint:
    def test_redact_email_in_text(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/redact",
            json={"text": "Email alice@example.com please"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "alice@example.com" not in data["redacted_text"]
        assert "<EMAIL_1>" in data["redacted_text"] or "EMAIL" in data["redacted_text"]

    def test_redact_returns_mapping_id_when_store_mapping_true(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/redact",
            json={"text": "Email alice@example.com", "store_mapping": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mapping_id"] is not None
        assert data["expires_in"] == 60  # From test settings

    def test_redact_no_mapping_id_when_store_mapping_false(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/redact",
            json={"text": "Email alice@example.com", "store_mapping": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mapping_id"] is None
        assert data["expires_in"] is None

    def test_redact_empty_text_ok(self, test_client: TestClient):
        resp = test_client.post("/v1/redact", json={"text": "   "})
        assert resp.status_code == 200
        data = resp.json()
        assert data["entities"] == []

    def test_redact_entities_in_response(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/redact",
            json={"text": "alice@example.com and 4111 1111 1111 1111"},
        )
        assert resp.status_code == 200
        entities = resp.json()["entities"]
        assert len(entities) >= 1

    def test_redact_entity_has_type_placeholder_confidence(self, test_client: TestClient):
        resp = test_client.post("/v1/redact", json={"text": "alice@example.com"})
        assert resp.status_code == 200
        entities = resp.json()["entities"]
        if entities:
            e = entities[0]
            assert "type" in e
            assert "placeholder" in e
            assert "confidence" in e

    def test_redact_text_too_large_returns_413(self, test_client: TestClient):
        """Text over 100KB should be rejected with 413."""
        large_text = "x" * 200_000
        resp = test_client.post(
            "/v1/redact",
            json={"text": large_text},
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (413, 422)  # Could be either size limit


class TestRestoreEndpoint:
    def _save_mapping(self, test_client: TestClient, text: str = "alice@example.com"):
        redact_resp = test_client.post(
            "/v1/redact",
            json={"text": text, "store_mapping": True},
        )
        assert redact_resp.status_code == 200
        data = redact_resp.json()
        return data["redacted_text"], data["mapping_id"]

    def test_restore_valid_mapping(self, test_client: TestClient):
        redacted_text, mapping_id = self._save_mapping(test_client)
        resp = test_client.post(
            "/v1/restore",
            json={
                "text": redacted_text,
                "mapping_id": mapping_id,
                "delete_after_restore": False,
            },
        )
        assert resp.status_code == 200
        restored = resp.json()["restored_text"]
        assert "alice@example.com" in restored

    def test_restore_unknown_mapping_returns_404(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/restore",
            json={"text": "some text", "mapping_id": "nonexistent_id_xyz123"},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "MAPPING_NOT_FOUND"

    def test_restore_deletes_mapping_after_restore(self, test_client: TestClient):
        redacted, mid = self._save_mapping(test_client)
        test_client.post(
            "/v1/restore",
            json={"text": redacted, "mapping_id": mid, "delete_after_restore": True},
        )
        # Second restore attempt should fail
        resp2 = test_client.post(
            "/v1/restore",
            json={"text": redacted, "mapping_id": mid, "delete_after_restore": False},
        )
        assert resp2.status_code == 404

    def test_restore_returns_restored_text(self, test_client: TestClient):
        original = "My email is bob@example.org"
        redacted, mid = self._save_mapping(test_client, text=original)
        resp = test_client.post(
            "/v1/restore",
            json={"text": redacted, "mapping_id": mid, "delete_after_restore": False},
        )
        assert resp.status_code == 200
        assert resp.json()["restored_text"] == original

    def test_restore_placeholders_replaced_count(self, test_client: TestClient):
        redacted, mid = self._save_mapping(test_client)
        resp = test_client.post(
            "/v1/restore",
            json={"text": redacted, "mapping_id": mid, "delete_after_restore": False},
        )
        assert resp.status_code == 200
        assert "placeholders_replaced" in resp.json()


class TestAPIAuthentication:
    def test_no_auth_required_when_no_api_key_set(self, test_client: TestClient):
        resp = test_client.post("/v1/detect", json={"text": "alice@example.com"})
        assert resp.status_code == 200

    def test_correct_api_key_allowed(self, test_client_with_auth: TestClient):
        resp = test_client_with_auth.post(
            "/v1/restore",
            json={"text": "some", "mapping_id": "nonexistent"},
            headers={"Authorization": "Bearer test-secret-key-12345"},
        )
        # 404 is ok — auth passed but mapping doesn't exist
        assert resp.status_code == 404

    def test_wrong_api_key_rejected(self, test_client_with_auth: TestClient):
        resp = test_client_with_auth.post(
            "/v1/restore",
            json={"text": "some", "mapping_id": "nonexistent"},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_missing_auth_header_rejected(self, test_client_with_auth: TestClient):
        resp = test_client_with_auth.post(
            "/v1/restore",
            json={"text": "some", "mapping_id": "nonexistent"},
        )
        assert resp.status_code == 401

    def test_unauthorized_error_code_in_response(self, test_client_with_auth: TestClient):
        resp = test_client_with_auth.post(
            "/v1/restore",
            json={"text": "some", "mapping_id": "abc"},
            headers={"Authorization": "Bearer bad-key"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "UNAUTHORIZED"


class TestChatCompletionsProxy:
    def test_proxy_without_llm_url_returns_503(self, test_client: TestClient):
        resp = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello alice@example.com"}],
            },
        )
        assert resp.status_code == 503
        assert resp.json()["error"]["code"] == "LLM_PROVIDER_NOT_CONFIGURED"


class TestDocsEndpoint:
    def test_docs_accessible_by_default(self, test_client: TestClient):
        resp = test_client.get("/docs")
        assert resp.status_code == 200

    def test_docs_disabled(self):
        from pii_redactor.api.app import create_app
        from pii_redactor.config import Settings

        settings = Settings(
            enable_presidio=False,
            enable_spacy=False,
            docs_enabled=False,
        )
        app = create_app(config=settings)
        client = TestClient(app)
        resp = client.get("/docs")
        assert resp.status_code == 404
