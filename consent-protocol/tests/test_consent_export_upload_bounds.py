# tests/test_consent_export_upload_bounds.py
"""
Proof: api.routes.consent.upload_refreshed_export -> POST /api/consent/export-refresh/upload

Verifies that the encryptedData field on RefreshExportUploadRequest enforces
a max_length of 10,000,000 characters, rejecting payloads that exceed the limit
with a 422 validation error.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes import consent


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(consent.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": "test-uid",
        "token": "fake-token",
        "scope": "vault.owner",
    }
    return app


_VALID_BASE = {
    "userId": "test-uid",
    "consentToken": "tok-abc",
    "encryptedData": "smalldata",
    "encryptedIv": "iv",
    "encryptedTag": "tag",
    "wrappedExportKey": "wek",
    "wrappedKeyIv": "wkiv",
    "wrappedKeyTag": "wktag",
    "senderPublicKey": "spk",
}


class TestRefreshExportUploadBounds:
    """encryptedData on RefreshExportUploadRequest must have a max_length of 10_000_000."""

    def test_oversized_encrypted_data_returns_422(self):
        """
        Posting encryptedData of 11 million characters must be rejected with 422.

        Without max_length the server would accept arbitrarily large ciphertext
        payloads and attempt to store them, consuming database bandwidth and
        memory proportional to input size.
        """
        client = TestClient(_build_app(), raise_server_exceptions=False)
        oversized_payload = {**_VALID_BASE, "encryptedData": "x" * 11_000_000}
        response = client.post(
            "/api/consent/export-refresh/upload",
            json=oversized_payload,
        )
        assert response.status_code == 422, (
            f"Expected 422 for encryptedData > 10MB, got {response.status_code}: {response.text[:200]}"
        )

    def test_valid_encrypted_data_passes_validation(self):
        """
        A small encryptedData value must not be rejected by Pydantic validation.

        The test does not need the endpoint to succeed end-to-end (DB calls
        will fail in the test environment) -- it only checks that the 422 is NOT
        raised by field length validation.
        """
        client = TestClient(_build_app(), raise_server_exceptions=False)
        response = client.post(
            "/api/consent/export-refresh/upload",
            json=_VALID_BASE,
        )
        # Any status other than 422 means the Pydantic model accepted the payload
        assert response.status_code != 422, (
            f"Small encryptedData was incorrectly rejected with 422: {response.text[:200]}"
        )

    def test_empty_encrypted_data_returns_422(self):
        """encryptedData with min_length=1 must reject empty strings."""
        client = TestClient(_build_app(), raise_server_exceptions=False)
        payload = {**_VALID_BASE, "encryptedData": ""}
        response = client.post(
            "/api/consent/export-refresh/upload",
            json=payload,
        )
        assert response.status_code == 422, (
            f"Expected 422 for empty encryptedData, got {response.status_code}"
        )
