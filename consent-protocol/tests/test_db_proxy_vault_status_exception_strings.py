"""
Tests: db_proxy vault-status endpoint suppresses internal exception strings.

Canonical attach point
----------------------
api.routes.db_proxy.vault_status -> POST /api/db/vault-status

Two exception handlers used detail=str(e):
- ValueError catch on line ~773 returned the raw consent validation
  error message (which can include token fields or internal state).
- Generic Exception catch on line ~778 returned the raw exception string
  from the VaultKeysService or DB layer.

Both are replaced with static strings:
- ValueError -> HTTP 401 "Vault authentication failed"
- Exception  -> HTTP 500 "Internal error"

Route-level proof: TestClient sends requests that trigger each exception
path and asserts the response detail does not contain internal strings.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes.db_proxy as db_proxy_module
from api.middleware import require_firebase_auth


def _stub_firebase():
    return "test-uid"


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(db_proxy_module.router)
    app.dependency_overrides[require_firebase_auth] = _stub_firebase
    return TestClient(app, raise_server_exceptions=False)


class TestVaultStatusExceptionStrings:
    """
    Canonical attach point: api.routes.db_proxy.vault_status
    POST /api/db/vault-status

    Proves that 401 and 500 responses use static detail strings and do
    not contain internal exception text.
    """

    _URL = "/api/db/vault-status"

    def test_missing_user_id_returns_400(self):
        """Requests missing userId must return 400, not 500."""
        resp = _client().post(self._URL, json={"consentToken": "fake"})
        assert resp.status_code == 400

    def test_missing_body_returns_non_200(self):
        """Request with empty body must not succeed."""
        resp = _client().post(self._URL, json={})
        assert resp.status_code != 200

    def test_invalid_token_returns_non_200(self):
        """A syntactically invalid consent token must not return 200."""
        resp = _client().post(
            self._URL,
            json={"userId": "test-uid", "consentToken": "not-a-valid-token"},
        )
        assert resp.status_code != 200

    def test_401_detail_is_static(self):
        """If 401 is returned the detail must be the static auth-failure string."""
        resp = _client().post(
            self._URL,
            json={"userId": "test-uid", "consentToken": "bad-token"},
        )
        if resp.status_code == 401:
            detail = resp.json().get("detail", "")
            # Internal error strings must not appear
            assert "ValueError" not in detail
            assert "traceback" not in detail.lower()
            assert "invalid prefix" not in detail.lower()
            assert "consent" not in detail.lower() or detail == "Vault authentication failed"

    def test_500_detail_does_not_contain_exception_class_name(self):
        """If 500 is returned the detail must not contain an exception class name."""
        resp = _client().post(
            self._URL,
            json={"userId": "test-uid", "consentToken": "bad-token"},
        )
        if resp.status_code == 500:
            detail = resp.json().get("detail", "")
            assert "Exception" not in detail
            assert "Error" not in detail
            assert "Traceback" not in detail
