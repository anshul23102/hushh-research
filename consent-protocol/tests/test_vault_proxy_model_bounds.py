"""Tests for vault proxy request model userId field bounds (CWE-400).

Seven request models in api/routes/db_proxy.py had unbounded userId fields,
allowing arbitrarily long identifier strings to reach the vault service layer.
Firebase UIDs are at most 128 characters; bounds are set accordingly.

Models fixed:
- VaultCheckRequest:            userId (max_length=128)
- VaultBootstrapStateRequest:   userId (max_length=128)
- VaultPreStateUpdateRequest:   userId (max_length=128)
- VaultGetRequest:              userId (max_length=128)
- VaultSetupStateRequest:       userId (max_length=128)
- VaultWrapperUpsertRequest:    userId (max_length=128)
- VaultWrapperDeleteRequest:    userId (max_length=128)
- VaultPrimaryMethodSetRequest: userId (max_length=128)

Canonical attach points:
- api/routes/db_proxy.py: vault endpoint request models
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.routes import db_proxy
from api.routes.db_proxy import (
    VaultBootstrapStateRequest,
    VaultCheckRequest,
    VaultGetRequest,
    VaultPreStateUpdateRequest,
    VaultPrimaryMethodSetRequest,
    VaultWrapperDeleteRequest,
    VaultWrapperUpsertRequest,
)

_VALID_USER_ID = "u" * 128
_OVER_USER_ID = "u" * 129


class TestVaultCheckRequestBounds:
    """VaultCheckRequest.userId max_length=128."""

    def test_userid_at_max_length_accepted(self):
        req = VaultCheckRequest(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            VaultCheckRequest(userId=_OVER_USER_ID)

    def test_userid_empty_rejected(self):
        with pytest.raises(ValidationError):
            VaultCheckRequest(userId="")


class TestVaultBootstrapStateRequestBounds:
    """VaultBootstrapStateRequest.userId max_length=128."""

    def test_userid_at_max_length_accepted(self):
        req = VaultBootstrapStateRequest(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            VaultBootstrapStateRequest(userId=_OVER_USER_ID)

    def test_userid_none_accepted(self):
        req = VaultBootstrapStateRequest(userId=None)
        assert req.userId is None


class TestVaultPreStateUpdateRequestBounds:
    """VaultPreStateUpdateRequest.userId max_length=128."""

    def test_userid_at_max_length_accepted(self):
        req = VaultPreStateUpdateRequest(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            VaultPreStateUpdateRequest(userId=_OVER_USER_ID)

    def test_userid_none_accepted(self):
        req = VaultPreStateUpdateRequest(userId=None)
        assert req.userId is None


class TestVaultGetRequestBounds:
    """VaultGetRequest.userId max_length=128."""

    def test_userid_at_max_length_accepted(self):
        req = VaultGetRequest(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            VaultGetRequest(userId=_OVER_USER_ID)

    def test_userid_empty_rejected(self):
        with pytest.raises(ValidationError):
            VaultGetRequest(userId="")


class TestVaultWrapperUpsertRequestBounds:
    """VaultWrapperUpsertRequest.userId max_length=128."""

    def _make(self, **kwargs):
        defaults = {
            "userId": "user-1",
            "vaultKeyHash": "hash",
            "method": "passphrase",
            "encryptedVaultKey": "enc",
            "salt": "sal",
            "iv": "iv_",
        }
        defaults.update(kwargs)
        return VaultWrapperUpsertRequest(**defaults)

    def test_userid_at_max_length_accepted(self):
        req = self._make(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId=_OVER_USER_ID)

    def test_userid_empty_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId="")


class TestVaultWrapperDeleteRequestBounds:
    """VaultWrapperDeleteRequest.userId max_length=128."""

    def _make(self, **kwargs):
        defaults = {
            "userId": "user-1",
            "vaultKeyHash": "hash",
            "method": "passphrase",
        }
        defaults.update(kwargs)
        return VaultWrapperDeleteRequest(**defaults)

    def test_userid_at_max_length_accepted(self):
        req = self._make(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId=_OVER_USER_ID)

    def test_userid_empty_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId="")


class TestVaultPrimaryMethodSetRequestBounds:
    """VaultPrimaryMethodSetRequest.userId max_length=128."""

    def _make(self, **kwargs):
        defaults = {"userId": "user-1", "primaryMethod": "passphrase"}
        defaults.update(kwargs)
        return VaultPrimaryMethodSetRequest(**defaults)

    def test_userid_at_max_length_accepted(self):
        req = self._make(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId=_OVER_USER_ID)

    def test_userid_empty_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId="")


# ---------------------------------------------------------------------------
# Route-level: oversized userId rejected before vault service runs
# ---------------------------------------------------------------------------


def _vault_app() -> FastAPI:
    app = FastAPI()
    app.include_router(db_proxy.router)
    app.dependency_overrides[db_proxy.require_firebase_auth] = lambda: "user-test"
    return app


@pytest.fixture(scope="module")
def vault_client():
    return TestClient(_vault_app(), raise_server_exceptions=False)


def _minimal_setup_payload(**overrides):
    base = {
        "userId": "user-test",
        "vaultKeyHash": "h" * 64,
        "primaryMethod": "passphrase",
        "recoveryEncryptedVaultKey": "enc",
        "recoverySalt": "sal",
        "recoveryIv": "iv_",
        "wrappers": [
            {
                "method": "passphrase",
                "encryptedVaultKey": "enc",
                "salt": "sal",
                "iv": "iv_",
            }
        ],
    }
    base.update(overrides)
    return base


class TestVaultSetupRouteRejectsOversizedUserId:
    """POST /db/vault/setup returns 422 for oversized userId."""

    def test_oversized_user_id_rejected(self, vault_client):
        payload = _minimal_setup_payload(userId="u" * 129)
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code == 422

    def test_valid_user_id_passes_model_validation(self, vault_client):
        payload = _minimal_setup_payload()
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code != 422, (
            "Valid userId must pass Pydantic validation (may fail at service level)"
        )
