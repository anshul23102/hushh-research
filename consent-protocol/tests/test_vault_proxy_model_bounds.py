"""Tests for vault proxy request model field bounds (CWE-400).

Seven Pydantic request models in api/routes/db_proxy.py lacked max_length
constraints on their identifier and method string fields, allowing
arbitrarily large payloads to reach the vault key storage layer:

Models fixed:
- VaultCheckRequest:          userId (max_length=128)
- VaultBootstrapStateRequest: userId (max_length=128)
- VaultPreStateUpdateRequest: userId (max_length=128)
- VaultGetRequest:            userId (max_length=128)
- VaultWrapperData:           method (max_length=32), wrapperId (max_length=128)
- VaultStateData:             vaultKeyHash (max_length=256), primaryMethod (max_length=32),
                              primaryWrapperId (max_length=128)
- VaultSetupStateRequest:     userId, vaultKeyHash, primaryMethod, primaryWrapperId
- VaultWrapperUpsertRequest:  userId, vaultKeyHash, method, wrapperId
- VaultWrapperDeleteRequest:  userId, vaultKeyHash, method, wrapperId,
                              fallbackPrimaryMethod (max_length=32),
                              fallbackPrimaryWrapperId (max_length=128)
- VaultPrimaryMethodSetRequest: userId, primaryMethod, primaryWrapperId

Canonical attach points:
- api/routes/db_proxy.py: all vault endpoint request models
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
    VaultWrapperData,
    VaultWrapperDeleteRequest,
)

_VALID_USER_ID = "u" * 128
_OVER_USER_ID = "u" * 129
_VALID_METHOD = "m" * 32
_OVER_METHOD = "m" * 33
_VALID_WRAPPER_ID = "w" * 128
_OVER_WRAPPER_ID = "w" * 129
_VALID_KEY_HASH = "h" * 256
_OVER_KEY_HASH = "h" * 257

# Minimal placeholder values for required crypto fields (content not under test)
_PLACEHOLDER_CIPHER = "cGxhY2Vob2xkZXI="
_PLACEHOLDER_SALT = "c2FsdA=="
_PLACEHOLDER_IV = "aXY="


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


class TestVaultGetRequestBounds:
    """VaultGetRequest.userId max_length=128."""

    def test_userid_at_max_length_accepted(self):
        req = VaultGetRequest(userId=_VALID_USER_ID)
        assert req.userId == _VALID_USER_ID

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            VaultGetRequest(userId=_OVER_USER_ID)


class TestVaultWrapperDataBounds:
    """VaultWrapperData: method max_length=32, wrapperId max_length=128."""

    def _make(self, **kwargs):
        defaults = {
            "method": "passphrase",
            "encryptedVaultKey": _PLACEHOLDER_CIPHER,
            "salt": _PLACEHOLDER_SALT,
            "iv": _PLACEHOLDER_IV,
        }
        defaults.update(kwargs)
        return VaultWrapperData(**defaults)

    def test_method_at_max_length_accepted(self):
        req = self._make(method=_VALID_METHOD)
        assert req.method == _VALID_METHOD

    def test_method_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(method=_OVER_METHOD)

    def test_wrapper_id_at_max_length_accepted(self):
        req = self._make(wrapperId=_VALID_WRAPPER_ID)
        assert req.wrapperId == _VALID_WRAPPER_ID

    def test_wrapper_id_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(wrapperId=_OVER_WRAPPER_ID)


class TestVaultWrapperDeleteRequestBounds:
    """VaultWrapperDeleteRequest: userId, vaultKeyHash, method, wrapperId bounds."""

    def _make(self, **kwargs):
        defaults = {
            "userId": "user-1",
            "vaultKeyHash": "hash",
            "method": "passphrase",
        }
        defaults.update(kwargs)
        return VaultWrapperDeleteRequest(**defaults)

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId=_OVER_USER_ID)

    def test_vault_key_hash_at_max_length_accepted(self):
        req = self._make(vaultKeyHash=_VALID_KEY_HASH)
        assert req.vaultKeyHash == _VALID_KEY_HASH

    def test_vault_key_hash_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(vaultKeyHash=_OVER_KEY_HASH)

    def test_method_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(method=_OVER_METHOD)

    def test_fallback_method_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(fallbackPrimaryMethod="x" * 33)

    def test_fallback_wrapper_id_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(fallbackPrimaryWrapperId="x" * 129)


class TestVaultPrimaryMethodSetRequestBounds:
    """VaultPrimaryMethodSetRequest: userId, primaryMethod, primaryWrapperId bounds."""

    def _make(self, **kwargs):
        defaults = {"userId": "user-1", "primaryMethod": "passphrase"}
        defaults.update(kwargs)
        return VaultPrimaryMethodSetRequest(**defaults)

    def test_userid_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(userId=_OVER_USER_ID)

    def test_primary_method_at_max_length_accepted(self):
        req = self._make(primaryMethod=_VALID_METHOD)
        assert req.primaryMethod == _VALID_METHOD

    def test_primary_method_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(primaryMethod=_OVER_METHOD)

    def test_primary_wrapper_id_at_max_length_accepted(self):
        req = self._make(primaryWrapperId=_VALID_WRAPPER_ID)
        assert req.primaryWrapperId == _VALID_WRAPPER_ID

    def test_primary_wrapper_id_over_max_length_rejected(self):
        with pytest.raises(ValidationError):
            self._make(primaryWrapperId=_OVER_WRAPPER_ID)


# ---------------------------------------------------------------------------
# Crypto blob / passkey field bounds (VaultWrapperData, VaultSetupStateRequest)
# ---------------------------------------------------------------------------

_VALID_ENC_KEY = "e" * 8192
_OVER_ENC_KEY = "e" * 8193
_VALID_SALT = "s" * 256
_OVER_SALT = "s" * 257
_VALID_IV = "v" * 128
_OVER_IV = "v" * 129
_VALID_PASSKEY_FIELD = "p" * 256
_OVER_PASSKEY_FIELD = "p" * 257


def _make_wrapper(**kwargs) -> dict:
    defaults = {
        "method": "passkey",
        "encryptedVaultKey": "enc",
        "salt": "sal",
        "iv": "iv_",
    }
    defaults.update(kwargs)
    return defaults


class TestVaultWrapperDataCryptoBounds:
    """VaultWrapperData crypto blob and passkey field bounds."""

    def test_enc_key_at_max_accepted(self):
        from api.routes.db_proxy import VaultWrapperData
        r = VaultWrapperData(**_make_wrapper(encryptedVaultKey=_VALID_ENC_KEY))
        assert len(r.encryptedVaultKey) == 8192

    def test_enc_key_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(encryptedVaultKey=_OVER_ENC_KEY))

    def test_salt_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(salt=_OVER_SALT))

    def test_iv_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(iv=_OVER_IV))

    def test_passkey_credential_id_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyCredentialId=_OVER_PASSKEY_FIELD))

    def test_passkey_rp_id_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyRpId=_OVER_PASSKEY_FIELD))

    def test_passkey_provider_over_max_rejected(self):
        from api.routes.db_proxy import VaultWrapperData
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyProvider="x" * 65))


class TestVaultSetupRecoveryFieldBounds:
    """VaultSetupStateRequest recovery crypto field bounds."""

    def _make(self, **kwargs):
        from api.routes.db_proxy import VaultSetupStateRequest
        defaults = {
            "userId": "u1",
            "vaultKeyHash": "h",
            "primaryMethod": "passphrase",
            "recoveryEncryptedVaultKey": "enc",
            "recoverySalt": "sal",
            "recoveryIv": "iv_",
            "wrappers": [_make_wrapper()],
        }
        defaults.update(kwargs)
        return VaultSetupStateRequest(**defaults)

    def test_recovery_enc_key_over_max_rejected(self):
        with pytest.raises(ValidationError):
            self._make(recoveryEncryptedVaultKey=_OVER_ENC_KEY)

    def test_recovery_salt_over_max_rejected(self):
        with pytest.raises(ValidationError):
            self._make(recoverySalt=_OVER_SALT)

    def test_recovery_iv_over_max_rejected(self):
        with pytest.raises(ValidationError):
            self._make(recoveryIv=_OVER_IV)

    def test_valid_setup_request_accepted(self):
        req = self._make()
        assert req.userId == "u1"


# ---------------------------------------------------------------------------
# Route-level rejection tests (exact-limit and one-over for vault endpoints)
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


class TestVaultSetupRouteRejectsOversizedFields:
    """POST /db/vault/setup returns 422 for oversized crypto blob fields."""

    def test_oversized_user_id_rejected(self, vault_client):
        payload = _minimal_setup_payload(userId="u" * 129)
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code == 422

    def test_oversized_vault_key_hash_rejected(self, vault_client):
        payload = _minimal_setup_payload(vaultKeyHash="h" * 257)
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code == 422

    def test_oversized_recovery_enc_key_rejected(self, vault_client):
        payload = _minimal_setup_payload(recoveryEncryptedVaultKey="e" * 8193)
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code == 422

    def test_oversized_wrapper_enc_key_rejected(self, vault_client):
        payload = _minimal_setup_payload(wrappers=[{
            "method": "passphrase",
            "encryptedVaultKey": "e" * 8193,
            "salt": "sal",
            "iv": "iv_",
        }])
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code == 422

    def test_valid_payload_passes_model_validation(self, vault_client):
        payload = _minimal_setup_payload()
        resp = vault_client.post("/db/vault/setup", json=payload)
        assert resp.status_code != 422, (
            "Valid payload must pass Pydantic validation (may fail at service level)"
        )
