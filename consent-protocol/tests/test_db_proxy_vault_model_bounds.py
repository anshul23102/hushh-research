"""
Tests for db_proxy vault request model input bounds.

All vault request models previously had unbounded string fields.
Verifies that oversized payloads are rejected by Pydantic (HTTP 422) before
any database or business logic runs.
"""

import pytest
from pydantic import ValidationError

from api.routes.db_proxy import (
    VaultBootstrapStateRequest,
    VaultCheckRequest,
    VaultGetRequest,
    VaultPreStateUpdateRequest,
    VaultPrimaryMethodSetRequest,
    VaultSetupStateRequest,
    VaultWrapperData,
    VaultWrapperDeleteRequest,
    VaultWrapperUpsertRequest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_WRAPPER = dict(
    method="passphrase",
    encryptedVaultKey="a" * 64,
    salt="s" * 44,
    iv="i" * 24,
)


def _make_wrapper(**overrides) -> dict:
    return {**_VALID_WRAPPER, **overrides}


# ---------------------------------------------------------------------------
# VaultCheckRequest
# ---------------------------------------------------------------------------


class TestVaultCheckRequest:
    def test_valid_passes(self):
        r = VaultCheckRequest(userId="uid_abc")
        assert r.userId == "uid_abc"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultCheckRequest(userId="u" * 129)

    def test_user_id_exactly_max_passes(self):
        r = VaultCheckRequest(userId="u" * 128)
        assert len(r.userId) == 128


# ---------------------------------------------------------------------------
# VaultBootstrapStateRequest
# ---------------------------------------------------------------------------


class TestVaultBootstrapStateRequest:
    def test_none_user_id_passes(self):
        r = VaultBootstrapStateRequest()
        assert r.userId is None

    def test_valid_user_id_passes(self):
        r = VaultBootstrapStateRequest(userId="uid_abc")
        assert r.userId == "uid_abc"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultBootstrapStateRequest(userId="u" * 129)


# ---------------------------------------------------------------------------
# VaultPreStateUpdateRequest
# ---------------------------------------------------------------------------


class TestVaultPreStateUpdateRequest:
    def test_none_user_id_passes(self):
        r = VaultPreStateUpdateRequest()
        assert r.userId is None

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultPreStateUpdateRequest(userId="u" * 129)


# ---------------------------------------------------------------------------
# VaultGetRequest
# ---------------------------------------------------------------------------


class TestVaultGetRequest:
    def test_valid_passes(self):
        r = VaultGetRequest(userId="uid_abc")
        assert r.userId == "uid_abc"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultGetRequest(userId="u" * 129)


# ---------------------------------------------------------------------------
# VaultWrapperData
# ---------------------------------------------------------------------------


class TestVaultWrapperData:
    def test_valid_passes(self):
        w = VaultWrapperData(**_VALID_WRAPPER)
        assert w.method == "passphrase"

    def test_method_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(method="x" * 51))

    def test_encrypted_vault_key_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(encryptedVaultKey="a" * 2049))

    def test_encrypted_vault_key_max_passes(self):
        w = VaultWrapperData(**_make_wrapper(encryptedVaultKey="a" * 2048))
        assert len(w.encryptedVaultKey) == 2048

    def test_salt_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(salt="s" * 257))

    def test_iv_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(iv="i" * 257))

    def test_passkey_credential_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyCredentialId="p" * 513))

    def test_passkey_rp_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyRpId="r" * 254))

    def test_passkey_device_label_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperData(**_make_wrapper(passkeyDeviceLabel="d" * 257))

    def test_optional_passkey_fields_none_passes(self):
        w = VaultWrapperData(**_VALID_WRAPPER)
        assert w.passkeyCredentialId is None
        assert w.passkeyRpId is None
        assert w.passkeyDeviceLabel is None


# ---------------------------------------------------------------------------
# VaultSetupStateRequest
# ---------------------------------------------------------------------------


class TestVaultSetupStateRequest:
    def _valid(self, **overrides) -> dict:
        base = dict(
            userId="uid_abc",
            vaultKeyHash="h" * 64,
            primaryMethod="passphrase",
            recoveryEncryptedVaultKey="a" * 64,
            recoverySalt="s" * 44,
            recoveryIv="i" * 24,
            wrappers=[_VALID_WRAPPER],
        )
        return {**base, **overrides}

    def test_valid_passes(self):
        r = VaultSetupStateRequest(**self._valid())
        assert r.userId == "uid_abc"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultSetupStateRequest(**self._valid(userId="u" * 129))

    def test_vault_key_hash_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultSetupStateRequest(**self._valid(vaultKeyHash="h" * 257))

    def test_primary_method_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultSetupStateRequest(**self._valid(primaryMethod="x" * 51))

    def test_recovery_encrypted_vault_key_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultSetupStateRequest(**self._valid(recoveryEncryptedVaultKey="a" * 2049))

    def test_wrappers_list_over_20_raises(self):
        with pytest.raises(ValidationError):
            VaultSetupStateRequest(**self._valid(wrappers=[_VALID_WRAPPER] * 21))

    def test_wrappers_list_exactly_20_passes(self):
        r = VaultSetupStateRequest(**self._valid(wrappers=[_VALID_WRAPPER] * 20))
        assert len(r.wrappers) == 20


# ---------------------------------------------------------------------------
# VaultWrapperUpsertRequest
# ---------------------------------------------------------------------------


class TestVaultWrapperUpsertRequest:
    def _valid(self, **overrides) -> dict:
        base = dict(
            userId="uid_abc",
            vaultKeyHash="h" * 64,
            **_VALID_WRAPPER,
        )
        return {**base, **overrides}

    def test_valid_passes(self):
        r = VaultWrapperUpsertRequest(**self._valid())
        assert r.userId == "uid_abc"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperUpsertRequest(**self._valid(userId="u" * 129))

    def test_vault_key_hash_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperUpsertRequest(**self._valid(vaultKeyHash="h" * 257))

    def test_encrypted_vault_key_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperUpsertRequest(**self._valid(encryptedVaultKey="a" * 2049))


# ---------------------------------------------------------------------------
# VaultWrapperDeleteRequest
# ---------------------------------------------------------------------------


class TestVaultWrapperDeleteRequest:
    def _valid(self, **overrides) -> dict:
        base = dict(userId="uid_abc", vaultKeyHash="h" * 64, method="passphrase")
        return {**base, **overrides}

    def test_valid_passes(self):
        r = VaultWrapperDeleteRequest(**self._valid())
        assert r.fallbackPrimaryMethod == "passphrase"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperDeleteRequest(**self._valid(userId="u" * 129))

    def test_method_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperDeleteRequest(**self._valid(method="x" * 51))

    def test_fallback_method_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperDeleteRequest(**self._valid(fallbackPrimaryMethod="x" * 51))

    def test_fallback_wrapper_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultWrapperDeleteRequest(**self._valid(fallbackPrimaryWrapperId="x" * 129))


# ---------------------------------------------------------------------------
# VaultPrimaryMethodSetRequest
# ---------------------------------------------------------------------------


class TestVaultPrimaryMethodSetRequest:
    def test_valid_passes(self):
        r = VaultPrimaryMethodSetRequest(userId="uid_abc", primaryMethod="passkey")
        assert r.primaryMethod == "passkey"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultPrimaryMethodSetRequest(userId="u" * 129, primaryMethod="passphrase")

    def test_primary_method_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultPrimaryMethodSetRequest(userId="uid_abc", primaryMethod="x" * 51)

    def test_primary_wrapper_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            VaultPrimaryMethodSetRequest(
                userId="uid_abc", primaryMethod="passkey", primaryWrapperId="x" * 129
            )
