"""
Tests: CWE-400 -- Developer API request/response models must enforce bounds to prevent resource exhaustion.

Validates that all string and numeric fields in developer API models properly reject oversized inputs.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.routes.developer import (
    DeveloperConsentRequest,
    DeveloperConsentStatusResponse,
    DeveloperDefaultAvailableExportRequest,
    DeveloperDefaultAvailableExportResponse,
    DeveloperPortalAccessResponse,
    DeveloperPortalAppResponse,
    DeveloperScopedExportRequest,
    DeveloperScopedExportResponse,
    DeveloperToolCatalogResponse,
    DeveloperUserScopesResponse,
)


class TestDeveloperUserScopesResponseBounds:
    """Validate DeveloperUserScopesResponse field bounds."""

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperUserScopesResponse(
                user_id="u" * 257,
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_app_id_max_length_256(self):
        """app_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperUserScopesResponse(
                user_id="user-123",
                app_id="a" * 257,
            )
        assert "at most 256 characters" in str(exc_info.value)


class TestDeveloperToolCatalogResponseBounds:
    """Validate DeveloperToolCatalogResponse field bounds."""

    def test_compatibility_status_max_length_64(self):
        """compatibility_status must not exceed 64 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperToolCatalogResponse(
                compatibility_status="s" * 65,
                allowed_tool_groups=[],
                tools=[],
                tool_groups=[],
                recommended_flow=[],
                notes=[],
            )
        assert "at most 64 characters" in str(exc_info.value)

    def test_version_max_length_32(self):
        """version must not exceed 32 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperToolCatalogResponse(
                version="v" * 33,
                compatibility_status="ok",
                allowed_tool_groups=[],
                tools=[],
                tool_groups=[],
                recommended_flow=[],
                notes=[],
            )
        assert "at most 32 characters" in str(exc_info.value)


class TestDeveloperConsentStatusResponseBounds:
    """Validate DeveloperConsentStatusResponse field bounds."""

    def test_status_max_length_64(self):
        """status must not exceed 64 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentStatusResponse(
                status="s" * 65,
                user_id="user-123",
                message="Test message",
            )
        assert "at most 64 characters" in str(exc_info.value)

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentStatusResponse(
                status="granted",
                user_id="u" * 257,
                message="Test message",
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_scope_max_length_500(self):
        """scope must not exceed 500 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentStatusResponse(
                status="granted",
                user_id="user-123",
                scope="s" * 501,
                message="Test message",
            )
        assert "at most 500 characters" in str(exc_info.value)

    def test_message_max_length_512(self):
        """message must not exceed 512 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentStatusResponse(
                status="granted",
                user_id="user-123",
                message="m" * 513,
            )
        assert "at most 512 characters" in str(exc_info.value)

    def test_approval_timeout_minutes_non_negative(self):
        """approval_timeout_minutes must be non-negative."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentStatusResponse(
                status="granted",
                user_id="user-123",
                approval_timeout_minutes=-1,
                message="Test message",
            )
        assert "greater than or equal to 0" in str(exc_info.value)


class TestDeveloperConsentRequestBounds:
    """Validate DeveloperConsentRequest field bounds."""

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentRequest(
                user_id="u" * 257,
                scope="pkm.read",
                connector_public_key="k" * 32,
                connector_key_id="key-123",
                connector_wrapping_alg="RSA-OAEP",
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_scope_max_length_500(self):
        """scope must not exceed 500 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentRequest(
                user_id="user-123",
                scope="s" * 501,
                connector_public_key="k" * 32,
                connector_key_id="key-123",
                connector_wrapping_alg="RSA-OAEP",
            )
        assert "at most 500 characters" in str(exc_info.value)

    def test_reason_max_length_512(self):
        """reason must not exceed 512 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentRequest(
                user_id="user-123",
                scope="pkm.read",
                reason="r" * 513,
                connector_public_key="k" * 32,
                connector_key_id="key-123",
                connector_wrapping_alg="RSA-OAEP",
            )
        assert "at most 512 characters" in str(exc_info.value)

    def test_connector_public_key_max_length_4096(self):
        """connector_public_key must not exceed 4096 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentRequest(
                user_id="user-123",
                scope="pkm.read",
                connector_public_key="k" * 4097,
                connector_key_id="key-123",
                connector_wrapping_alg="RSA-OAEP",
            )
        assert "at most 4096 characters" in str(exc_info.value)

    def test_expiry_hours_non_negative(self):
        """expiry_hours must be non-negative."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperConsentRequest(
                user_id="user-123",
                scope="pkm.read",
                expiry_hours=-1,
                connector_public_key="k" * 32,
                connector_key_id="key-123",
                connector_wrapping_alg="RSA-OAEP",
            )
        assert "greater than or equal to 0" in str(exc_info.value)


class TestDeveloperScopedExportRequestBounds:
    """Validate DeveloperScopedExportRequest field bounds."""

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperScopedExportRequest(
                user_id="u" * 257,
                consent_token="token" * 20,
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_consent_token_max_length_512(self):
        """consent_token must not exceed 512 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperScopedExportRequest(
                user_id="user-123",
                consent_token="t" * 513,
            )
        assert "at most 512 characters" in str(exc_info.value)

    def test_expected_scope_max_length_500(self):
        """expected_scope must not exceed 500 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperScopedExportRequest(
                user_id="user-123",
                consent_token="token" * 20,
                expected_scope="s" * 501,
            )
        assert "at most 500 characters" in str(exc_info.value)


class TestDeveloperDefaultAvailableExportRequestBounds:
    """Validate DeveloperDefaultAvailableExportRequest field bounds."""

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperDefaultAvailableExportRequest(
                user_id="u" * 257,
                scope="pkm.read",
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_scope_max_length_500(self):
        """scope must not exceed 500 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperDefaultAvailableExportRequest(
                user_id="user-123",
                scope="s" * 501,
            )
        assert "at most 500 characters" in str(exc_info.value)


class TestDeveloperScopedExportResponseBounds:
    """Validate DeveloperScopedExportResponse field bounds."""

    def test_status_max_length_64(self):
        """status must not exceed 64 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperScopedExportResponse(
                status="s" * 65,
                user_id="user-123",
                consent_token="token" * 20,
                message="Test",
            )
        assert "at most 64 characters" in str(exc_info.value)

    def test_encrypted_data_max_length_65536(self):
        """encrypted_data must not exceed 65536 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperScopedExportResponse(
                status="ok",
                user_id="user-123",
                consent_token="token" * 20,
                encrypted_data="d" * 65537,
                message="Test",
            )
        assert "at most 65536 characters" in str(exc_info.value)


class TestDeveloperDefaultAvailableExportResponseBounds:
    """Validate DeveloperDefaultAvailableExportResponse field bounds."""

    def test_status_max_length_64(self):
        """status must not exceed 64 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperDefaultAvailableExportResponse(
                status="s" * 65,
                user_id="user-123",
                scope="pkm.read",
                message="Test",
            )
        assert "at most 64 characters" in str(exc_info.value)

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperDefaultAvailableExportResponse(
                status="ok",
                user_id="u" * 257,
                scope="pkm.read",
                message="Test",
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_scope_max_length_500(self):
        """scope must not exceed 500 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperDefaultAvailableExportResponse(
                status="ok",
                user_id="user-123",
                scope="s" * 501,
                message="Test",
            )
        assert "at most 500 characters" in str(exc_info.value)


class TestDeveloperPortalAppResponseBounds:
    """Validate DeveloperPortalAppResponse field bounds."""

    def test_app_id_max_length_256(self):
        """app_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAppResponse(
                app_id="a" * 257,
                agent_id="agent-123",
                display_name="Test App",
                contact_email="test@example.com",
                status="active",
                allowed_tool_groups=[],
                created_at=1000,
                updated_at=2000,
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_contact_email_max_length_320(self):
        """contact_email must not exceed 320 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAppResponse(
                app_id="app-123",
                agent_id="agent-123",
                display_name="Test App",
                contact_email="e" * 321,
                status="active",
                allowed_tool_groups=[],
                created_at=1000,
                updated_at=2000,
            )
        assert "at most 320 characters" in str(exc_info.value)

    def test_created_at_non_negative(self):
        """created_at must be non-negative."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAppResponse(
                app_id="app-123",
                agent_id="agent-123",
                display_name="Test App",
                contact_email="test@example.com",
                status="active",
                allowed_tool_groups=[],
                created_at=-1,
                updated_at=2000,
            )
        assert "greater than or equal to 0" in str(exc_info.value)


class TestDeveloperPortalAccessResponseBounds:
    """Validate DeveloperPortalAccessResponse field bounds."""

    def test_user_id_max_length_256(self):
        """user_id must not exceed 256 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAccessResponse(
                access_enabled=True,
                user_id="u" * 257,
            )
        assert "at most 256 characters" in str(exc_info.value)

    def test_owner_email_max_length_320(self):
        """owner_email must not exceed 320 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAccessResponse(
                access_enabled=True,
                user_id="user-123",
                owner_email="e" * 321,
            )
        assert "at most 320 characters" in str(exc_info.value)

    def test_raw_token_max_length_512(self):
        """raw_token must not exceed 512 chars."""
        with pytest.raises(ValidationError) as exc_info:
            DeveloperPortalAccessResponse(
                access_enabled=True,
                user_id="user-123",
                raw_token="t" * 513,
            )
        assert "at most 512 characters" in str(exc_info.value)
