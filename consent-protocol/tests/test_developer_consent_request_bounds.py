"""
Canonical caller proof for CWE-400 bounds enforcement on Developer API.

Tests that DeveloperConsentRequest and DeveloperScopedExportRequest
validate field bounds at Pydantic parse time, preventing unbounded
resource consumption (CWE-400).
"""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.routes.developer import (
    DeveloperConsentRequest,
    DeveloperScopedExportRequest,
    _MAX_PUBLIC_APPROVAL_TIMEOUT_MINUTES,
    _MAX_PUBLIC_EXPIRY_HOURS,
    _MIN_PUBLIC_APPROVAL_TIMEOUT_MINUTES,
    _MIN_PUBLIC_EXPIRY_HOURS,
)


class TestDeveloperConsentRequestBounds:
    """Canonical attach point: api.routes.developer.DeveloperConsentRequest"""

    def test_expiry_hours_minimum_enforced(self):
        """expiry_hours must be >= _MIN_PUBLIC_EXPIRY_HOURS."""
        with pytest.raises(ValidationError) as exc:
            DeveloperConsentRequest(
                user_id="user_123",
                scope="pkm.read",
                expiry_hours=_MIN_PUBLIC_EXPIRY_HOURS - 1,
                connector_public_key="a" * 100,
                connector_key_id="key_1",
                connector_wrapping_alg="AES_256_GCM",
            )
        assert "greater than or equal to" in str(exc.value).lower()

    def test_expiry_hours_maximum_enforced(self):
        """expiry_hours must be <= _MAX_PUBLIC_EXPIRY_HOURS."""
        with pytest.raises(ValidationError) as exc:
            DeveloperConsentRequest(
                user_id="user_123",
                scope="pkm.read",
                expiry_hours=_MAX_PUBLIC_EXPIRY_HOURS + 1,
                connector_public_key="a" * 100,
                connector_key_id="key_1",
                connector_wrapping_alg="AES_256_GCM",
            )
        assert "less than or equal to" in str(exc.value).lower()

    def test_approval_timeout_minutes_maximum_enforced(self):
        """approval_timeout_minutes must be <= _MAX_PUBLIC_APPROVAL_TIMEOUT_MINUTES."""
        with pytest.raises(ValidationError) as exc:
            DeveloperConsentRequest(
                user_id="user_123",
                scope="pkm.read",
                approval_timeout_minutes=_MAX_PUBLIC_APPROVAL_TIMEOUT_MINUTES + 1,
                connector_public_key="a" * 100,
                connector_key_id="key_1",
                connector_wrapping_alg="AES_256_GCM",
            )
        assert "less than or equal to" in str(exc.value).lower()

    def test_connector_public_key_maximum_enforced(self):
        """connector_public_key must be <= 8192 chars."""
        with pytest.raises(ValidationError) as exc:
            DeveloperConsentRequest(
                user_id="user_123",
                scope="pkm.read",
                connector_public_key="a" * 8193,
                connector_key_id="key_1",
                connector_wrapping_alg="AES_256_GCM",
            )
        assert "at most 8192" in str(exc.value).lower() or "shorter" in str(exc.value).lower()


class TestDeveloperScopedExportRequestBounds:
    """Canonical attach point: api.routes.developer.DeveloperScopedExportRequest"""

    def test_consent_token_maximum_enforced(self):
        """consent_token must be <= 1024 chars."""
        with pytest.raises(ValidationError) as exc:
            DeveloperScopedExportRequest(
                user_id="user_123",
                consent_token="a" * 1025,
            )
        assert "at most 1024" in str(exc.value).lower() or "shorter" in str(exc.value).lower()

    def test_expected_scope_maximum_enforced(self):
        """expected_scope must be <= 256 chars."""
        with pytest.raises(ValidationError) as exc:
            DeveloperScopedExportRequest(
                user_id="user_123",
                consent_token="valid_token_xyz",
                expected_scope="a" * 257,
            )
        assert "at most 256" in str(exc.value).lower() or "shorter" in str(exc.value).lower()

    def test_valid_request_passes(self):
        """Valid request within all bounds should parse successfully."""
        req = DeveloperScopedExportRequest(
            user_id="user_123",
            consent_token="valid_token_xyz",
            expected_scope="pkm.read",
        )
        assert req.user_id == "user_123"
        assert req.consent_token == "valid_token_xyz"
        assert req.expected_scope == "pkm.read"
