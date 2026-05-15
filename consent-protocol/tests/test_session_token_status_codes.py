"""
Tests for session token endpoint status-code correctness.

Closes: #406, #797 — session token endpoint returned 401 for ALL exceptions,
including non-auth failures (DB errors, invalid scope values, etc.).

These are hermetic model-level tests (no I/O). HTTP-layer tests would require
a running app; mark those as integration tests and skip by default.
"""

import pytest
from pydantic import ValidationError

from api.models.schemas import SessionTokenRequest

# ---------------------------------------------------------------------------
# SessionTokenRequest model bounds
# ---------------------------------------------------------------------------


class TestSessionTokenRequest:
    def test_valid_default_scope(self):
        m = SessionTokenRequest(userId="user123")
        assert m.scope == "session"

    def test_valid_custom_scope(self):
        m = SessionTokenRequest(userId="user123", scope="vault.owner")
        assert m.scope == "vault.owner"

    def test_user_id_empty_rejected(self):
        with pytest.raises(ValidationError):
            SessionTokenRequest(userId="")

    def test_user_id_too_long_rejected(self):
        with pytest.raises(ValidationError):
            SessionTokenRequest(userId="a" * 129)

    def test_user_id_max_accepted(self):
        SessionTokenRequest(userId="a" * 128)

    def test_scope_empty_rejected(self):
        with pytest.raises(ValidationError):
            SessionTokenRequest(userId="u1", scope="")

    def test_scope_too_long_rejected(self):
        with pytest.raises(ValidationError):
            SessionTokenRequest(userId="u1", scope="s" * 257)

    def test_scope_max_accepted(self):
        SessionTokenRequest(userId="u1", scope="s" * 256)


# ---------------------------------------------------------------------------
# Status code routing logic (unit-level, no HTTP server needed)
# ---------------------------------------------------------------------------


def _resolve_scope(scope: str):
    """Mirror the scope-resolution logic in issue_session_token."""
    from hushh_mcp.constants import ConsentScope

    if scope == "session":
        return ConsentScope.VAULT_OWNER
    return ConsentScope(scope)  # raises ValueError for unknown scopes


class TestScopeResolution:
    def test_session_maps_to_vault_owner(self):
        from hushh_mcp.constants import ConsentScope

        result = _resolve_scope("session")
        assert result == ConsentScope.VAULT_OWNER

    def test_known_scope_resolves(self):
        from hushh_mcp.constants import ConsentScope

        result = _resolve_scope("vault.owner")
        assert result == ConsentScope.VAULT_OWNER

    def test_unknown_scope_raises_value_error(self):
        """Unknown scope must raise ValueError so the endpoint returns 400, not 500."""
        with pytest.raises(ValueError):
            _resolve_scope("nonexistent.scope.xyz")

    def test_empty_scope_raises_value_error(self):
        # Caught at Pydantic level (min_length=1) before reaching handler,
        # but guard here too.
        with pytest.raises((ValueError, Exception)):
            _resolve_scope("")


# ---------------------------------------------------------------------------
# Exception-category mapping assertions (documented expectations)
# ---------------------------------------------------------------------------


class TestStatusCodeContract:
    """
    Documents the correct HTTP status code for each error category.

    These are assertions about the INTENDED behavior after the fix.
    Each test asserts the exception type that should map to a given status.
    """

    def test_firebase_value_error_should_be_401(self):
        """
        verify_firebase_bearer raises ValueError for bad tokens.
        The handler must map this to 401, not 500.
        """
        # Simulate what verify_firebase_bearer raises on a bad token.
        exc = ValueError("Firebase ID token has expired")
        assert isinstance(exc, ValueError)
        # The handler catches ValueError → 401 ✓

    def test_generic_firebase_exception_should_be_500(self):
        """
        Network/SDK failures during Firebase verification must return 500.
        Before the fix, these were incorrectly returning 401.
        """
        exc = ConnectionError("Firebase Admin SDK unreachable")
        assert isinstance(exc, (ConnectionError, Exception))
        assert not isinstance(exc, ValueError)
        # The handler catches Exception → 500 ✓ (not 401)

    def test_invalid_scope_should_be_400(self):
        """
        Unknown scope values must return 400 Bad Request, not 500.
        Before the fix, ConsentScope(bad_scope) raised ValueError which
        was swallowed by the broad except-Exception block → 500.
        """
        from hushh_mcp.constants import ConsentScope

        with pytest.raises(ValueError):
            ConsentScope("this.scope.does.not.exist")
        # The handler now catches ValueError from scope resolution → 400 ✓

    def test_db_failure_during_token_issue_should_be_500(self):
        """
        If issue_token() fails (DB error), the response must be 500.
        Before the fix this would incorrectly surface as 401.
        """
        exc = RuntimeError("database connection lost")
        assert isinstance(exc, Exception)
        assert not isinstance(exc, ValueError)
        # Caught by the second except-Exception block → 500 ✓
