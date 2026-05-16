"""
Tests proving that the /validate-token endpoint uses DB-backed revocation
(validate_token_with_db) rather than the weaker in-memory-only validate_token.

Background: Hussh runs on multiple Cloud Run instances. When a user revokes a
consent token, the revocation is written to the database and to the local
in-memory cache on the instance that processed the revocation. Other instances
only learn about the revocation via the DB check. If the endpoint uses the
in-memory-only validate_token, a revoked token could return {"valid": True}
on any instance that has not yet seen the in-memory update.

validate_token_with_db already handles the cross-instance case correctly by
falling back gracefully when the DB is unreachable (apply fail-closed for
non-VAULT_OWNER scopes, short grace period for VAULT_OWNER).

The stream.py route already carried a comment noting that the weaker
validate_token was the "previous" check; this test suite proves agents.py
now matches that standard.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


def _make_client():
    from fastapi import FastAPI

    from api.routes.agents import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Prove validate_token_with_db (async) is called, not validate_token (sync)
# ---------------------------------------------------------------------------


class TestValidateTokenEndpointUsesDbCheck:
    """
    The /api/validate-token endpoint must call validate_token_with_db
    (DB-backed revocation check) not the weaker in-memory-only validate_token.
    """

    def test_db_check_function_is_called(self):
        """
        Patch validate_token_with_db and confirm it is invoked.

        If the implementation reverts to validate_token, the mock is never called
        and the assertion fails.
        """
        client = _make_client()

        mock_result = (
            True,
            None,
            MagicMock(user_id="u1", agent_id="a1", scope=MagicMock(value="vault.owner")),
        )

        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(return_value=mock_result),
        ) as mock_db_check:
            client.post("/api/validate-token", json={"token": "hussh:fake.token"})

        (
            mock_db_check.assert_called_once(),
            ("validate_token_with_db was not called — DB revocation check is missing"),
        )

    def test_db_revoked_token_returns_invalid(self):
        """
        A token that the DB marks as revoked must return {"valid": False},
        even if it passes the in-memory HMAC check.

        This is the exact cross-instance revocation scenario: the token has a
        valid signature but has been revoked in the DB on another instance.
        """
        client = _make_client()

        # Simulate: HMAC passes, DB says revoked
        db_revoked_result = (False, "Token has been revoked (DB check)", None)

        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(return_value=db_revoked_result),
        ):
            response = client.post("/api/validate-token", json={"token": "hussh:revoked.token"})

        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False
        # Reason must be the generic message, not the internal detail
        assert body["reason"] == "Token validation failed"
        assert "DB check" not in body.get("reason", "")

    def test_valid_token_returns_expected_fields(self):
        """A valid, non-revoked token must return the expected payload shape."""
        client = _make_client()

        mock_token_obj = MagicMock()
        mock_token_obj.user_id = "firebase-uid-abc"
        mock_token_obj.agent_id = "self"
        mock_token_obj.scope = MagicMock(value="vault.owner")

        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(return_value=(True, None, mock_token_obj)),
        ):
            response = client.post("/api/validate-token", json={"token": "hussh:valid.token"})

        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is True
        assert body["user_id"] == "firebase-uid-abc"
        assert body["agent_id"] == "self"
        assert body["scope"] == "vault.owner"

    def test_expired_token_returns_invalid(self):
        """An expired token must return {"valid": False} with a generic reason."""
        client = _make_client()

        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(return_value=(False, "Token expired", None)),
        ):
            response = client.post("/api/validate-token", json={"token": "hussh:old.token"})

        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False
        # Must NOT leak the internal reason "Token expired" to client
        assert "expired" not in body.get("reason", "").lower()
        assert body["reason"] == "Token validation failed"

    def test_db_unavailable_returns_invalid_for_scoped_token(self):
        """
        When the DB is unreachable, validate_token_with_db applies fail-closed
        for non-VAULT_OWNER scopes. The endpoint must propagate this correctly.
        """
        client = _make_client()

        # validate_token_with_db returns (False, ...) for DB-unavailable scoped tokens
        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(
                return_value=(
                    False,
                    "Token revocation status could not be confirmed (DB unavailable)",
                    None,
                )
            ),
        ):
            response = client.post("/api/validate-token", json={"token": "hussh:scoped.token"})

        body = response.json()
        assert body["valid"] is False

    def test_exception_during_validation_returns_invalid(self):
        """An unexpected exception must not propagate to the client."""
        client = _make_client()

        with patch(
            "api.routes.agents.validate_token_with_db",
            new=AsyncMock(side_effect=Exception("DB connection refused at 10.0.0.1:5432")),
        ):
            response = client.post("/api/validate-token", json={"token": "hussh:any.token"})

        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False
        # Internal connection error must not appear in response
        assert "DB connection" not in response.text
        assert "10.0.0" not in response.text
