# tests/test_logout_auth.py
"""
Regression tests for the missing authentication on POST /api/consent/logout.

Before the fix the endpoint had no authentication: any caller could pass any
userId and receive {"status": "success"} without proving their identity.

After the fix the endpoint:
1. Requires a valid Firebase ID token in the Authorization header.
2. Validates that request.userId matches the authenticated Firebase UID.
3. Returns 401 for missing/invalid tokens and 403 for user mismatches.

All tests are hermetic: no network, no DB, no Firebase calls.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api.routes import session


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(session.router)
    return app


def _logout_payload(user_id: str = "user_123") -> dict[str, str]:
    return {"userId": user_id}


# ---------------------------------------------------------------------------
# Authentication requirement
# ---------------------------------------------------------------------------


def test_logout_missing_auth_header_returns_401(monkeypatch):
    """Logout without any Authorization header must be rejected."""

    def _raise_missing(_: str | None) -> str:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    monkeypatch.setattr(session, "verify_firebase_bearer", _raise_missing)

    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post("/api/consent/logout", json=_logout_payload())

    assert response.status_code == 401


def test_logout_invalid_firebase_token_returns_401(monkeypatch):
    """Logout with an invalid Firebase token must be rejected."""

    def _raise_invalid(_: str | None) -> str:
        raise ValueError("malformed firebase token")

    monkeypatch.setattr(session, "verify_firebase_bearer", _raise_invalid)

    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post(
        "/api/consent/logout",
        json=_logout_payload(),
        headers={"Authorization": "Bearer bad-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"


def test_logout_unexpected_verifier_failure_returns_500(monkeypatch):
    """Unexpected verifier exception must return 500, not expose internals."""

    def _raise_unexpected(_: str | None) -> str:
        raise RuntimeError("firebase verifier unavailable")

    monkeypatch.setattr(session, "verify_firebase_bearer", _raise_unexpected)

    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post(
        "/api/consent/logout",
        json=_logout_payload(),
        headers={"Authorization": "Bearer any-token"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"


# ---------------------------------------------------------------------------
# User ownership check
# ---------------------------------------------------------------------------


def test_logout_user_mismatch_returns_403(monkeypatch):
    """Attempting to log out a different user must be rejected with 403."""
    monkeypatch.setattr(session, "verify_firebase_bearer", lambda _: "other_user")

    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post(
        "/api/consent/logout",
        json=_logout_payload("user_123"),  # trying to logout user_123
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "userId mismatch"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_logout_valid_auth_and_matching_user_returns_success(monkeypatch):
    """Authenticated logout for the correct user must succeed."""
    monkeypatch.setattr(session, "verify_firebase_bearer", lambda _: "user_123")

    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.post(
        "/api/consent/logout",
        json=_logout_payload("user_123"),
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
